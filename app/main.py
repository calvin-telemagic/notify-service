"""
notify-service: one place that sends texts and emails for any TeleMagic or
SecureVoice service, and one log of everything sent.

Clients, their API keys and their provider configs live in notify-service's
database (managed with `python -m app.admin`). A caller authenticates with
its key, names one of its configs, and gets back the message's id; every
send is logged with the client that made it, and Jasmin delivery receipts
are recorded against it.

  POST /v1/sms                       { config, to, body | media_urls, from?, sensitive?, reference? }
  POST /v1/email                     { config, to[], subject, html | text, reply_to?, sensitive?, reference? }
  GET  /v1/messages/{id}             one of this client's messages
  GET  /v1/messages?reference=&to=&before=&limit=
  POST /dlr/jasmin/{id}/{token}      Jasmin's delivery receipts (token: vault.dlr_token)
  GET  /healthz

A sensitive message's body isn't kept: the log holds its length and a keyed
MAC instead. Nothing a request carries -- bodies, full recipients -- goes to
the service's own log lines; they name the client, config, a masked
recipient and the outcome.
"""

import asyncio
import contextlib
import logging
import secrets
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime

import httpx
from fastapi import Depends, FastAPI, Header, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import ValidationError

from . import db, vault
from .config import settings
from .errors import ConfigError, SendError
from .models import (Accepted, EmailRequest, GraphConfig, InteliquentConfig, JasminConfig, Message,
                     SmsRequest, provider_config)
from .providers import graph, inteliquent, jasmin, smtp

logging.basicConfig(level=settings.log_level, format="%(asctime)s %(levelname)s %(name)s %(message)s")
# httpx logs each request URL at INFO; Jasmin's carries the password.
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)
log = logging.getLogger("notify")

PURGE_EVERY_S = 3600


async def _purge_loop() -> None:
    while True:
        try:
            removed = await db.purge(settings.retention_days)
            if removed:
                log.info("purged %d messages older than %d days", removed, settings.retention_days)
        except Exception:
            log.exception("purge failed")
        await asyncio.sleep(PURGE_EVERY_S)


@asynccontextmanager
async def lifespan(app: FastAPI):
    if settings.encryption_key is None:
        raise SystemExit("CONFIG_ENCRYPTION_KEY is required")
    await db.connect()
    if not settings.dlr_base_url:
        log.warning("DLR_BASE_URL is blank: Jasmin sends won't ask for delivery receipts")
    # follow_redirects=False: a provider endpoint can't bounce the service elsewhere.
    app.state.http = httpx.AsyncClient(timeout=settings.provider_timeout_s, follow_redirects=False)
    purger = asyncio.create_task(_purge_loop()) if settings.retention_days > 0 else None
    yield
    if purger:
        purger.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await purger
    await app.state.http.aclose()
    await db.close()


app = FastAPI(title="notify-service", version="2.0.0", lifespan=lifespan,
              description="Send SMS and email through per-client stored provider configs, and log every send.")


class _Refused(Exception):
    def __init__(self, status: int, error: str, detail: str) -> None:
        self.status, self.error, self.detail = status, error, detail


@app.exception_handler(_Refused)
async def _refused(_: Request, exc: _Refused):
    return JSONResponse({"error": exc.error, "detail": exc.detail, "retryable": False}, status_code=exc.status)


@app.exception_handler(SendError)
async def _send_error(_: Request, exc: SendError):
    return JSONResponse(exc.body(), status_code=exc.status)


@app.exception_handler(RequestValidationError)
async def _invalid(_: Request, exc: RequestValidationError):
    # FastAPI's default echoes each bad field's input back.
    errors = [{"loc": [str(p) for p in e.get("loc", ())], "msg": e.get("msg", "")} for e in exc.errors()]
    return JSONResponse({"error": "invalid_request", "detail": errors, "retryable": False}, status_code=422)


async def client_id(authorization: str = Header(default="")) -> str:
    scheme, _, key = authorization.partition(" ")
    if scheme.lower() != "bearer" or not key.strip():
        raise _Refused(401, "unauthorized", "Authorization: Bearer <key> is required")
    client = await db.client_for_key(vault.api_key_hash(key.strip()))
    if client is None:
        raise _Refused(401, "unauthorized", "Unknown or revoked API key")
    return client


async def load_config(client: str, name: str, kind: str):
    row = await db.get_config(client, name)
    if row is None:
        raise ConfigError(f"No active config {name!r} for this client")
    if row["kind"] != kind:
        raise ConfigError(f"Config {name!r} is for {row['kind']}, not {kind}")
    try:
        return provider_config.validate_python(vault.open_(client, name, row["settings"]))
    except (vault.VaultError, ValidationError) as exc:
        log.error("config %s/%s unreadable: %s", client, name, type(exc).__name__)
        raise ConfigError(f"Config {name!r} can't be read; ask an admin to set it again") from None


def mask(recipient: str) -> str:
    if "@" in recipient:
        local, _, domain = recipient.rpartition("@")
        return f"{local[:1]}***@{domain}"
    return f"***{recipient[-4:]}"


async def _run(*, client: str, req, cfg, kind: str, sender: str, recipients: list[str], subject: str | None,
               text: str | None, html: str | None, media_urls: list[str] | None, send) -> Accepted:
    body_length = len(subject or "") + len(text or "") + len(html or "")
    message_id = await db.log_send(
        client_id=client, config_name=req.config, kind=kind, provider=cfg.provider, sender=sender,
        recipients=recipients, subject=subject,
        body_text=None if req.sensitive else text, body_html=None if req.sensitive else html,
        media_urls=media_urls or None, body_length=body_length,
        body_mac=vault.body_mac(subject, text, html) if req.sensitive else None,
        sensitive=req.sensitive, reference=req.reference)
    started = time.monotonic()
    who = ",".join(mask(r) for r in recipients[:3]) + ("…" if len(recipients) > 3 else "")
    try:
        provider_id, refused = await send(message_id)
    except SendError as exc:
        await db.log_failed(message_id, exc.error, exc.detail)
        log.warning("%s %s %s/%s %s to=%s failed %s in %dms: %s", message_id, kind, client, req.config,
                    cfg.provider, who, exc.error, (time.monotonic() - started) * 1000, exc.detail)
        raise
    await db.log_accepted(message_id, provider_id, refused)
    log.info("%s %s %s/%s %s to=%s accepted id=%s in %dms", message_id, kind, client, req.config,
             cfg.provider, who, provider_id, (time.monotonic() - started) * 1000)
    return Accepted(id=message_id, provider=cfg.provider, provider_message_id=provider_id, refused=refused)


def _dlr_url(message_id: uuid.UUID) -> str | None:
    if not settings.dlr_base_url:
        return None
    return f"{settings.dlr_base_url}/dlr/jasmin/{message_id}/{vault.dlr_token(str(message_id))}"


@app.post("/v1/sms", response_model=Accepted)
async def send_sms(request: Request, req: SmsRequest, client: str = Depends(client_id)) -> Accepted:
    cfg = await load_config(client, req.config, "sms")
    if cfg.from_any:
        if req.from_ is None:
            raise ConfigError(f"config {req.config!r} is from_any: every send needs a from number")
    elif req.from_ is not None and req.from_ not in cfg.from_numbers:
        raise ConfigError(f"{req.from_} isn't one of config {req.config!r}'s from_numbers")
    if req.media_urls and not isinstance(cfg, InteliquentConfig):
        raise ConfigError("media_urls (MMS) needs an Inteliquent config")
    sender = req.from_ or secrets.choice(cfg.from_numbers)
    http = request.app.state.http

    async def send(message_id):
        if isinstance(cfg, JasminConfig):
            return await jasmin.send(http, cfg, sender=sender, to=req.to, body=req.body,
                                     dlr_url=_dlr_url(message_id)), []
        return await inteliquent.send(http, cfg, sender=sender, to=req.to, body=req.body,
                                      media_urls=req.media_urls), []

    return await _run(client=client, req=req, cfg=cfg, kind="sms", sender=sender, recipients=[req.to],
                      subject=None, text=req.body, html=None, media_urls=req.media_urls, send=send)


@app.post("/v1/email", response_model=Accepted)
async def send_email(request: Request, req: EmailRequest, client: str = Depends(client_id)) -> Accepted:
    cfg = await load_config(client, req.config, "email")
    http = request.app.state.http
    sender = cfg.sender if isinstance(cfg, GraphConfig) else cfg.from_

    async def send(_message_id):
        if isinstance(cfg, GraphConfig):
            await graph.send(http, cfg, req)
            return None, []
        return await smtp.send(cfg, req, settings.provider_timeout_s)

    return await _run(client=client, req=req, cfg=cfg, kind="email", sender=sender, recipients=req.to,
                      subject=req.subject, text=req.text, html=req.html, media_urls=None, send=send)


@app.get("/v1/messages/{message_id}", response_model=Message)
async def get_message(message_id: uuid.UUID, client: str = Depends(client_id)) -> Message:
    row = await db.get_message(client, message_id)
    if row is None:
        raise _Refused(404, "not_found", "No such message for this client")
    return Message(**dict(row))


@app.get("/v1/messages", response_model=list[Message])
async def find_messages(client: str = Depends(client_id),
                        reference: str | None = Query(default=None, max_length=200),
                        to: str | None = Query(default=None, max_length=254),
                        before: datetime | None = None,
                        limit: int = Query(default=50, ge=1, le=200)) -> list[Message]:
    rows = await db.find_messages(client, reference=reference, recipient=to, before=before, limit=limit)
    return [Message(**dict(r)) for r in rows]


@app.post("/dlr/jasmin/{message_id}/{token}")
async def jasmin_dlr(request: Request, message_id: uuid.UUID, token: str):
    """Jasmin's delivery receipt (adapted from messaging's routers/dlr_http.py).
    Answers ACK/Jasmin -- anything else and Jasmin retries."""
    if not vault.dlr_token_ok(str(message_id), token):
        return PlainTextResponse("bad token", status_code=403)
    form = dict(await request.form())
    # Jasmin echoes the start of the message in "text" -- often the one-time code.
    form.pop("text", None)
    raw = {k: str(v)[:200] for k, v in list(form.items())[:30]}
    status = jasmin.dlr_status(raw.get("message_status"))
    error = raw.get("err") if status != "delivered" and raw.get("err") not in (None, "", "000") else None
    if not await db.log_dlr(message_id, status, error, raw):
        log.warning("DLR for unknown message %s", message_id)
    else:
        log.info("%s dlr %s", message_id, status)
    return PlainTextResponse("ACK/Jasmin")


@app.get("/healthz")
async def healthz() -> dict:
    await db.pool().fetchval("SELECT 1")
    return {"status": "ok"}
