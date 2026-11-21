"""
notify-service: one place that sends texts and emails, for any TeleMagic or
SecureVoice service. It keeps no provider credentials, no message store and
no templates: the caller says which provider, passes that provider's
credentials, and gets back the provider's message id or why it failed.

  POST /v1/sms     Jasmin or Inteliquent
  POST /v1/email   Microsoft Graph or SMTP
  GET  /healthz

Callers authenticate with "Authorization: Bearer <one of API_KEYS>".
Nothing a request carries -- credentials, bodies (often one-time codes),
full recipients -- is logged; log lines name the provider, a masked
recipient and the outcome.
"""

import hmac
import logging
import time
import uuid
from contextlib import asynccontextmanager

import httpx
from fastapi import Body, Depends, FastAPI, Header, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from .config import settings
from .errors import SendError
from .models import Accepted, EmailRequest, GraphEmail, JasminSms, SmsRequest
from .providers import graph, inteliquent, jasmin, smtp

logging.basicConfig(level=settings.log_level, format="%(asctime)s %(levelname)s %(name)s %(message)s")
# httpx logs each request URL at INFO; Jasmin's carries the password.
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)
log = logging.getLogger("notify")


@asynccontextmanager
async def lifespan(app: FastAPI):
    if not settings.api_keys:
        log.warning("API_KEYS is empty: every send will be refused")
    if "*" in settings.egress_allowed_hosts:
        log.warning("EGRESS_ALLOWED_HOSTS is '*': callers may point the service at any host")
    # follow_redirects=False: an allowed host can't redirect the service anywhere else.
    app.state.http = httpx.AsyncClient(timeout=settings.provider_timeout_s, follow_redirects=False)
    yield
    await app.state.http.aclose()


app = FastAPI(title="notify-service", version="1.0.0", lifespan=lifespan,
              description="Send SMS and email with caller-supplied provider credentials.")


def require_api_key(authorization: str = Header(default="")) -> None:
    if not settings.api_keys:
        raise _Refused(503, "not_configured", "This service has no API_KEYS configured")
    scheme, _, key = authorization.partition(" ")
    if scheme.lower() != "bearer" or not key:
        raise _Refused(401, "unauthorized", "Authorization: Bearer <key> is required")
    # Check every key so the time taken doesn't say which one nearly matched.
    matched = False
    for candidate in settings.api_keys:
        matched |= hmac.compare_digest(candidate.encode(), key.strip().encode())
    if not matched:
        raise _Refused(401, "unauthorized", "Unknown API key")


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
    # FastAPI's default echoes each bad field's input back -- credentials included.
    errors = [{"loc": [str(p) for p in e.get("loc", ())], "msg": e.get("msg", "")} for e in exc.errors()]
    return JSONResponse({"error": "invalid_request", "detail": errors, "retryable": False}, status_code=422)


def mask(recipient: str) -> str:
    if "@" in recipient:
        local, _, domain = recipient.rpartition("@")
        return f"{local[:1]}***@{domain}"
    return f"***{recipient[-4:]}"


async def _run(kind: str, provider: str, recipients: list[str], send) -> Accepted:
    request_id = uuid.uuid4().hex[:12]
    started = time.monotonic()
    who = ",".join(mask(r) for r in recipients[:3]) + ("…" if len(recipients) > 3 else "")
    try:
        message_id, refused = await send()
    except SendError as exc:
        log.warning("%s %s %s to=%s failed %s in %dms: %s", request_id, kind, provider, who, exc.error,
                    (time.monotonic() - started) * 1000, exc.detail)
        raise
    log.info("%s %s %s to=%s accepted id=%s in %dms", request_id, kind, provider, who, message_id,
             (time.monotonic() - started) * 1000)
    return Accepted(provider=provider, message_id=message_id, refused=refused)


@app.post("/v1/sms", response_model=Accepted, dependencies=[Depends(require_api_key)])
async def send_sms(request: Request, req: SmsRequest = Body(...)) -> Accepted:
    http = request.app.state.http

    async def send():
        if isinstance(req, JasminSms):
            return await jasmin.send(http, req), []
        return await inteliquent.send(http, req), []

    return await _run("sms", req.provider, [req.to], send)


@app.post("/v1/email", response_model=Accepted, dependencies=[Depends(require_api_key)])
async def send_email(request: Request, req: EmailRequest = Body(...)) -> Accepted:
    http = request.app.state.http

    async def send():
        if isinstance(req, GraphEmail):
            await graph.send(http, req)
            return None, []
        return await smtp.send(req, settings.provider_timeout_s)

    return await _run("email", req.provider, req.to, send)


@app.get("/healthz")
async def healthz() -> dict:
    return {"status": "ok"}
