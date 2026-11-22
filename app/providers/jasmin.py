"""
SMS through Jasmin's HTTP API (GET {base_url}/send), extracted from
tm-messaging's messaging/app/services/jasmin.py. That's the send the
messaging hub makes for otp-service's codes; the message_log/hop bookkeeping
around it stays in messaging.

Jasmin answers 'Success "<uuid>"' or 'Error "<reason>"' (with a 4xx/5xx
status for most errors), and never transcodes content: a UCS-2 message has to
arrive as UTF-16BE bytes, sent here as hex-content with coding=8, the same as
the messaging hub and opensips.cfg's gsm_utf.py do.

The username and password ride in the query string (Jasmin's API); the
service's httpx logger is held at WARNING so the URL is never logged.

Delivery receipts: with a dlr_url, Jasmin POSTs the receipt there (level 2:
the terminal status from the carrier); app/main.py's /dlr/jasmin route
records it. STATUS_MAP is messaging's services/dlr_status.py.
"""

import re

import httpx

from ..errors import ProviderAuthFailed, ProviderRejected, ProviderUnavailable
from ..models import JasminConfig

_UCS2_DATA_CODING = 8


def needs_ucs2(body: str) -> bool:
    # messaging's heuristic: anything outside ASCII sends the whole message as UCS-2.
    return any(ord(ch) > 127 for ch in body)


def content_params(body: str) -> dict:
    if needs_ucs2(body):
        return {"hex-content": body.encode("utf-16-be").hex(), "coding": _UCS2_DATA_CODING}
    return {"content": body}


def parse_response(text: str) -> tuple[str | None, str | None]:
    """(message id, None) on success, (None, reason) otherwise."""
    text = text.strip()
    if match := re.match(r'^Success "([^"]+)"$', text):
        return match.group(1), None
    if match := re.match(r'^Error "(.+)"$', text, re.S):
        return None, match.group(1)
    return None, f"Unexpected Jasmin response: {text[:200]}"


STATUS_MAP = {
    "DELIVRD": "delivered",
    "UNDELIV": "undeliverable",
    "REJECTD": "rejected",
    "EXPIRED": "expired",
    "FAILED":  "failed",
    "UNKNOWN": "unknown",
}


def dlr_status(raw: str | None) -> str:
    return STATUS_MAP.get((raw or "").upper(), "unknown")


async def send(client: httpx.AsyncClient, cfg: JasminConfig, *, sender: str, to: str, body: str,
               dlr_url: str | None) -> str:
    params = {
        "username": cfg.username.get_secret_value(),
        "password": cfg.password.get_secret_value(),
        "from": sender,
        "to": to,
        **content_params(body),
    }
    if cfg.route:
        params["route"] = cfg.route
    if dlr_url:
        params |= {"dlr": "yes", "dlr-url": dlr_url, "dlr-level": cfg.dlr_level, "dlr-method": "POST"}

    try:
        response = await client.get(cfg.base_url.rstrip("/") + "/send", params=params)
    except httpx.HTTPError as exc:
        raise ProviderUnavailable(f"Jasmin unreachable: {type(exc).__name__}") from None

    message_id, error = parse_response(response.text)
    if message_id:
        return message_id
    if response.status_code >= 500:
        raise ProviderUnavailable(f"Jasmin {response.status_code}: {error}")
    if response.status_code in (401, 403) or (error and "authentication" in error.lower()):
        raise ProviderAuthFailed(f"Jasmin refused the credentials: {error}")
    raise ProviderRejected(f"Jasmin rejected the message: {error}")
