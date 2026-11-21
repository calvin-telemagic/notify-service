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
"""

import re

import httpx

from ..egress import check_url
from ..errors import ProviderAuthFailed, ProviderRejected, ProviderUnavailable
from ..models import JasminSms

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


async def send(client: httpx.AsyncClient, req: JasminSms) -> str:
    creds = req.credentials
    check_url(creds.base_url)
    params = {
        "username": creds.username.get_secret_value(),
        "password": creds.password.get_secret_value(),
        "from": req.from_,
        "to": req.to,
        **content_params(req.body),
    }
    if req.route:
        params["route"] = req.route
    if req.dlr_url:
        params |= {"dlr": "yes", "dlr-url": req.dlr_url, "dlr-level": req.dlr_level, "dlr-method": "POST"}

    try:
        response = await client.get(creds.base_url.rstrip("/") + "/send", params=params)
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
