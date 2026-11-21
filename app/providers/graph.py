"""
Email through Microsoft Graph (client-credentials token, then
POST /users/{sender}/sendMail), extracted from otp-service's
app/graph_mail.py, with the tenant, client and secret coming from each
request instead of MS_GRAPH_* env vars.

Tokens are cached per (tenant, client, secret) until a minute before they
expire, so a busy caller doesn't fetch one per message. A sendMail answered
401 drops the cached token and tries once more with a fresh one. Graph
answers 202 with no message id.
"""

import asyncio
import hashlib
import time
import urllib.parse

import httpx

from ..errors import ProviderAuthFailed, ProviderRejected, ProviderUnavailable
from ..models import GraphCredentials, GraphEmail

TOKEN_URL = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
SCOPE = "https://graph.microsoft.com/.default"
GRAPH_URL = "https://graph.microsoft.com/v1.0"
_EARLY_S = 60
_MAX_CACHED = 256

_tokens: dict[str, tuple[str, float]] = {}
_lock = asyncio.Lock()


def _cache_key(creds: GraphCredentials) -> str:
    raw = "\0".join((creds.tenant_id, creds.client_id, creds.client_secret.get_secret_value()))
    return hashlib.sha256(raw.encode()).hexdigest()


def clear_cache() -> None:
    _tokens.clear()


async def _token(client: httpx.AsyncClient, creds: GraphCredentials, fresh: bool = False) -> str:
    key = _cache_key(creds)
    async with _lock:
        cached = _tokens.get(key)
        if cached and not fresh and cached[1] > time.monotonic():
            return cached[0]
        try:
            response = await client.post(
                TOKEN_URL.format(tenant=urllib.parse.quote(creds.tenant_id, safe="")),
                data={
                    "grant_type": "client_credentials",
                    "client_id": creds.client_id,
                    "client_secret": creds.client_secret.get_secret_value(),
                    "scope": SCOPE,
                },
            )
        except httpx.HTTPError as exc:
            raise ProviderUnavailable(f"Microsoft login unreachable: {type(exc).__name__}") from None
        if response.status_code >= 500:
            raise ProviderUnavailable(f"Microsoft login {response.status_code}")
        if response.status_code != 200:
            raise ProviderAuthFailed(f"Microsoft login refused the credentials: {_graph_error(response)}")
        data = response.json()
        token = data.get("access_token")
        if not token:
            raise ProviderAuthFailed("Microsoft login answered without an access token")
        lifetime = int(data.get("expires_in", 3599))
        if len(_tokens) >= _MAX_CACHED:
            _tokens.clear()
        _tokens[key] = (token, time.monotonic() + max(lifetime - _EARLY_S, 0))
        return token


def _graph_error(response: httpx.Response) -> str:
    try:
        data = response.json()
    except ValueError:
        return f"{response.status_code}"
    err = data.get("error") if isinstance(data, dict) else None
    if isinstance(err, dict):  # Graph: {"error": {"code", "message"}}
        return f"{err.get('code')}: {err.get('message')}"
    if isinstance(err, str):   # login: {"error", "error_description"}
        description = str(data.get("error_description") or "").splitlines()
        return f"{err}: {description[0]}" if description else err
    return f"{response.status_code}"


def message_payload(req: GraphEmail) -> dict:
    # Graph carries one body; HTML when the caller gave both.
    body = {"contentType": "HTML", "content": req.html} if req.html else {"contentType": "Text", "content": req.text}
    message = {
        "subject": req.subject,
        "body": body,
        "toRecipients": [{"emailAddress": {"address": to}} for to in req.to],
    }
    if req.reply_to:
        message["replyTo"] = [{"emailAddress": {"address": req.reply_to}}]
    return {"message": message, "saveToSentItems": False}


async def send(client: httpx.AsyncClient, req: GraphEmail) -> None:
    creds = req.credentials
    url = f"{GRAPH_URL}/users/{urllib.parse.quote(creds.sender, safe='')}/sendMail"
    payload = message_payload(req)
    for attempt in range(2):
        token = await _token(client, creds, fresh=attempt > 0)
        try:
            response = await client.post(url, json=payload, headers={"Authorization": f"Bearer {token}"})
        except httpx.HTTPError as exc:
            raise ProviderUnavailable(f"Microsoft Graph unreachable: {type(exc).__name__}") from None
        if response.status_code == 401 and attempt == 0:
            continue
        break
    if response.status_code < 300:
        return None
    if response.status_code in (401, 403):
        raise ProviderAuthFailed(f"Microsoft Graph refused to send as {creds.sender}: {_graph_error(response)}")
    if response.status_code == 429 or response.status_code >= 500:
        raise ProviderUnavailable(f"Microsoft Graph {response.status_code}: {_graph_error(response)}")
    raise ProviderRejected(f"Microsoft Graph rejected the message: {_graph_error(response)}")
