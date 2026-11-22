"""
SMS/MMS through Inteliquent's Message Broker (POST {base_url}publishMessages),
extracted from tm-messaging's mms-server/src/server.js publishMessage().
Numbers go without the "+"; the broker's reference is result.referenceId.
"""

from urllib.parse import urljoin

import httpx

from ..errors import ProviderAuthFailed, ProviderRejected, ProviderUnavailable
from ..models import InteliquentConfig


async def send(client: httpx.AsyncClient, cfg: InteliquentConfig, *, sender: str, to: str,
               body: str | None, media_urls: list[str]) -> str | None:
    base_url = cfg.base_url if cfg.base_url.endswith("/") else cfg.base_url + "/"
    payload: dict = {"from": sender.lstrip("+"), "to": [to.lstrip("+")]}
    if body:
        payload["text"] = body
    if media_urls:
        payload["mediaUrls"] = media_urls

    try:
        response = await client.post(
            urljoin(base_url, "publishMessages"),
            json=payload,
            headers={"Authorization": f"Bearer {cfg.token.get_secret_value()}"},
        )
    except httpx.HTTPError as exc:
        raise ProviderUnavailable(f"Inteliquent unreachable: {type(exc).__name__}") from None

    if response.status_code in (401, 403):
        raise ProviderAuthFailed(f"Inteliquent refused the token ({response.status_code})")
    if response.status_code >= 500:
        raise ProviderUnavailable(f"Inteliquent {response.status_code}")
    if response.status_code >= 300:
        raise ProviderRejected(f"Inteliquent {response.status_code}: {response.text}")
    try:
        data = response.json()
    except ValueError:
        return None
    result = data.get("result") if isinstance(data, dict) else None
    reference = result.get("referenceId") if isinstance(result, dict) else None
    return str(reference) if reference else None
