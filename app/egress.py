"""
Which hosts a caller may point the service at.

A request that names its own endpoint (a Jasmin base_url, an Inteliquent
base_url override, an SMTP host) would otherwise let any caller use this
service to reach anything it can reach, internal networks included. Only
hosts in EGRESS_ALLOWED_HOSTS are allowed; the fixed provider endpoints
(Microsoft's login and Graph hosts, Inteliquent's default) don't go through
this check. Redirects are never followed (see main.py's HTTP client), so an
allowed host can't bounce the service elsewhere.
"""

from urllib.parse import urlsplit

from .config import settings
from .errors import EgressRefused


def host_allowed(host: str, allowed: list[str] | None = None) -> bool:
    host = host.strip().rstrip(".").lower()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if not host:
        return False
    for pattern in settings.egress_allowed_hosts if allowed is None else allowed:
        if pattern == "*" or pattern == host:
            return True
        if pattern.startswith("*.") and host.endswith(pattern[1:]) and host != pattern[2:]:
            return True
    return False


def check_host(host: str) -> None:
    if not host_allowed(host):
        raise EgressRefused(f"{host} is not in this service's EGRESS_ALLOWED_HOSTS")


def check_url(url: str) -> None:
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise EgressRefused("base_url must be an http(s) URL")
    if parts.username or parts.password:
        raise EgressRefused("base_url must not carry credentials; pass them in credentials")
    check_host(parts.hostname)
