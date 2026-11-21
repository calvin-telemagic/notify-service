"""
notify-service settings, all from the environment. The service holds no
provider credentials of its own: every request carries the Jasmin,
Inteliquent, Microsoft Graph or SMTP credentials it should be sent with.

  API_KEYS               Comma-separated keys callers present as
                         "Authorization: Bearer <key>". Required: with none
                         set, every send is refused (503).
  EGRESS_ALLOWED_HOSTS   Comma-separated hosts a request may point the service
                         at (Jasmin base_url, an Inteliquent base_url
                         override, an SMTP host). Exact names or IPs,
                         "*.example.com" wildcards, or "*" for any. Empty
                         means none: only the fixed Microsoft Graph and
                         Inteliquent endpoints can be used.
  ALLOW_INSECURE_SMTP    "true" permits SMTP security "none" (plaintext,
                         password included). Off by default.
  PROVIDER_TIMEOUT_S     Per-request timeout towards providers (default 10).
  LOG_LEVEL              Default INFO.
"""

import os


def _list(name: str) -> list[str]:
    return [item.strip() for item in os.getenv(name, "").split(",") if item.strip()]


def _bool(name: str) -> bool:
    return os.getenv(name, "").strip().lower() in {"1", "true", "yes"}


class Settings:
    def __init__(self) -> None:
        self.api_keys: list[str] = _list("API_KEYS")
        self.egress_allowed_hosts: list[str] = [h.lower() for h in _list("EGRESS_ALLOWED_HOSTS")]
        self.allow_insecure_smtp: bool = _bool("ALLOW_INSECURE_SMTP")
        self.provider_timeout_s: float = float(os.getenv("PROVIDER_TIMEOUT_S", "10"))
        self.log_level: str = os.getenv("LOG_LEVEL", "INFO").upper()


settings = Settings()
