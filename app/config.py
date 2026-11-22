"""
notify-service settings, from the environment. Clients, their API keys and
their provider configs live in the database (app/admin.py manages them).

  DATABASE_URL            postgresql://... (required)
  CONFIG_ENCRYPTION_KEY   32 random bytes, base64url: encrypts stored provider
                          configs (AES-256-GCM) and keys the body MACs and
                          delivery-receipt URLs. Required. Generate with
                            python3 -c "import secrets,base64; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())"
                          Losing it makes every stored config unreadable.
  DLR_BASE_URL            How Jasmin reaches this service, e.g.
                          http://10.0.0.5:8010. Set: every Jasmin send asks for
                          a delivery receipt at <DLR_BASE_URL>/dlr/jasmin/...
                          Blank: no receipts.
  MESSAGE_RETENTION_DAYS  Log rows older than this are deleted (default 365;
                          0 keeps them forever).
  ALLOW_INSECURE_SMTP     "true" permits SMTP security "none". Off by default.
  PROVIDER_TIMEOUT_S      Per-request timeout towards providers (default 10).
  LOG_LEVEL               Default INFO.
"""

import base64
import binascii
import os


def _bool(name: str) -> bool:
    return os.getenv(name, "").strip().lower() in {"1", "true", "yes"}


def _key(value: str) -> bytes | None:
    if not value:
        return None
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (binascii.Error, ValueError):
        raise SystemExit("CONFIG_ENCRYPTION_KEY is not base64url") from None
    if len(raw) != 32:
        raise SystemExit("CONFIG_ENCRYPTION_KEY must be 32 bytes")
    return raw


class Settings:
    def __init__(self) -> None:
        self.database_url: str = os.getenv("DATABASE_URL", "")
        self.encryption_key: bytes | None = _key(os.getenv("CONFIG_ENCRYPTION_KEY", "").strip())
        self.dlr_base_url: str = os.getenv("DLR_BASE_URL", "").strip().rstrip("/")
        self.retention_days: int = int(os.getenv("MESSAGE_RETENTION_DAYS", "365"))
        self.allow_insecure_smtp: bool = _bool("ALLOW_INSECURE_SMTP")
        self.provider_timeout_s: float = float(os.getenv("PROVIDER_TIMEOUT_S", "10"))
        self.log_level: str = os.getenv("LOG_LEVEL", "INFO").upper()


settings = Settings()
