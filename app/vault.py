"""
Everything keyed by CONFIG_ENCRYPTION_KEY:

- provider configs at rest: AES-256-GCM, bound (as associated data) to the
  client and config name, so a row copied onto another config won't decrypt;
- body MACs for sensitive messages: lets an investigator check "was this the
  text we sent?" without the log holding it (a plain hash of a 6-digit code
  would give the code away);
- delivery-receipt URLs: Jasmin can't authenticate, so each message's
  receipt URL carries a MAC of its id.

Each use gets its own key derived from the master key.
"""

import base64
import hashlib
import hmac
import json
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .config import settings

_VERSION = b"\x01"


class VaultError(Exception):
    pass


def _master() -> bytes:
    if settings.encryption_key is None:
        raise VaultError("CONFIG_ENCRYPTION_KEY is not set")
    return settings.encryption_key


def _derive(purpose: bytes) -> bytes:
    return hmac.new(_master(), b"notify-service/v1/" + purpose, hashlib.sha256).digest()


def _aad(client_id: str, name: str) -> bytes:
    return client_id.encode() + b"\0" + name.encode()


def seal(client_id: str, name: str, settings_: dict) -> bytes:
    nonce = os.urandom(12)
    plaintext = json.dumps(settings_, separators=(",", ":")).encode()
    return _VERSION + nonce + AESGCM(_derive(b"config")).encrypt(nonce, plaintext, _aad(client_id, name))


def open_(client_id: str, name: str, blob: bytes) -> dict:
    blob = bytes(blob)
    if blob[:1] != _VERSION or len(blob) < 1 + 12 + 16:
        raise VaultError("unknown config format")
    try:
        plaintext = AESGCM(_derive(b"config")).decrypt(blob[1:13], blob[13:], _aad(client_id, name))
    except InvalidTag:
        raise VaultError("config doesn't decrypt with this CONFIG_ENCRYPTION_KEY") from None
    return json.loads(plaintext)


def body_mac(*parts: str | None) -> bytes:
    mac = hmac.new(_derive(b"body"), digestmod=hashlib.sha256)
    for part in parts:
        mac.update((part or "").encode() + b"\0")
    return mac.digest()


def dlr_token(message_id: str) -> str:
    mac = hmac.new(_derive(b"dlr"), message_id.encode(), hashlib.sha256).digest()[:18]
    return base64.urlsafe_b64encode(mac).decode()


def dlr_token_ok(message_id: str, token: str) -> bool:
    return hmac.compare_digest(dlr_token(message_id), token)


def api_key_hash(key: str) -> bytes:
    # Keys are 256 random bits, so a plain hash is enough to make a leaked
    # table useless; no per-key salt or slow hash needed.
    return hashlib.sha256(key.encode()).digest()
