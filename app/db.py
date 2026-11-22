"""asyncpg pool and every query notify-service makes."""

import json
import uuid
from pathlib import Path
from typing import Optional

import asyncpg

from .config import settings

_pool: Optional[asyncpg.Pool] = None
SCHEMA = (Path(__file__).parent / "schema.sql").read_text()


async def connect(url: str | None = None, **kwargs) -> asyncpg.Pool:
    global _pool
    _pool = await asyncpg.create_pool(url or settings.database_url, min_size=1, max_size=10, **kwargs)
    async with _pool.acquire() as conn:
        # One instance applies the schema at a time.
        async with conn.transaction():
            await conn.execute("SELECT pg_advisory_xact_lock(7316001)")
            await conn.execute(SCHEMA)
    return _pool


async def close() -> None:
    global _pool
    if _pool is not None:
        await _pool.close()
        _pool = None


def pool() -> asyncpg.Pool:
    if _pool is None:
        raise RuntimeError("database not connected")
    return _pool


# ── clients and keys ─────────────────────────────────────────────────────────

async def client_for_key(key_hash: bytes) -> Optional[str]:
    return await pool().fetchval(
        """UPDATE api_keys k SET last_used_at = now()
             FROM clients c
            WHERE k.key_hash = $1 AND k.revoked_at IS NULL AND c.id = k.client_id AND c.active
        RETURNING k.client_id""", key_hash)


async def get_config(client_id: str, name: str) -> Optional[asyncpg.Record]:
    return await pool().fetchrow(
        "SELECT kind, provider, settings FROM provider_configs WHERE client_id = $1 AND name = $2 AND active",
        client_id, name)


# ── the message log ──────────────────────────────────────────────────────────

async def log_send(*, client_id: str, config_name: str, kind: str, provider: str, sender: str,
                   recipients: list[str], subject: str | None, body_text: str | None, body_html: str | None,
                   media_urls: list[str] | None, body_length: int, body_mac: bytes | None,
                   sensitive: bool, reference: str | None) -> uuid.UUID:
    message_id = uuid.uuid4()
    await pool().execute(
        """INSERT INTO messages (id, client_id, config_name, kind, provider, sender, recipients, subject,
                                 body_text, body_html, media_urls, body_length, body_mac, sensitive,
                                 reference, status)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, 'sending')""",
        message_id, client_id, config_name, kind, provider, sender, recipients, subject,
        body_text, body_html, media_urls, body_length, body_mac, sensitive, reference)
    return message_id


async def log_accepted(message_id: uuid.UUID, provider_message_id: str | None, refused: list[str]) -> None:
    await pool().execute(
        """UPDATE messages SET status = 'accepted', provider_message_id = $2, refused = $3, updated_at = now()
            WHERE id = $1""", message_id, provider_message_id, refused or None)


async def log_failed(message_id: uuid.UUID, error: str, detail: str) -> None:
    await pool().execute(
        "UPDATE messages SET status = 'failed', error = $2, error_detail = $3, updated_at = now() WHERE id = $1",
        message_id, error, detail)


async def log_dlr(message_id: uuid.UUID, status: str, error: str | None, raw: dict) -> bool:
    result = await pool().execute(
        """UPDATE messages SET dlr_status = $2, dlr_error = $3, dlr_raw = $4::jsonb, dlr_at = now(),
                               updated_at = now()
            WHERE id = $1 AND provider = 'jasmin'""", message_id, status, error, json.dumps(raw))
    return result.endswith(" 1")


_PUBLIC = """id, config_name, kind, provider, sender, recipients, subject,
             CASE WHEN sensitive THEN NULL ELSE body_text END AS body_text,
             CASE WHEN sensitive THEN NULL ELSE body_html END AS body_html,
             media_urls, body_length, sensitive, reference, status, provider_message_id, error, error_detail,
             refused, dlr_status, dlr_error, dlr_at, created_at, updated_at"""


async def get_message(client_id: str, message_id: uuid.UUID) -> Optional[asyncpg.Record]:
    return await pool().fetchrow(f"SELECT {_PUBLIC} FROM messages WHERE client_id = $1 AND id = $2",
                                 client_id, message_id)


async def find_messages(client_id: str, *, reference: str | None, recipient: str | None,
                        before, limit: int) -> list[asyncpg.Record]:
    return await pool().fetch(
        f"""SELECT {_PUBLIC} FROM messages
             WHERE client_id = $1
               AND ($2::text IS NULL OR reference = $2)
               AND ($3::text IS NULL OR recipients @> ARRAY[$3::text])
               AND ($4::timestamptz IS NULL OR created_at < $4::timestamptz)
             ORDER BY created_at DESC LIMIT $5""",
        client_id, reference, recipient, before, limit)


async def purge(retention_days: int) -> int:
    result = await pool().execute(
        "DELETE FROM messages WHERE created_at < now() - make_interval(days => $1)", retention_days)
    return int(result.split()[-1])
