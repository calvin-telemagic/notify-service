"""
Manage notify-service's clients, API keys and provider configs.

    docker compose exec notify-service python -m app.admin <command>

  client add <id> [--description TEXT]
  client list
  client disable|enable <id>
  key create <client> [--label TEXT]      prints the new key once; only its hash is kept
  key list <client>
  key revoke <key-id>
  config set <client> <name>              reads the config's JSON from stdin (never argv,
                                          so secrets stay out of shell history and ps)
  config list [<client>]                  secrets masked
  config disable|enable <client> <name>
  messages <client> [--limit N]           the latest sends, bodies left out

config set examples (one JSON object on stdin):

  {"provider": "jasmin", "base_url": "http://jasmin:1401", "username": "sv", "password": "...",
   "from_numbers": ["16606009000"]}
  {"provider": "inteliquent", "token": "...", "from_numbers": ["16606009000"]}
  {"provider": "graph", "tenant_id": "...", "client_id": "...", "client_secret": "...",
   "sender": "noreply@telemagic.app"}
  {"provider": "smtp", "host": "smtp.office365.com", "port": 587, "username": "...", "password": "...",
   "from": "PQTutela <noreply@pqtutela.telemagic.app>"}
"""

import argparse
import asyncio
import json
import re
import secrets
import sys
import uuid

from pydantic import ValidationError

from . import db, vault
from .models import CONFIG_NAME, KIND, SECRET_FIELDS, config_json, provider_config

KEY_PREFIX = "nsk_"


class AdminError(Exception):
    pass


async def client_add(client_id: str, description: str = "") -> None:
    try:
        await db.pool().execute("INSERT INTO clients (id, description) VALUES ($1, $2)", client_id, description)
    except Exception as exc:  # unique or check violation
        raise AdminError(f"can't add client {client_id!r}: {exc}") from None


async def client_list() -> list[dict]:
    rows = await db.pool().fetch(
        """SELECT c.id, c.description, c.active, c.created_at,
                  (SELECT COUNT(*) FROM api_keys k WHERE k.client_id = c.id AND k.revoked_at IS NULL) AS keys,
                  (SELECT COUNT(*) FROM provider_configs p WHERE p.client_id = c.id AND p.active) AS configs
             FROM clients c ORDER BY c.id""")
    return [dict(r) for r in rows]


async def client_set_active(client_id: str, active: bool) -> None:
    if await db.pool().execute("UPDATE clients SET active = $2 WHERE id = $1", client_id, active) == "UPDATE 0":
        raise AdminError(f"no client {client_id!r}")


async def key_create(client_id: str, label: str = "") -> tuple[uuid.UUID, str]:
    if not await db.pool().fetchval("SELECT 1 FROM clients WHERE id = $1", client_id):
        raise AdminError(f"no client {client_id!r}")
    key = KEY_PREFIX + secrets.token_urlsafe(32)
    key_id = uuid.uuid4()
    await db.pool().execute("INSERT INTO api_keys (id, client_id, key_hash, label) VALUES ($1, $2, $3, $4)",
                            key_id, client_id, vault.api_key_hash(key), label)
    return key_id, key


async def key_list(client_id: str) -> list[dict]:
    rows = await db.pool().fetch(
        "SELECT id, label, created_at, last_used_at, revoked_at FROM api_keys WHERE client_id = $1 ORDER BY created_at",
        client_id)
    return [dict(r) for r in rows]


async def key_revoke(key_id: str) -> None:
    result = await db.pool().execute(
        "UPDATE api_keys SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL", uuid.UUID(key_id))
    if result == "UPDATE 0":
        raise AdminError(f"no live key {key_id}")


async def config_set(client_id: str, name: str, settings: dict) -> str:
    if not re.match(CONFIG_NAME, name):
        raise AdminError("config names are lowercase letters, digits, '-' and '_'")
    try:
        cfg = provider_config.validate_python(settings)
    except ValidationError as exc:
        # Field names and messages only: never the values (they're secrets).
        problems = "; ".join(f"{'.'.join(map(str, e['loc']))}: {e['msg']}" for e in exc.errors())
        raise AdminError(f"invalid config: {problems}") from None
    if not await db.pool().fetchval("SELECT 1 FROM clients WHERE id = $1", client_id):
        raise AdminError(f"no client {client_id!r}")
    sealed = vault.seal(client_id, name, config_json(cfg))
    await db.pool().execute(
        """INSERT INTO provider_configs (client_id, name, kind, provider, settings)
           VALUES ($1, $2, $3, $4, $5)
           ON CONFLICT (client_id, name) DO UPDATE
              SET kind = EXCLUDED.kind, provider = EXCLUDED.provider, settings = EXCLUDED.settings,
                  active = TRUE, updated_at = now()""",
        client_id, name, KIND[cfg.provider], cfg.provider, sealed)
    return cfg.provider


async def config_list(client_id: str | None = None) -> list[dict]:
    rows = await db.pool().fetch(
        """SELECT client_id, name, kind, provider, settings, active, updated_at FROM provider_configs
            WHERE $1::text IS NULL OR client_id = $1 ORDER BY client_id, name""", client_id)
    out = []
    for r in rows:
        try:
            shown = {k: ("****" if k in SECRET_FIELDS else v)
                     for k, v in vault.open_(r["client_id"], r["name"], r["settings"]).items()}
        except vault.VaultError as exc:
            shown = {"error": str(exc)}
        out.append({**{k: r[k] for k in ("client_id", "name", "kind", "provider", "active", "updated_at")},
                    "settings": shown})
    return out


async def config_set_active(client_id: str, name: str, active: bool) -> None:
    result = await db.pool().execute(
        "UPDATE provider_configs SET active = $3, updated_at = now() WHERE client_id = $1 AND name = $2",
        client_id, name, active)
    if result == "UPDATE 0":
        raise AdminError(f"no config {client_id}/{name}")


async def recent_messages(client_id: str, limit: int) -> list[dict]:
    rows = await db.pool().fetch(
        """SELECT id, created_at, config_name, provider, recipients, status, error, dlr_status, sensitive, reference
             FROM messages WHERE client_id = $1 ORDER BY created_at DESC LIMIT $2""", client_id, limit)
    return [dict(r) for r in rows]


def _print(rows) -> None:
    print(json.dumps(rows, indent=2, default=str))


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python -m app.admin", description=__doc__.split("\n\n")[0])
    sub = p.add_subparsers(dest="area", required=True)

    c = sub.add_parser("client").add_subparsers(dest="action", required=True)
    add = c.add_parser("add"); add.add_argument("id"); add.add_argument("--description", default="")
    c.add_parser("list")
    for action in ("disable", "enable"):
        c.add_parser(action).add_argument("id")

    k = sub.add_parser("key").add_subparsers(dest="action", required=True)
    create = k.add_parser("create"); create.add_argument("client"); create.add_argument("--label", default="")
    k.add_parser("list").add_argument("client")
    k.add_parser("revoke").add_argument("key_id")

    g = sub.add_parser("config").add_subparsers(dest="action", required=True)
    put = g.add_parser("set"); put.add_argument("client"); put.add_argument("name")
    g.add_parser("list").add_argument("client", nargs="?")
    for action in ("disable", "enable"):
        a = g.add_parser(action); a.add_argument("client"); a.add_argument("name")

    m = sub.add_parser("messages"); m.add_argument("client"); m.add_argument("--limit", type=int, default=20)
    return p


async def run(args) -> None:
    await db.connect()
    try:
        if args.area == "client":
            if args.action == "add":
                await client_add(args.id, args.description); print(f"added client {args.id}")
            elif args.action == "list":
                _print(await client_list())
            else:
                await client_set_active(args.id, args.action == "enable"); print(f"{args.action}d {args.id}")
        elif args.area == "key":
            if args.action == "create":
                key_id, key = await key_create(args.client, args.label)
                print(f"key id {key_id}\n\n  {key}\n\nShown once: store it in the client's secrets now.")
            elif args.action == "list":
                _print(await key_list(args.client))
            else:
                await key_revoke(args.key_id); print(f"revoked {args.key_id}")
        elif args.area == "config":
            if args.action == "set":
                if sys.stdin.isatty():
                    print("Paste the config JSON, then Ctrl-D:", file=sys.stderr)
                try:
                    settings = json.loads(sys.stdin.read())
                except json.JSONDecodeError as exc:
                    raise AdminError(f"stdin isn't JSON: {exc.msg} (line {exc.lineno})") from None
                provider = await config_set(args.client, args.name, settings)
                print(f"set {args.client}/{args.name} ({provider})")
            elif args.action == "list":
                _print(await config_list(args.client))
            else:
                await config_set_active(args.client, args.name, args.action == "enable")
                print(f"{args.action}d {args.client}/{args.name}")
        else:
            _print(await recent_messages(args.client, args.limit))
    finally:
        await db.close()


def main(argv=None) -> int:
    args = _parser().parse_args(argv)
    try:
        asyncio.run(run(args))
    except AdminError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
