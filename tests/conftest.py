"""
Tests run against a real Postgres: TEST_DATABASE_URL if set, otherwise a
throwaway cluster started with the local initdb/pg_ctl (the Dockerfile's
test stage installs them). Every test starts from empty tables.
"""

import base64
import glob
import os
import shutil
import socket
import subprocess
import tempfile

import pytest
from fastapi.testclient import TestClient

from app import admin, db, main
from app.config import settings
from app.providers import graph

KEY = base64.urlsafe_b64encode(b"k" * 32).decode()


def _pg_bin(name: str) -> str | None:
    found = shutil.which(name)
    if found:
        return found
    candidates = sorted(glob.glob(f"/usr/lib/postgresql/*/bin/{name}"))
    return candidates[-1] if candidates else None


@pytest.fixture(scope="session")
def database_url():
    url = os.getenv("TEST_DATABASE_URL")
    if url:
        yield url
        return
    initdb, pg_ctl = _pg_bin("initdb"), _pg_bin("pg_ctl")
    if not (initdb and pg_ctl):
        pytest.skip("no TEST_DATABASE_URL and no local initdb/pg_ctl")
    data = tempfile.mkdtemp(prefix="notify-pg-")
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    subprocess.run([initdb, "-D", data, "-U", "notify", "--auth=trust", "-E", "UTF8"], check=True,
                   capture_output=True)
    subprocess.run([pg_ctl, "-D", data, "-l", f"{data}/log", "-w", "-o",
                    f"-p {port} -k {data} -c listen_addresses=127.0.0.1 -c fsync=off", "start"],
                   check=True, capture_output=True)
    try:
        yield f"postgresql://notify@127.0.0.1:{port}/postgres"
    finally:
        subprocess.run([pg_ctl, "-D", data, "-m", "immediate", "stop"], capture_output=True)
        shutil.rmtree(data, ignore_errors=True)


@pytest.fixture(autouse=True)
def _settings(monkeypatch, database_url):
    monkeypatch.setattr(settings, "database_url", database_url)
    monkeypatch.setattr(settings, "encryption_key", base64.urlsafe_b64decode(KEY))
    monkeypatch.setattr(settings, "dlr_base_url", "http://notify.internal:8010")
    monkeypatch.setattr(settings, "allow_insecure_smtp", False)
    monkeypatch.setattr(settings, "retention_days", 0)
    graph.clear_cache()


class Harness:
    """The app under test plus admin helpers run on the app's own event loop."""

    def __init__(self, client: TestClient):
        self.http = client
        self.portal = client.portal

    def call(self, fn, *args):
        return self.portal.call(fn, *args)

    def sql(self, query, *args):
        async def go():
            return [dict(r) for r in await db.pool().fetch(query, *args)]
        return self.portal.call(go)

    def add_client(self, client_id: str) -> str:
        self.call(admin.client_add, client_id, "")
        return self.call(admin.key_create, client_id, "test")[1]

    def set_config(self, client_id: str, name: str, cfg: dict) -> None:
        self.call(admin.config_set, client_id, name, cfg)

    def as_client(self, key: str) -> dict:
        return {"Authorization": f"Bearer {key}"}


JASMIN_CFG = {"provider": "jasmin", "base_url": "http://jasmin.internal:1401", "username": "tm",
              "password": "s3cret-pw", "from_numbers": ["16606009000"], "route": "inteliquent"}
INTELIQUENT_CFG = {"provider": "inteliquent", "token": "bearer-tok", "from_numbers": ["+16606009000"]}
GRAPH_CFG = {"provider": "graph", "tenant_id": "tenant-1", "client_id": "client-1",
             "client_secret": "graph-secret", "sender": "noreply@telemagic.app"}


@pytest.fixture
def h():
    with TestClient(main.app) as client:
        harness = Harness(client)
        harness.sql("TRUNCATE messages, provider_configs, api_keys, clients")
        harness.key = harness.add_client("sv")
        client.headers["Authorization"] = f"Bearer {harness.key}"
        harness.set_config("sv", "sv-sms", JASMIN_CFG)
        harness.set_config("sv", "sv-mms", INTELIQUENT_CFG)
        harness.set_config("sv", "sv-email", GRAPH_CFG)
        yield harness
