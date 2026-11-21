import pytest
from fastapi.testclient import TestClient

from app import main
from app.config import settings
from app.providers import graph

KEY = "test-key-1"


@pytest.fixture(autouse=True)
def _settings(monkeypatch):
    monkeypatch.setattr(settings, "api_keys", [KEY, "other-key"])
    monkeypatch.setattr(settings, "egress_allowed_hosts", ["jasmin.internal", "*.mail.example", "127.0.0.1"])
    monkeypatch.setattr(settings, "allow_insecure_smtp", False)
    graph.clear_cache()


@pytest.fixture
def client():
    with TestClient(main.app) as c:
        c.headers["Authorization"] = f"Bearer {KEY}"
        yield c
