import logging

import httpx
import respx

from app.egress import host_allowed
from app.main import mask

JASMIN = {
    "provider": "jasmin",
    "credentials": {"base_url": "http://jasmin.internal:1401", "username": "tm", "password": "s3cret-pw"},
    "from": "16606009000",
    "to": "+15551234567",
    "body": "Your code is 123456",
}


def test_needs_an_api_key(client):
    for header in ("", "Bearer", "Basic test-key-1", "Bearer wrong"):
        r = client.post("/v1/sms", json=JASMIN, headers={"Authorization": header})
        assert r.status_code == 401, header
    assert client.post("/v1/sms", json={}, headers={"Authorization": "Bearer nope"}).status_code == 401


def test_refuses_everything_without_keys(client, monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings, "api_keys", [])
    r = client.post("/v1/sms", json=JASMIN)
    assert r.status_code == 503 and r.json()["error"] == "not_configured"


def test_healthz_is_open(client):
    assert client.get("/healthz", headers={"Authorization": ""}).json() == {"status": "ok"}


def test_validation_errors_never_echo_secrets(client):
    bad = {**JASMIN, "to": "not-a-number", "credentials": {**JASMIN["credentials"], "extra": "s3cret-pw"}}
    r = client.post("/v1/sms", json=bad)
    assert r.status_code == 422
    assert "s3cret-pw" not in r.text and "not-a-number" not in r.text
    assert r.json()["error"] == "invalid_request"


def test_unknown_provider_and_extra_fields(client):
    assert client.post("/v1/sms", json={**JASMIN, "provider": "twilio"}).status_code == 422
    assert client.post("/v1/sms", json={**JASMIN, "cc": "x"}).status_code == 422


def test_host_patterns():
    allowed = ["jasmin.internal", "*.mail.example"]
    assert host_allowed("Jasmin.Internal.", allowed)
    assert host_allowed("smtp.mail.example", allowed)
    assert not host_allowed("mail.example", allowed)
    assert not host_allowed("evilmail.example", allowed)
    assert not host_allowed("jasmin.internal.evil", allowed)
    assert not host_allowed("anything", [])
    assert host_allowed("anything", ["*"])


def test_mask():
    assert mask("+15551234567") == "***4567"
    assert mask("alice@example.com") == "a***@example.com"


@respx.mock
def test_logs_carry_no_secrets_or_bodies(client, caplog):
    respx.get("http://jasmin.internal:1401/send").respond(200, text='Success "abc"')
    with caplog.at_level(logging.DEBUG):
        assert client.post("/v1/sms", json=JASMIN).status_code == 200
    text = caplog.text
    assert "s3cret-pw" not in text and "123456" not in text and "5551234567" not in text
    assert "***4567" in text and "accepted" in text
