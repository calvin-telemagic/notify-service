import json
import pytest

import httpx
import respx

from app import vault
from app.providers import jasmin

from .test_api import SEND, SMS

BROKER = "https://messagebroker.inteliquent.com/msgbroker/rest/publishMessages"
MMS = {"config": "sv-mms", "to": "+15551234567", "body": "hello"}


@respx.mock
def test_jasmin_send_is_logged_with_its_client(h):
    route = respx.get(SEND).respond(200, text='Success "86d69a0b-7142"')
    r = h.http.post("/v1/sms", json={**SMS, "reference": "order-1"})
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["status"] == "accepted" and out["provider_message_id"] == "86d69a0b-7142"

    params = dict(route.calls.last.request.url.params)
    dlr_url = f"http://notify.internal:8010/dlr/jasmin/{out['id']}/{vault.dlr_token(out['id'])}"
    assert params == {
        "username": "tm", "password": "s3cret-pw", "from": "16606009000", "to": "+15551234567",
        "content": "Your code is 123456",
        "dlr": "yes", "dlr-url": dlr_url, "dlr-level": "2", "dlr-method": "POST",
    }
    row = h.sql("SELECT * FROM messages")[0]
    assert row["client_id"] == "sv" and row["config_name"] == "sv-sms" and row["provider"] == "jasmin"
    assert row["sender"] == "16606009000" and row["recipients"] == ["+15551234567"]
    assert row["body_text"] == "Your code is 123456" and row["body_mac"] is None and row["reference"] == "order-1"
    assert row["status"] == "accepted" and row["provider_message_id"] == "86d69a0b-7142"

    got = h.http.get(f"/v1/messages/{out['id']}").json()
    assert got["body_text"] == "Your code is 123456" and got["dlr_status"] is None
    assert [m["id"] for m in h.http.get("/v1/messages", params={"reference": "order-1"}).json()] == [out["id"]]
    assert [m["id"] for m in h.http.get("/v1/messages", params={"to": "+15551234567"}).json()] == [out["id"]]
    assert h.http.get("/v1/messages", params={"to": "+15550000000"}).json() == []


@respx.mock
def test_sensitive_bodies_arent_kept(h):
    respx.get(SEND).respond(200, text='Success "x"')
    out = h.http.post("/v1/sms", json={**SMS, "sensitive": True}).json()
    row = h.sql("SELECT body_text, body_mac, body_length, sensitive FROM messages")[0]
    assert row["body_text"] is None and row["sensitive"] and row["body_length"] == len(SMS["body"])
    assert bytes(row["body_mac"]) == vault.body_mac(None, SMS["body"], None)
    assert h.http.get(f"/v1/messages/{out['id']}").json()["body_text"] is None


@respx.mock
def test_delivery_receipts(h):
    respx.get(SEND).respond(200, text='Success "jas-1"')
    out = h.http.post("/v1/sms", json=SMS).json()
    url = f"/dlr/jasmin/{out['id']}/{vault.dlr_token(out['id'])}"
    form = {"id": "jas-1", "message_status": "DELIVRD", "level": "2", "id_smsc": "smsc-9", "err": "000",
            "text": "Your code is 123456"}
    r = h.http.post(url, data=form, headers={"Authorization": ""})
    assert r.status_code == 200 and r.text == "ACK/Jasmin"
    row = h.sql("SELECT dlr_status, dlr_error, dlr_raw, dlr_at FROM messages")[0]
    raw = json.loads(row["dlr_raw"])
    assert row["dlr_status"] == "delivered" and row["dlr_error"] is None and row["dlr_at"] is not None
    assert raw["id_smsc"] == "smsc-9" and "text" not in raw          # the code never reaches the log
    assert h.http.get(f"/v1/messages/{out['id']}").json()["dlr_status"] == "delivered"

    h.http.post(url, data={**form, "message_status": "UNDELIV", "err": "00B"})
    assert h.sql("SELECT dlr_status, dlr_error FROM messages")[0] == {"dlr_status": "undeliverable", "dlr_error": "00B"}

    assert h.http.post(f"/dlr/jasmin/{out['id']}/forged", data=form).status_code == 403
    other = "00000000-0000-0000-0000-000000000000"
    assert h.http.post(f"/dlr/jasmin/{other}/{vault.dlr_token(other)}", data=form).text == "ACK/Jasmin"


@respx.mock
def test_no_receipts_without_a_dlr_base_url(h, monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings, "dlr_base_url", "")
    route = respx.get(SEND).respond(200, text='Success "x"')
    h.http.post("/v1/sms", json=SMS)
    assert "dlr" not in dict(route.calls.last.request.url.params)


@respx.mock
def test_sender_comes_from_the_config(h):
    h.set_config("sv", "pool", {"provider": "jasmin", "base_url": "http://jasmin.internal:1401",
                                "username": "tm", "password": "p", "from_numbers": ["16606009000", "16606009001"]})
    route = respx.get(SEND).respond(200, text='Success "x"')
    senders = set()
    for _ in range(20):
        h.http.post("/v1/sms", json={**SMS, "config": "pool"})
        senders.add(dict(route.calls.last.request.url.params)["from"])
    assert senders == {"16606009000", "16606009001"}
    assert h.http.post("/v1/sms", json={**SMS, "config": "pool", "from": "16606009001"}).status_code == 200
    r = h.http.post("/v1/sms", json={**SMS, "config": "pool", "from": "15550001111"})
    assert r.status_code == 400 and "from_numbers" in r.json()["detail"]


@respx.mock
def test_jasmin_unicode_goes_as_ucs2_hex(h):
    route = respx.get(SEND).respond(200, text='Success "x"')
    h.http.post("/v1/sms", json={**SMS, "body": "Hi 👋"})
    params = dict(route.calls.last.request.url.params)
    assert params["coding"] == "8" and "content" not in params
    assert bytes.fromhex(params["hex-content"]).decode("utf-16-be") == "Hi 👋"


def test_jasmin_parse():
    assert jasmin.parse_response('Success "a-b"\n') == ("a-b", None)
    assert jasmin.parse_response('Error "No route found"') == (None, "No route found")
    assert jasmin.parse_response("garbage")[0] is None
    assert jasmin.dlr_status("delivrd") == "delivered" and jasmin.dlr_status(None) == "unknown"


@respx.mock
def test_failures_are_logged(h):
    send = respx.get(SEND)
    send.respond(412, text='Error "No route found"')
    r = h.http.post("/v1/sms", json=SMS)
    assert r.status_code == 502 and r.json() == {
        "error": "provider_rejected", "detail": "Jasmin rejected the message: No route found", "retryable": False}
    send.respond(403, text='Error "Authentication failure for username:tm"')
    assert h.http.post("/v1/sms", json=SMS).json()["error"] == "provider_auth_failed"
    send.side_effect = httpx.ConnectError("boom")
    assert h.http.post("/v1/sms", json=SMS).json()["retryable"] is True
    rows = h.sql("SELECT status, error, error_detail FROM messages ORDER BY created_at")
    assert [(r["status"], r["error"]) for r in rows] == [
        ("failed", "provider_rejected"), ("failed", "provider_auth_failed"), ("failed", "provider_unavailable")]
    assert rows[0]["error_detail"] == "Jasmin rejected the message: No route found"


@respx.mock
def test_inteliquent_send(h):
    route = respx.post(BROKER).respond(200, json={"success": True, "result": {"referenceId": "ref-9"}})
    r = h.http.post("/v1/sms", json={**MMS, "media_urls": ["https://x/y.png"]})
    assert r.status_code == 200 and r.json()["provider_message_id"] == "ref-9"
    request = route.calls.last.request
    assert request.headers["Authorization"] == "Bearer bearer-tok"
    assert json.loads(request.content) == {
        "from": "16606009000", "to": ["15551234567"], "text": "hello", "mediaUrls": ["https://x/y.png"]}
    assert h.sql("SELECT media_urls FROM messages")[0]["media_urls"] == ["https://x/y.png"]


@respx.mock
def test_inteliquent_errors(h):
    route = respx.post(BROKER)
    route.respond(401)
    assert h.http.post("/v1/sms", json=MMS).json()["error"] == "provider_auth_failed"
    route.respond(400, text="bad number")
    assert h.http.post("/v1/sms", json=MMS).json()["detail"] == "Inteliquent 400: bad number"
    route.respond(503)
    assert h.http.post("/v1/sms", json=MMS).status_code == 503


def test_mms_needs_inteliquent(h):
    r = h.http.post("/v1/sms", json={**SMS, "media_urls": ["https://x/y.png"]})
    assert r.status_code == 400 and "Inteliquent" in r.json()["detail"]
    assert h.http.post("/v1/sms", json={**MMS, "body": None}).status_code == 422


@respx.mock
def test_from_any_takes_any_number_and_needs_one(h):
    h.set_config("sv", "dids", {"provider": "jasmin", "base_url": "http://jasmin.internal:1401",
                                "username": "tm", "password": "p", "from_any": True})
    route = respx.get(SEND).respond(200, text='Success "x"')
    assert h.http.post("/v1/sms", json={**SMS, "config": "dids", "from": "+15550001111"}).status_code == 200
    assert dict(route.calls.last.request.url.params)["from"] == "+15550001111"
    r = h.http.post("/v1/sms", json={**SMS, "config": "dids"})
    assert r.status_code == 400 and "from_any" in r.json()["detail"]


def test_sms_config_needs_numbers_unless_from_any():
    import pydantic
    from app.models import JasminConfig
    base = {"provider": "jasmin", "base_url": "http://j:1401", "username": "u", "password": "p"}
    with pytest.raises(pydantic.ValidationError):
        JasminConfig(**base)
    assert JasminConfig(**base, from_any=True).from_numbers == []
