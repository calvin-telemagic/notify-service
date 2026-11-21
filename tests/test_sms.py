import json

import httpx
import respx

from app.providers import jasmin

from .test_api import JASMIN

BROKER = "https://messagebroker.inteliquent.com/msgbroker/rest/publishMessages"
INTELIQUENT = {
    "provider": "inteliquent",
    "credentials": {"token": "bearer-tok"},
    "from": "+16606009000",
    "to": "+15551234567",
    "body": "hello",
}


@respx.mock
def test_jasmin_send(client):
    route = respx.get("http://jasmin.internal:1401/send").respond(200, text='Success "86d69a0b-7142"')
    r = client.post("/v1/sms", json={**JASMIN, "route": "inteliquent", "dlr_url": "http://hub/dlr"})
    assert r.status_code == 200
    assert r.json() == {"status": "accepted", "provider": "jasmin", "message_id": "86d69a0b-7142", "refused": []}
    params = dict(route.calls.last.request.url.params)
    assert params == {
        "username": "tm", "password": "s3cret-pw", "from": "16606009000", "to": "+15551234567",
        "content": "Your code is 123456", "route": "inteliquent",
        "dlr": "yes", "dlr-url": "http://hub/dlr", "dlr-level": "2", "dlr-method": "POST",
    }


@respx.mock
def test_jasmin_unicode_goes_as_ucs2_hex(client):
    route = respx.get("http://jasmin.internal:1401/send").respond(200, text='Success "x"')
    client.post("/v1/sms", json={**JASMIN, "body": "Hi 👋"})
    params = dict(route.calls.last.request.url.params)
    assert params["coding"] == "8" and "content" not in params
    assert bytes.fromhex(params["hex-content"]).decode("utf-16-be") == "Hi 👋"
    assert "dlr" not in params


def test_jasmin_parse():
    assert jasmin.parse_response('Success "a-b"\n') == ("a-b", None)
    assert jasmin.parse_response('Error "No route found"') == (None, "No route found")
    assert jasmin.parse_response("garbage")[0] is None


@respx.mock
def test_jasmin_errors(client):
    send = respx.get("http://jasmin.internal:1401/send")
    send.respond(412, text='Error "No route found"')
    r = client.post("/v1/sms", json=JASMIN)
    assert r.status_code == 502 and r.json() == {
        "error": "provider_rejected", "detail": "Jasmin rejected the message: No route found", "retryable": False}

    send.respond(403, text='Error "Authentication failure for username:tm"')
    assert client.post("/v1/sms", json=JASMIN).json()["error"] == "provider_auth_failed"

    send.side_effect = httpx.ConnectError("boom")
    r = client.post("/v1/sms", json=JASMIN)
    assert r.status_code == 503 and r.json()["retryable"] is True


def test_jasmin_host_must_be_allowed(client):
    for url in ("http://10.0.0.5:1401", "file:///etc/passwd", "http://u:p@jasmin.internal:1401"):
        bad = {**JASMIN, "credentials": {**JASMIN["credentials"], "base_url": url}}
        r = client.post("/v1/sms", json=bad)
        assert r.status_code == 403 and r.json()["error"] == "host_not_allowed", url


@respx.mock
def test_inteliquent_send(client):
    route = respx.post(BROKER).respond(200, json={"success": True, "result": {"referenceId": "ref-9"}})
    r = client.post("/v1/sms", json={**INTELIQUENT, "media_urls": ["https://x/y.png"]})
    assert r.status_code == 200 and r.json()["message_id"] == "ref-9"
    request = route.calls.last.request
    assert request.headers["Authorization"] == "Bearer bearer-tok"
    assert json.loads(request.content) == {
        "from": "16606009000", "to": ["15551234567"], "text": "hello", "mediaUrls": ["https://x/y.png"]}


@respx.mock
def test_inteliquent_errors(client):
    route = respx.post(BROKER)
    route.respond(401)
    assert client.post("/v1/sms", json=INTELIQUENT).json()["error"] == "provider_auth_failed"
    route.respond(400, text="bad number")
    assert client.post("/v1/sms", json=INTELIQUENT).json()["detail"] == "Inteliquent 400: bad number"
    route.respond(503)
    assert client.post("/v1/sms", json=INTELIQUENT).status_code == 503


def test_inteliquent_needs_content_and_allowed_override(client):
    assert client.post("/v1/sms", json={**INTELIQUENT, "body": None}).status_code == 422
    other = {**INTELIQUENT, "credentials": {"token": "t", "base_url": "https://evil.example/"}}
    assert client.post("/v1/sms", json=other).status_code == 403
