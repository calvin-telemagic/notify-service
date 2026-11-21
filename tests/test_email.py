import asyncio
import json
import socket
import threading
from email import message_from_bytes
from email.policy import default as default_policy

import pytest
import respx
from aiosmtpd.controller import Controller
from aiosmtpd.smtp import AuthResult, LoginPassword

TOKEN = "https://login.microsoftonline.com/tenant-1/oauth2/v2.0/token"
SENDMAIL = "https://graph.microsoft.com/v1.0/users/noreply%40telemagic.app/sendMail"
GRAPH = {
    "provider": "graph",
    "credentials": {"tenant_id": "tenant-1", "client_id": "client-1", "client_secret": "graph-secret",
                    "sender": "noreply@telemagic.app"},
    "to": ["alice@example.com"],
    "subject": "Your code",
    "html": "<p>123456</p>",
}


@respx.mock
def test_graph_send_and_token_cache(client):
    token = respx.post(TOKEN).respond(200, json={"access_token": "tok-1", "expires_in": 3600})
    send = respx.post(SENDMAIL).respond(202)
    for _ in range(3):
        r = client.post("/v1/email", json={**GRAPH, "reply_to": "help@telemagic.app"})
        assert r.status_code == 200 and r.json()["provider"] == "graph"
    assert token.call_count == 1 and send.call_count == 3
    assert "client_secret=graph-secret" in token.calls.last.request.content.decode()
    assert send.calls.last.request.headers["Authorization"] == "Bearer tok-1"
    assert json.loads(send.calls.last.request.content) == {
        "message": {
            "subject": "Your code",
            "body": {"contentType": "HTML", "content": "<p>123456</p>"},
            "toRecipients": [{"emailAddress": {"address": "alice@example.com"}}],
            "replyTo": [{"emailAddress": {"address": "help@telemagic.app"}}],
        },
        "saveToSentItems": False,
    }


@respx.mock
def test_graph_cache_is_per_credentials(client):
    token = respx.post(TOKEN).respond(200, json={"access_token": "tok", "expires_in": 3600})
    respx.post(SENDMAIL).respond(202)
    client.post("/v1/email", json=GRAPH)
    other = {**GRAPH, "credentials": {**GRAPH["credentials"], "client_secret": "another"}}
    client.post("/v1/email", json=other)
    assert token.call_count == 2


@respx.mock
def test_graph_refreshes_a_rejected_token_once(client):
    token = respx.post(TOKEN)
    token.side_effect = [
        respx.MockResponse(200, json={"access_token": "old", "expires_in": 3600}),
        respx.MockResponse(200, json={"access_token": "new", "expires_in": 3600}),
    ]
    send = respx.post(SENDMAIL)
    send.side_effect = [respx.MockResponse(401), respx.MockResponse(202)]
    assert client.post("/v1/email", json=GRAPH).status_code == 200
    assert send.calls.last.request.headers["Authorization"] == "Bearer new"


@respx.mock
def test_graph_errors(client):
    respx.post(TOKEN).respond(401, json={"error": "invalid_client", "error_description": "AADSTS7000215: bad secret\nTrace"})
    r = client.post("/v1/email", json=GRAPH)
    assert r.status_code == 502 and r.json()["error"] == "provider_auth_failed"
    assert r.json()["detail"].endswith("invalid_client: AADSTS7000215: bad secret")

    respx.post(TOKEN).respond(200, json={"access_token": "t", "expires_in": 3600})
    respx.post(SENDMAIL).respond(403, json={"error": {"code": "ErrorAccessDenied", "message": "no"}})
    assert client.post("/v1/email", json=GRAPH).json()["error"] == "provider_auth_failed"
    respx.post(SENDMAIL).respond(429)
    assert client.post("/v1/email", json=GRAPH).json()["retryable"] is True
    respx.post(SENDMAIL).respond(400, json={"error": {"code": "ErrorInvalidRecipients", "message": "bad"}})
    assert client.post("/v1/email", json=GRAPH).json()["detail"].endswith("ErrorInvalidRecipients: bad")


def test_email_validation(client):
    for bad in (
        {**GRAPH, "to": ["nobody"]},
        {**GRAPH, "to": []},
        {**GRAPH, "subject": "Hi\r\nBcc: victim@example.com"},
        {**GRAPH, "html": None},
        {**GRAPH, "credentials": {**GRAPH["credentials"], "tenant_id": "../evil"}},
    ):
        assert client.post("/v1/email", json=bad).status_code == 422


# ---------------------------------------------------------------- SMTP

class _Inbox:
    def __init__(self):
        self.messages = []

    async def handle_DATA(self, server, session, envelope):
        if "refused@example.com" in envelope.rcpt_tos:
            return "550 no such user"
        self.messages.append((envelope.mail_from, list(envelope.rcpt_tos), envelope.content, session.authenticated))
        return "250 OK"

    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        if address.startswith("refused@"):
            return "550 no such user"
        envelope.rcpt_tos.append(address)
        return "250 OK"


def _auth(server, session, envelope, mechanism, auth_data):
    if isinstance(auth_data, LoginPassword) and auth_data.login == b"mailer" and auth_data.password == b"smtp-pw":
        return AuthResult(success=True)
    return AuthResult(success=False, handled=False)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def smtp_server():
    inbox = _Inbox()
    controller = Controller(inbox, hostname="127.0.0.1", port=_free_port(), authenticator=_auth,
                            auth_require_tls=False)
    controller.start()
    yield controller, inbox
    controller.stop()


def _smtp(port, **creds):
    return {
        "provider": "smtp",
        "credentials": {"host": "127.0.0.1", "port": port, "security": "none",
                        "username": "mailer", "password": "smtp-pw", **creds},
        "from": "TeleMagic <noreply@telemagic.app>",
        "to": ["alice@example.com", "bob@example.com"],
        "subject": "Your code",
        "text": "123456",
        "html": "<p>123456</p>",
    }


def test_smtp_plaintext_needs_opt_in(client, smtp_server):
    controller, inbox = smtp_server
    r = client.post("/v1/email", json=_smtp(controller.port))
    assert r.status_code == 403 and r.json()["error"] == "not_permitted"
    assert inbox.messages == []


def test_smtp_send(client, smtp_server, monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings, "allow_insecure_smtp", True)
    controller, inbox = smtp_server
    r = client.post("/v1/email", json={**_smtp(controller.port), "to": ["alice@example.com", "refused@example.com"]})
    assert r.status_code == 200, r.text
    assert r.json()["refused"] == ["refused@example.com"]
    assert r.json()["message_id"].endswith("@telemagic.app>")
    mail_from, rcpts, content, authed = inbox.messages[0]
    assert mail_from == "noreply@telemagic.app" and rcpts == ["alice@example.com"] and authed
    msg = message_from_bytes(content, policy=default_policy)
    assert msg["Subject"] == "Your code" and msg.get_content_type() == "multipart/alternative"
    assert msg.get_body(("plain",)).get_content().strip() == "123456"
    assert msg.get_body(("html",)).get_content().strip() == "<p>123456</p>"


def test_smtp_errors(client, smtp_server, monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings, "allow_insecure_smtp", True)
    controller, _ = smtp_server
    r = client.post("/v1/email", json=_smtp(controller.port, password="wrong"))
    assert r.status_code == 502 and r.json()["error"] == "provider_auth_failed"
    r = client.post("/v1/email", json={**_smtp(controller.port), "to": ["refused@example.com"]})
    assert r.json()["error"] == "provider_rejected"
    r = client.post("/v1/email", json=_smtp(_free_port()))
    assert r.status_code == 503 and r.json()["retryable"] is True


def test_smtp_starttls_is_required_not_opportunistic(client, smtp_server):
    controller, inbox = smtp_server  # this server offers no STARTTLS
    r = client.post("/v1/email", json=_smtp(controller.port, security="starttls"))
    assert r.status_code == 503 and inbox.messages == []


def test_smtp_host_must_be_allowed(client):
    r = client.post("/v1/email", json=_smtp(25, host="smtp.gmail.com", security="tls"))
    assert r.status_code == 403 and r.json()["error"] == "host_not_allowed"
    assert client.post("/v1/email", json=_smtp(25, password=None)).status_code == 422


@pytest.fixture
def tls_smtp_server(tmp_path):
    import ssl
    import subprocess
    key, cert = tmp_path / "key.pem", tmp_path / "cert.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                    "-nodes", "-keyout", key, "-out", cert, "-days", "1", "-subj", "/CN=127.0.0.1",
                    "-addext", "subjectAltName=IP:127.0.0.1"], check=True, capture_output=True)
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(cert, key)
    inbox = _Inbox()
    controller = Controller(inbox, hostname="127.0.0.1", port=_free_port(), authenticator=_auth,
                            ssl_context=context, auth_require_tls=False)
    controller.start()
    yield controller, inbox
    controller.stop()


def test_smtp_implicit_tls_checks_the_certificate(client, tls_smtp_server):
    controller, inbox = tls_smtp_server
    r = client.post("/v1/email", json=_smtp(controller.port, security="tls"))
    assert r.status_code == 502 and r.json()["retryable"] is False and inbox.messages == []
    assert "certificate failed verification" in r.json()["detail"]
    r = client.post("/v1/email", json=_smtp(controller.port, security="tls", verify_tls=False))
    assert r.status_code == 200, r.text
    assert len(inbox.messages) == 1 and inbox.messages[0][3]


def test_smtp_server_without_login(client, monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings, "allow_insecure_smtp", True)
    controller = Controller(_Inbox(), hostname="127.0.0.1", port=_free_port())  # no authenticator
    controller.start()
    try:
        r = client.post("/v1/email", json=_smtp(controller.port))
        assert r.status_code == 502 and r.json()["error"] == "provider_auth_failed"
    finally:
        controller.stop()
