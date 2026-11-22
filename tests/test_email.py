import json
import socket
from email import message_from_bytes
from email.policy import default as default_policy

import pytest
import respx
from aiosmtpd.controller import Controller
from aiosmtpd.smtp import AuthResult, LoginPassword

from app import vault

TOKEN = "https://login.microsoftonline.com/tenant-1/oauth2/v2.0/token"
SENDMAIL = "https://graph.microsoft.com/v1.0/users/noreply%40telemagic.app/sendMail"
EMAIL = {"config": "sv-email", "to": ["alice@example.com"], "subject": "Your code", "html": "<p>123456</p>"}


@respx.mock
def test_graph_send_logged_and_token_cached(h):
    token = respx.post(TOKEN).respond(200, json={"access_token": "tok-1", "expires_in": 3600})
    send = respx.post(SENDMAIL).respond(202)
    for _ in range(3):
        r = h.http.post("/v1/email", json={**EMAIL, "reply_to": "help@telemagic.app"})
        assert r.status_code == 200 and r.json()["provider"] == "graph", r.text
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
    rows = h.sql("SELECT kind, provider, sender, recipients, subject, body_html, status FROM messages")
    assert len(rows) == 3 and rows[0] == {
        "kind": "email", "provider": "graph", "sender": "noreply@telemagic.app",
        "recipients": ["alice@example.com"], "subject": "Your code", "body_html": "<p>123456</p>",
        "status": "accepted"}


@respx.mock
def test_sensitive_email_keeps_no_body(h):
    respx.post(TOKEN).respond(200, json={"access_token": "t", "expires_in": 3600})
    respx.post(SENDMAIL).respond(202)
    h.http.post("/v1/email", json={**EMAIL, "text": "123456", "sensitive": True})
    row = h.sql("SELECT body_text, body_html, body_mac, body_length FROM messages")[0]
    assert row["body_text"] is None and row["body_html"] is None
    assert bytes(row["body_mac"]) == vault.body_mac("Your code", "123456", "<p>123456</p>")
    assert row["body_length"] == len("Your code") + len("123456") + len("<p>123456</p>")


@respx.mock
def test_graph_refreshes_a_rejected_token_once(h):
    token = respx.post(TOKEN)
    token.side_effect = [
        respx.MockResponse(200, json={"access_token": "old", "expires_in": 3600}),
        respx.MockResponse(200, json={"access_token": "new", "expires_in": 3600}),
    ]
    send = respx.post(SENDMAIL)
    send.side_effect = [respx.MockResponse(401), respx.MockResponse(202)]
    assert h.http.post("/v1/email", json=EMAIL).status_code == 200
    assert send.calls.last.request.headers["Authorization"] == "Bearer new"


@respx.mock
def test_graph_errors(h):
    respx.post(TOKEN).respond(401, json={"error": "invalid_client", "error_description": "AADSTS7000215: bad secret\nTrace"})
    r = h.http.post("/v1/email", json=EMAIL)
    assert r.status_code == 502 and r.json()["error"] == "provider_auth_failed"
    assert r.json()["detail"].endswith("invalid_client: AADSTS7000215: bad secret")

    respx.post(TOKEN).respond(200, json={"access_token": "t", "expires_in": 3600})
    respx.post(SENDMAIL).respond(403, json={"error": {"code": "ErrorAccessDenied", "message": "no"}})
    assert h.http.post("/v1/email", json=EMAIL).json()["error"] == "provider_auth_failed"
    respx.post(SENDMAIL).respond(429)
    assert h.http.post("/v1/email", json=EMAIL).json()["retryable"] is True
    respx.post(SENDMAIL).respond(400, json={"error": {"code": "ErrorInvalidRecipients", "message": "bad"}})
    assert h.http.post("/v1/email", json=EMAIL).json()["detail"].endswith("ErrorInvalidRecipients: bad")
    assert {r["status"] for r in h.sql("SELECT status FROM messages")} == {"failed"}


def test_email_validation(h):
    for bad in (
        {**EMAIL, "to": ["nobody"]},
        {**EMAIL, "to": []},
        {**EMAIL, "subject": "Hi\r\nBcc: victim@example.com"},
        {**EMAIL, "html": None},
        {**EMAIL, "from": "spoof@example.com"},
    ):
        assert h.http.post("/v1/email", json=bad).status_code == 422


# ── SMTP, against real aiosmtpd servers ──────────────────────────────────────

class _Inbox:
    def __init__(self):
        self.messages = []

    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        if address.startswith("refused@"):
            return "550 no such user"
        envelope.rcpt_tos.append(address)
        return "250 OK"

    async def handle_DATA(self, server, session, envelope):
        self.messages.append((envelope.mail_from, list(envelope.rcpt_tos), envelope.content, session.authenticated))
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


def _smtp_cfg(port, **overrides):
    return {"provider": "smtp", "host": "127.0.0.1", "port": port, "security": "none",
            "username": "mailer", "password": "smtp-pw", "from": "TeleMagic <noreply@telemagic.app>", **overrides}


MAIL = {"config": "smtp", "to": ["alice@example.com"], "subject": "Your code", "text": "123456",
        "html": "<p>123456</p>"}


def test_smtp_plaintext_needs_opt_in(h, smtp_server):
    controller, inbox = smtp_server
    h.set_config("sv", "smtp", _smtp_cfg(controller.port))
    r = h.http.post("/v1/email", json=MAIL)
    assert r.status_code == 403 and r.json()["error"] == "not_permitted" and inbox.messages == []


def test_smtp_send(h, smtp_server, monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings, "allow_insecure_smtp", True)
    controller, inbox = smtp_server
    h.set_config("sv", "smtp", _smtp_cfg(controller.port, reply_to="help@telemagic.app"))
    r = h.http.post("/v1/email", json={**MAIL, "to": ["alice@example.com", "refused@example.com"]})
    assert r.status_code == 200, r.text
    assert r.json()["refused"] == ["refused@example.com"]
    assert r.json()["provider_message_id"].endswith("@telemagic.app>")
    mail_from, rcpts, content, authed = inbox.messages[0]
    assert mail_from == "noreply@telemagic.app" and rcpts == ["alice@example.com"] and authed
    msg = message_from_bytes(content, policy=default_policy)
    assert msg["Subject"] == "Your code" and msg["Reply-To"] == "help@telemagic.app"
    assert msg.get_content_type() == "multipart/alternative"
    assert msg.get_body(("plain",)).get_content().strip() == "123456"
    row = h.sql("SELECT sender, refused FROM messages")[0]
    assert row == {"sender": "TeleMagic <noreply@telemagic.app>", "refused": ["refused@example.com"]}


def test_smtp_errors(h, smtp_server, monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings, "allow_insecure_smtp", True)
    controller, _ = smtp_server
    h.set_config("sv", "smtp", _smtp_cfg(controller.port, password="wrong"))
    assert h.http.post("/v1/email", json=MAIL).json()["error"] == "provider_auth_failed"
    h.set_config("sv", "smtp", _smtp_cfg(controller.port))
    assert h.http.post("/v1/email", json={**MAIL, "to": ["refused@example.com"]}).json()["error"] == "provider_rejected"
    h.set_config("sv", "smtp", _smtp_cfg(_free_port()))
    r = h.http.post("/v1/email", json=MAIL)
    assert r.status_code == 503 and r.json()["retryable"] is True


def test_smtp_starttls_is_required_not_opportunistic(h, smtp_server):
    controller, inbox = smtp_server  # this server offers no STARTTLS
    h.set_config("sv", "smtp", _smtp_cfg(controller.port, security="starttls"))
    assert h.http.post("/v1/email", json=MAIL).status_code == 503 and inbox.messages == []


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


def test_smtp_implicit_tls_checks_the_certificate(h, tls_smtp_server):
    controller, inbox = tls_smtp_server
    h.set_config("sv", "smtp", _smtp_cfg(controller.port, security="tls"))
    r = h.http.post("/v1/email", json=MAIL)
    assert r.status_code == 502 and r.json()["retryable"] is False and inbox.messages == []
    assert "certificate failed verification" in r.json()["detail"]
    h.set_config("sv", "smtp", _smtp_cfg(controller.port, security="tls", verify_tls=False))
    assert h.http.post("/v1/email", json=MAIL).status_code == 200
    assert len(inbox.messages) == 1 and inbox.messages[0][3]


def test_smtp_server_without_login(h, monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings, "allow_insecure_smtp", True)
    controller = Controller(_Inbox(), hostname="127.0.0.1", port=_free_port())  # no authenticator
    controller.start()
    try:
        h.set_config("sv", "smtp", _smtp_cfg(controller.port))
        r = h.http.post("/v1/email", json=MAIL)
        assert r.status_code == 502 and r.json()["error"] == "provider_auth_failed"
    finally:
        controller.stop()


def test_purge_removes_old_messages(h):
    from app import db
    h.sql("""INSERT INTO messages (id, client_id, config_name, kind, provider, sender, recipients, body_length,
                                   status, created_at)
             VALUES (gen_random_uuid(), 'sv', 'sv-email', 'email', 'graph', 'a@b.co', ARRAY['c@d.co'], 1,
                     'accepted', now() - interval '400 days'),
                    (gen_random_uuid(), 'sv', 'sv-email', 'email', 'graph', 'a@b.co', ARRAY['c@d.co'], 1,
                     'accepted', now() - interval '10 days')""")
    assert h.call(db.purge, 365) == 1
    assert h.sql("SELECT COUNT(*) AS n FROM messages")[0]["n"] == 1
