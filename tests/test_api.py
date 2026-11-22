import logging

import respx

from app import admin
from app.main import mask

SMS = {"config": "sv-sms", "to": "+15551234567", "body": "Your code is 123456"}
SEND = "http://jasmin.internal:1401/send"


def test_needs_a_live_key(h):
    for header in ("", "Bearer", "Basic " + h.key, "Bearer wrong"):
        r = h.http.post("/v1/sms", json=SMS, headers={"Authorization": header})
        assert r.status_code == 401, header
    assert h.http.post("/v1/sms", json={}, headers={"Authorization": "Bearer nope"}).status_code == 401


@respx.mock
def test_revoked_keys_and_disabled_clients(h):
    respx.get(SEND).respond(200, text='Success "x"')
    key_id, key = h.call(admin.key_create, "sv", "second")
    assert h.http.post("/v1/sms", json=SMS, headers=h.as_client(key)).status_code == 200
    h.call(admin.key_revoke, str(key_id))
    assert h.http.post("/v1/sms", json=SMS, headers=h.as_client(key)).status_code == 401
    assert h.http.post("/v1/sms", json=SMS).status_code == 200      # the other key still works
    h.call(admin.client_set_active, "sv", False)
    assert h.http.post("/v1/sms", json=SMS).status_code == 401
    assert h.sql("SELECT last_used_at FROM api_keys WHERE id = $1", key_id)[0]["last_used_at"] is not None


def test_configs_belong_to_their_client(h):
    other = h.add_client("other")
    r = h.http.post("/v1/sms", json=SMS, headers=h.as_client(other))
    assert r.status_code == 400 and r.json()["error"] == "bad_config"
    assert h.http.post("/v1/sms", json={**SMS, "config": "sv-email"}).json()["detail"] == \
        "Config 'sv-email' is for email, not sms"
    h.call(admin.config_set_active, "sv", "sv-sms", False)
    assert h.http.post("/v1/sms", json=SMS).json()["error"] == "bad_config"
    assert h.sql("SELECT COUNT(*) AS n FROM messages")[0]["n"] == 0


def test_a_config_copied_onto_another_name_wont_decrypt(h):
    h.sql("""UPDATE provider_configs SET settings = (SELECT settings FROM provider_configs WHERE name = 'sv-mms')
              WHERE name = 'sv-sms'""")
    r = h.http.post("/v1/sms", json=SMS)
    assert r.status_code == 400 and "can't be read" in r.json()["detail"]


def test_validation_errors_never_echo_input(h):
    r = h.http.post("/v1/sms", json={**SMS, "to": "not-a-number", "password": "s3cret-pw"})
    assert r.status_code == 422 and "s3cret-pw" not in r.text and "not-a-number" not in r.text


def test_callers_cant_send_credentials_any_more(h):
    r = h.http.post("/v1/sms", json={**SMS, "credentials": {"base_url": "http://x"}})
    assert r.status_code == 422


def test_healthz_is_open(h):
    assert h.http.get("/healthz", headers={"Authorization": ""}).json() == {"status": "ok"}


def test_mask():
    assert mask("+15551234567") == "***4567"
    assert mask("alice@example.com") == "a***@example.com"


@respx.mock
def test_logs_carry_no_secrets_or_bodies(h, caplog):
    respx.get(SEND).respond(200, text='Success "abc"')
    with caplog.at_level(logging.DEBUG):
        assert h.http.post("/v1/sms", json=SMS).status_code == 200
    assert "s3cret-pw" not in caplog.text and "123456" not in caplog.text and "5551234567" not in caplog.text
    assert "***4567" in caplog.text and "sv/sv-sms" in caplog.text


def test_admin_config_errors_name_fields_not_values(h):
    import pytest
    with pytest.raises(admin.AdminError) as exc:
        h.call(admin.config_set, "sv", "bad", {"provider": "jasmin", "base_url": "ftp://x", "username": "u",
                                               "password": "hunter2", "from_numbers": ["12"]})
    assert "hunter2" not in str(exc.value) and "base_url" in str(exc.value) and "from_numbers" in str(exc.value)


def test_admin_config_list_masks_secrets(h):
    listed = {c["name"]: c for c in h.call(admin.config_list, "sv")}
    assert listed["sv-sms"]["settings"]["password"] == "****"
    assert listed["sv-sms"]["settings"]["username"] == "****"
    assert listed["sv-sms"]["settings"]["base_url"] == "http://jasmin.internal:1401"
    assert listed["sv-email"]["settings"]["client_secret"] == "****"
    raw = h.sql("SELECT settings FROM provider_configs WHERE name = 'sv-sms'")[0]["settings"]
    assert b"s3cret-pw" not in raw and b"jasmin.internal" not in raw


def test_admin_cli_reads_config_from_stdin(h, database_url):
    import json
    import os
    import subprocess
    import sys
    from tests.conftest import KEY
    env = {**os.environ, "DATABASE_URL": database_url, "CONFIG_ENCRYPTION_KEY": KEY}
    cfg = {"provider": "inteliquent", "token": "t0ken", "from_numbers": ["+16606009001"]}
    run = subprocess.run([sys.executable, "-m", "app.admin", "config", "set", "sv", "cli-sms"],
                         input=json.dumps(cfg), env=env, capture_output=True, text=True, timeout=60)
    assert run.returncode == 0, run.stderr
    assert "set sv/cli-sms (inteliquent)" in run.stdout
    run = subprocess.run([sys.executable, "-m", "app.admin", "key", "create", "sv", "--label", "cli"],
                         env=env, capture_output=True, text=True, timeout=60)
    key = next(line.strip() for line in run.stdout.splitlines() if line.strip().startswith("nsk_"))
    assert h.http.get("/v1/messages", headers=h.as_client(key)).status_code == 200
    run = subprocess.run([sys.executable, "-m", "app.admin", "config", "list", "sv"],
                         env=env, capture_output=True, text=True, timeout=60)
    assert "t0ken" not in run.stdout and "cli-sms" in run.stdout


def test_jasmin_configs_take_no_route(h):
    import pytest
    from tests.conftest import JASMIN_CFG
    with pytest.raises(admin.AdminError) as exc:
        h.call(admin.config_set, "sv", "routed", {**JASMIN_CFG, "route": "inteliquent"})
    assert "route" in str(exc.value)
