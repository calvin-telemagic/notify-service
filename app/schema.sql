-- notify-service's own database. Applied (idempotently) at every start.

CREATE TABLE IF NOT EXISTS clients (
    id          TEXT        PRIMARY KEY CHECK (id ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
    description TEXT        NOT NULL DEFAULT '',
    active      BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- A client may hold several keys (rotation); only a SHA-256 of each is kept.
CREATE TABLE IF NOT EXISTS api_keys (
    id           UUID        PRIMARY KEY,
    client_id    TEXT        NOT NULL REFERENCES clients (id),
    key_hash     BYTEA       NOT NULL UNIQUE,
    label        TEXT        NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ,
    revoked_at   TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS api_keys_client_idx ON api_keys (client_id);

-- A client's named provider setups ("securevoice-sms"). settings is the
-- provider's JSON (credentials, sender numbers / address), AES-256-GCM
-- encrypted with CONFIG_ENCRYPTION_KEY (app/vault.py).
CREATE TABLE IF NOT EXISTS provider_configs (
    client_id  TEXT        NOT NULL REFERENCES clients (id),
    name       TEXT        NOT NULL CHECK (name ~ '^[a-z0-9][a-z0-9_-]{0,62}$'),
    kind       TEXT        NOT NULL CHECK (kind IN ('sms', 'email')),
    provider   TEXT        NOT NULL CHECK (provider IN ('jasmin', 'inteliquent', 'graph', 'smtp')),
    settings   BYTEA       NOT NULL,
    active     BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (client_id, name)
);

-- Every send: who asked, through which config, to whom, what (unless
-- sensitive), what the provider said, and -- for Jasmin -- the delivery
-- receipt.
CREATE TABLE IF NOT EXISTS messages (
    id                  UUID        PRIMARY KEY,
    client_id           TEXT        NOT NULL REFERENCES clients (id),
    config_name         TEXT        NOT NULL,
    kind                TEXT        NOT NULL CHECK (kind IN ('sms', 'email')),
    provider            TEXT        NOT NULL,
    sender              TEXT        NOT NULL,
    recipients          TEXT[]      NOT NULL,
    subject             TEXT,
    body_text           TEXT,       -- NULL when sensitive
    body_html           TEXT,       -- NULL when sensitive
    media_urls          TEXT[],
    body_length         INT         NOT NULL,
    body_mac            BYTEA,      -- sensitive only: vault.body_mac(subject, text, html)
    sensitive           BOOLEAN     NOT NULL DEFAULT FALSE,
    reference           TEXT,       -- the caller's own id for the message
    status              TEXT        NOT NULL CHECK (status IN ('sending', 'accepted', 'failed')),
    provider_message_id TEXT,
    error               TEXT,
    error_detail        TEXT,
    refused             TEXT[],
    dlr_status          TEXT,
    dlr_error           TEXT,
    dlr_raw             JSONB,
    dlr_at              TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS messages_client_time_idx ON messages (client_id, created_at DESC);
CREATE INDEX IF NOT EXISTS messages_client_reference_idx ON messages (client_id, reference) WHERE reference IS NOT NULL;
CREATE INDEX IF NOT EXISTS messages_recipients_idx ON messages USING GIN (recipients);
CREATE INDEX IF NOT EXISTS messages_created_idx ON messages (created_at);
