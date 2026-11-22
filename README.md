# notify-service

One internal service that sends texts and emails for every TeleMagic or SecureVoice service, and keeps **one log of everything sent**.

Clients, their API keys and their provider configs (credentials and sender numbers or addresses) live in notify-service's own Postgres. A caller authenticates with its key, names one of its configs, and gets back the message's id. Every send is logged with the client that made it, and Jasmin delivery receipts are recorded on the same row. Callers don't handle provider credentials and don't write their own logs.

The sending code comes from TeleMagic's existing services:

| Provider | Kind | From |
|---|---|---|
| `jasmin` | SMS | tm-messaging `messaging/app/services/jasmin.py`, plus its DLR handling (`routers/dlr_http.py`, `services/dlr_status.py`) |
| `inteliquent` | SMS/MMS | tm-messaging `mms-server/src/server.js` `publishMessage` (Message Broker) |
| `graph` | Email | otp-service `app/graph_mail.py` (Microsoft Graph) |
| `smtp` | Email | telemagic-utils `com.pti.utils.EmailSender` |

## Setting up a client

```bash
docker compose exec notify-service python -m app.admin client add securevoice --description "SecureVoice relay"
docker compose exec notify-service python -m app.admin key create securevoice --label relay
#  -> prints the key once (nsk_...). Put it in the client's secrets.

docker compose exec -T notify-service python -m app.admin config set securevoice securevoice-sms <<'JSON'
{"provider": "jasmin", "base_url": "http://jasmin:1401", "username": "...", "password": "...",
 "from_numbers": ["16606009000"], "route": "inteliquent"}
JSON

docker compose exec -T notify-service python -m app.admin config set securevoice securevoice-email <<'JSON'
{"provider": "graph", "tenant_id": "...", "client_id": "...", "client_secret": "...",
 "sender": "noreply@pqtutela.telemagic.app"}
JSON
```

Configs are read from stdin, so secrets never appear in shell history or `ps`. They're validated, then encrypted (AES-256-GCM, bound to the client and config name) before they're stored. `config list` shows them with secrets masked. `config set` on an existing name replaces it.

Other admin commands:

- `client list`, `client disable|enable`
- `key list`, `key revoke <key-id>`. A client can hold several keys, for rotation.
- `config disable|enable`
- `messages <client>`

The provider config fields:

| Provider | Fields |
|---|---|
| `jasmin` | `base_url`, `username`, `password`, `from_numbers`, `route`?, `dlr_level` (2 = carrier's final status, the default; 3 = also SMSC acks) |
| `inteliquent` | `token`, `from_numbers`, `base_url`? |
| `graph` | `tenant_id`, `client_id`, `client_secret`, `sender`, `reply_to`? |
| `smtp` | `host`, `port` (587), `username`?, `password`?, `security` (`tls` on 465, `starttls` otherwise; `none` needs `ALLOW_INSECURE_SMTP`), `verify_tls` (true), `from`, `reply_to`? |

## API

Every call except `/healthz` and the receipt route needs `Authorization: Bearer <key>`.

### `POST /v1/sms`

```json
{"config": "securevoice-sms", "to": "+15551234567", "body": "Your code is 123456",
 "sensitive": true, "reference": "signup-abc"}
```

- **`from`**: optional, and must be one of the config's `from_numbers`. Without it, one is picked at random.
- **`media_urls`**: optional, for MMS. Needs an Inteliquent config.
- **`sensitive`**: the body isn't kept (see below).
- **`reference`**: your own id, for lookups.

### `POST /v1/email`

```json
{"config": "securevoice-email", "to": ["alice@example.com"], "subject": "Your code",
 "html": "<p>Your code is <b>123456</b></p>", "text": "Your code is 123456", "sensitive": true}
```

The sender comes from the config. Callers can't set `from`.

### Responses

```json
{"id": "6f0c...", "status": "accepted", "provider": "jasmin", "provider_message_id": "86d69a0b-...", "refused": []}
```

Failures look like `{"error", "detail", "retryable"}`. The message is logged as `failed` with the same error.

| Status | `error` | Meaning |
|---|---|---|
| 401 | `unauthorized` | Missing, unknown or revoked key, or the client is disabled |
| 400 | `bad_config` | No such active config for this client, the wrong kind, a `from` outside the pool, or a config that can't be decrypted |
| 403 | `not_permitted` | Plaintext SMTP while it's turned off |
| 422 | `invalid_request` | Bad body. Field errors never echo what was sent. |
| 502 | `provider_auth_failed` / `provider_rejected` | The provider refused the credentials or the message |
| 503 | `provider_unavailable` | Unreachable, timed out, 5xx or throttled (`retryable: true`) |

### The log

- **`GET /v1/messages/{id}`**: one of your messages, with its status, the provider's id, any error, and `dlr_status`, `dlr_error` and `dlr_at`.
- **`GET /v1/messages?reference=…&to=…&before=…&limit=…`**: your messages, newest first.

A client only ever sees its own messages.

Every send gets a row in `messages`. It holds the client, config, provider, sender, recipients, subject, body, length, reference, status, the provider's message id, errors, SMTP recipients that were refused, and the delivery receipt. Rows are deleted after `MESSAGE_RETENTION_DAYS` (365 by default).

**Sensitive messages** (one-time codes, magic links) keep no subject or body text. They keep only the length and an HMAC keyed by `CONFIG_ENCRYPTION_KEY`, which can confirm "was this the text?" without revealing it. A plain hash of a 6-digit code would give the code away.

### Delivery receipts (Jasmin)

With `DLR_BASE_URL` set, each Jasmin send asks for a receipt at `DLR_BASE_URL/dlr/jasmin/<message id>/<token>`:

- **The token** is an HMAC of the message id, because Jasmin can't authenticate, so receipts can't be forged.
- **Statuses** are mapped as messaging maps them: `DELIVRD` → `delivered`, `UNDELIV` → `undeliverable`, `REJECTD`, `EXPIRED`, `FAILED` and `UNKNOWN`.
- **Storage**: the raw receipt is stored without its `text` field, which echoes the start of the message, often the code itself.
- **Reply**: the route answers `ACK/Jasmin`.

Jasmin must be able to reach `DLR_BASE_URL`, so bind the port (`NOTIFY_BIND`) to an address it can route to. Inteliquent and email record submission only.

## Security

- **Only clients configured by an admin can send**, and each client can use only its own configs. Keys are random (`nsk_` + 256 bits), and only their SHA-256 is stored.
- **Provider credentials stay encrypted at rest**, and only notify-service and its admin CLI can read them. Back up `CONFIG_ENCRYPTION_KEY`: without it, every stored config has to be set again.
- **Nothing sensitive is logged.** The service's own log lines carry the message id, client/config, provider, a masked recipient (`***4567`), the outcome and the time taken. They never carry bodies or credentials. httpx's request logging and uvicorn's access log are off: Jasmin's URL carries its password, and receipt URLs carry tokens.
- **HTTP redirects are never followed.**

## Configuration

See `.env.example`: `NOTIFY_DB_PASSWORD`, `CONFIG_ENCRYPTION_KEY`, `DLR_BASE_URL`, `NOTIFY_BIND`/`NOTIFY_PORT`, `MESSAGE_RETENTION_DAYS`, `ALLOW_INSECURE_SMTP`, `PROVIDER_TIMEOUT_S`, `LOG_LEVEL`.

## Run and test

```bash
cp .env.example .env                    # set NOTIFY_DB_PASSWORD, CONFIG_ENCRYPTION_KEY, DLR_BASE_URL
docker compose up -d --build            # the image build runs the tests against a throwaway Postgres
```

Callers on the same host reach the service in either of two ways:

- **Containers** join the `notify` Docker network and use `http://notify-service:8000`. SecureVoice's relay does this through pqtutela's `docker-compose.notify.yml`.
- **Host processes** use `http://127.0.0.1:8010`.

The tests run against real Postgres: `TEST_DATABASE_URL`, or a throwaway cluster from a local `initdb`. They mock Jasmin, Inteliquent and Graph with respx, and run real SMTP against aiosmtpd. `docker build --target test .` runs them.
