# notify-service

One internal service that sends texts and emails for any TeleMagic or
SecureVoice service. It **keeps no provider credentials**: each request names
a provider and carries that provider's credentials, and the service sends the
message and answers with the provider's message id or the reason it failed.
It has no database, no templates and no queue. Wording, codes, retries and
delivery records stay with the caller.

The sending code is pulled out of TeleMagic's existing services:

| Provider | Kind | From |
|---|---|---|
| `jasmin` | SMS | tm-messaging `messaging/app/services/jasmin.py` (Jasmin HTTP API, UCS-2 as hex-content) |
| `inteliquent` | SMS/MMS | tm-messaging `mms-server/src/server.js` `publishMessage` (Message Broker) |
| `graph` | Email | otp-service `app/graph_mail.py` (Microsoft Graph client credentials + sendMail) |
| `smtp` | Email | telemagic-utils `com.pti.utils.EmailSender` (jakarta.mail) |

## API

Every call except `/healthz` needs `Authorization: Bearer <key>`, where the key is one of `API_KEYS`.

### `POST /v1/sms`

```json
{
  "provider": "jasmin",
  "credentials": {"base_url": "http://jasmin:1401", "username": "...", "password": "..."},
  "from": "16606009000",
  "to": "+15551234567",
  "body": "Your SecureVoice code is 123456",
  "route": "inteliquent",
  "dlr_url": "http://messaging:8000/api/v1/webhooks/jasmin/dlr",
  "dlr_level": 2
}
```

`route`, `dlr_url` and `dlr_level` are optional. When there's no `dlr_url`, no delivery receipt is requested.

```json
{
  "provider": "inteliquent",
  "credentials": {"token": "..."},
  "from": "+16606009000",
  "to": "+15551234567",
  "body": "hello",
  "media_urls": ["https://.../image.png"]
}
```

`credentials.base_url` optionally overrides the Message Broker URL. Either `body` or `media_urls` is required.

### `POST /v1/email`

```json
{
  "provider": "graph",
  "credentials": {"tenant_id": "...", "client_id": "...", "client_secret": "...", "sender": "noreply@telemagic.app"},
  "to": ["alice@example.com"],
  "subject": "Your verification code",
  "html": "<p>Your code is <b>123456</b></p>",
  "text": "Your code is 123456",
  "reply_to": "support@telemagic.app"
}
```

```json
{
  "provider": "smtp",
  "credentials": {"host": "smtp.office365.com", "port": 587, "username": "...", "password": "...",
                  "security": "starttls", "verify_tls": true},
  "from": "SecureVoice <noreply@pqtutela.telemagic.app>",
  "to": ["alice@example.com"],
  "subject": "Your verification code",
  "text": "Your code is 123456"
}
```

Email needs `html`, `text` or both. Graph sends one body, the HTML one when both are given. SMTP sends both as multipart/alternative.

SMTP `security` defaults to `tls` on port 465 and `starttls` on every other port. STARTTLS is required: a server that doesn't offer it fails the send instead of receiving the password in the clear. `none` is refused unless `ALLOW_INSECURE_SMTP=true`. `verify_tls: false` skips certificate checks, which matches EmailSender's `trust_host`.

### Responses

Success (200):

```json
{"status": "accepted", "provider": "jasmin", "message_id": "86d69a0b-...", "refused": []}
```

- `message_id`: Jasmin's message id, Inteliquent's referenceId, or the SMTP Message-ID. Graph returns none.
- `refused`: SMTP recipients the server turned away while it accepted the others.

Failure:

```json
{"error": "provider_rejected", "detail": "Jasmin rejected the message: No route found", "retryable": false}
```

| Status | `error` | Meaning |
|---|---|---|
| 401 | `unauthorized` | Missing or unknown API key |
| 403 | `host_not_allowed` | `base_url` or SMTP host isn't in `EGRESS_ALLOWED_HOSTS` |
| 403 | `not_permitted` | Plaintext SMTP while it's turned off |
| 422 | `invalid_request` | Bad body. Field errors never echo what was sent. |
| 502 | `provider_auth_failed` | The provider refused the credentials |
| 502 | `provider_rejected` | The provider refused the message |
| 503 | `provider_unavailable` | Unreachable, timed out, 5xx or throttled (`retryable: true`) |
| 503 | `not_configured` | `API_KEYS` is empty |

## Security

- **Credentials travel with each request.** Run the service on the private network only. The compose file binds it to 127.0.0.1 by default. Callers send credentials over that network. Credentials are held in memory for the length of the request. Microsoft Graph access tokens are cached under a hash of their credentials until shortly before they expire.
- **Egress allow-list.** Some requests name their own endpoint: a Jasmin URL, an Inteliquent override or an SMTP host. Those can only reach hosts in `EGRESS_ALLOWED_HOSTS`. Without the list, any caller could turn the service into a proxy into the internal network. HTTP redirects are never followed.
- **Nothing sensitive is logged.** That covers credentials, message bodies (which often hold one-time codes) and full recipients. A log line has a request id, the kind, the provider, a masked recipient (`***4567`, `a***@example.com`), the outcome and the time taken. httpx's own request logging is turned off because Jasmin's URL carries its password, and uvicorn's access log is off.
- **One API key per calling service**, so each caller can be revoked on its own.

## Configuration

See `.env.example`: `API_KEYS`, `EGRESS_ALLOWED_HOSTS`, `ALLOW_INSECURE_SMTP`, `PROVIDER_TIMEOUT_S`, `LOG_LEVEL`.

## Run and test

Callers on the same host reach the service in either of two ways:

- **Containers** join the `notify` Docker network and use `http://notify-service:8000`. SecureVoice's relay does this through pqtutela's `docker-compose.notify.yml`.
- **Host processes** use `http://127.0.0.1:8010`.

```bash
cp .env.example .env                    # set API_KEYS and EGRESS_ALLOWED_HOSTS
docker compose up -d --build            # the image build runs the tests first
```

Locally:

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
.venv/bin/python -m pytest
```

The tests mock Jasmin, Inteliquent and Graph with respx. They run real SMTP against aiosmtpd servers, covering plaintext, implicit TLS with certificate checks, missing STARTTLS, a server with no login and refused recipients.
