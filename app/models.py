"""
Request/response bodies, and the provider configs stored per client.

Callers no longer send credentials: a request names one of its client's
configs ("securevoice-sms"), and the config -- kept encrypted in the
database, managed with app/admin.py -- holds the provider, its credentials
and the sender(s).
"""

import re
import uuid
from datetime import datetime
from typing import Annotated, Literal, Union

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, SecretStr, TypeAdapter, field_validator, model_validator

PHONE = r"^\+?[1-9]\d{6,14}$"
CONFIG_NAME = r"^[a-z0-9][a-z0-9_-]{0,62}$"
_EMAIL = re.compile(r"^[^@\s<>,;\"]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$")
_HOST = re.compile(r"^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$|^\[?[0-9A-Fa-f:.]+\]?$")

MAX_SMS_CHARS = 1600
MAX_EMAIL_BODY_CHARS = 1_000_000
MAX_EMAIL_RECIPIENTS = 50


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


def _email(value: str) -> str:
    if len(value) > 254 or not _EMAIL.match(value):
        raise ValueError("not an email address")
    return value


def _one_line(value: str) -> str:
    if "\r" in value or "\n" in value:
        raise ValueError("must be a single line")
    return value


def _http_url(value: str) -> str:
    if not re.match(r"^https?://[^/\s@]+(/\S*)?$", value):
        raise ValueError("must be an http(s) URL without credentials")
    return value


def mailbox(value: str) -> str:
    """An address, or "Name <address>"."""
    _one_line(value)
    match = re.match(r"^(.*)<([^<>]+)>$", value)
    _email(match.group(2).strip() if match else value)
    return value


Email = Annotated[str, AfterValidator(_email)]
Mailbox = Annotated[str, AfterValidator(mailbox)]
HttpUrl = Annotated[str, AfterValidator(_http_url)]
OneLine = Annotated[str, AfterValidator(_one_line)]


# ── stored provider configs ──────────────────────────────────────────────────

_Numbers = Annotated[list[Annotated[str, Field(pattern=PHONE)]], Field(min_length=1, max_length=100)]


class JasminConfig(_Strict):
    provider: Literal["jasmin"]
    base_url: HttpUrl = Field(max_length=512, description="Jasmin's HTTP API, e.g. http://jasmin:1401")
    username: SecretStr
    password: SecretStr
    from_numbers: _Numbers
    dlr_level: Literal[2, 3] = 2


class InteliquentConfig(_Strict):
    provider: Literal["inteliquent"]
    token: SecretStr
    base_url: HttpUrl = Field(default="https://messagebroker.inteliquent.com/msgbroker/rest/", max_length=512)
    from_numbers: _Numbers


class GraphConfig(_Strict):
    provider: Literal["graph"]
    tenant_id: str = Field(pattern=r"^[A-Za-z0-9.-]{1,128}$")
    client_id: str = Field(pattern=r"^[A-Za-z0-9-]{1,128}$")
    client_secret: SecretStr
    sender: Email = Field(description="The mailbox Graph sends as")
    reply_to: Email | None = None


class SmtpConfig(_Strict):
    provider: Literal["smtp"]
    host: str = Field(max_length=253)
    port: int = Field(default=587, ge=1, le=65535)
    username: str | None = Field(default=None, max_length=320)
    password: SecretStr | None = None
    security: Literal["starttls", "tls", "none"] | None = None   # default: tls on 465, starttls otherwise
    verify_tls: bool = True
    from_: Mailbox = Field(alias="from", max_length=400, description='Address, or "Name <address>"')
    reply_to: Email | None = None

    @field_validator("host")
    @classmethod
    def _host(cls, v: str) -> str:
        if not _HOST.match(v):
            raise ValueError("not a host name")
        return v

    @model_validator(mode="after")
    def _login_pair(self):
        if (self.username is None) != (self.password is None):
            raise ValueError("username and password go together")
        return self

    @property
    def effective_security(self) -> str:
        return self.security or ("tls" if self.port == 465 else "starttls")


SmsConfig = Annotated[Union[JasminConfig, InteliquentConfig], Field(discriminator="provider")]
EmailConfig = Annotated[Union[GraphConfig, SmtpConfig], Field(discriminator="provider")]
ProviderConfig = Annotated[Union[JasminConfig, InteliquentConfig, GraphConfig, SmtpConfig],
                           Field(discriminator="provider")]
provider_config = TypeAdapter(ProviderConfig)
KIND = {"jasmin": "sms", "inteliquent": "sms", "graph": "email", "smtp": "email"}
SECRET_FIELDS = {"username", "password", "token", "client_secret"}


def config_json(cfg) -> dict:
    """A config as it's stored: secrets in the clear (it's encrypted as a whole)."""
    data = cfg.model_dump(by_alias=True, exclude_none=True)
    for key, value in data.items():
        if isinstance(value, SecretStr):
            data[key] = value.get_secret_value()
    return data


# ── requests ─────────────────────────────────────────────────────────────────

class _SendBase(_Strict):
    config: str = Field(pattern=CONFIG_NAME, description="One of this client's configs")
    sensitive: bool = Field(default=False, description="Don't keep the body (one-time codes, links)")
    reference: str | None = Field(default=None, max_length=200, description="The caller's own id, for lookups")


class SmsRequest(_SendBase):
    to: str = Field(pattern=PHONE)
    from_: str | None = Field(default=None, alias="from", pattern=PHONE,
                              description="One of the config's from_numbers; default: one at random")
    body: str | None = Field(default=None, min_length=1, max_length=MAX_SMS_CHARS)
    media_urls: list[Annotated[str, Field(max_length=2048)]] = Field(default_factory=list, max_length=10,
                                                                    description="Inteliquent only (MMS)")

    @model_validator(mode="after")
    def _has_content(self):
        if not self.body and not self.media_urls:
            raise ValueError("body or media_urls is required")
        return self


class EmailRequest(_SendBase):
    to: list[Email] = Field(min_length=1, max_length=MAX_EMAIL_RECIPIENTS)
    subject: OneLine = Field(min_length=1, max_length=998)
    html: str | None = Field(default=None, max_length=MAX_EMAIL_BODY_CHARS)
    text: str | None = Field(default=None, max_length=MAX_EMAIL_BODY_CHARS)
    reply_to: Email | None = None

    @model_validator(mode="after")
    def _has_body(self):
        if not self.html and not self.text:
            raise ValueError("html or text is required")
        return self


# ── responses ────────────────────────────────────────────────────────────────

class Accepted(BaseModel):
    id: uuid.UUID = Field(description="notify-service's id for the message (GET /v1/messages/{id})")
    status: Literal["accepted"] = "accepted"
    provider: str
    provider_message_id: str | None = Field(description="The provider's reference, when it gives one")
    refused: list[str] = Field(default_factory=list, description="SMTP: recipients refused while the rest were taken")


class Message(BaseModel):
    id: uuid.UUID
    config_name: str
    kind: str
    provider: str
    sender: str
    recipients: list[str]
    subject: str | None
    body_text: str | None
    body_html: str | None
    media_urls: list[str] | None
    body_length: int
    sensitive: bool
    reference: str | None
    status: str
    provider_message_id: str | None
    error: str | None
    error_detail: str | None
    refused: list[str] | None
    dlr_status: str | None
    dlr_error: str | None
    dlr_at: datetime | None
    created_at: datetime
    updated_at: datetime
