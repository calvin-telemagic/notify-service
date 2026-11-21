"""
Request and response bodies. Every request names its provider and carries
that provider's credentials; secrets are SecretStr so they never show up in
a repr, a log line, or a validation error.
"""

import re
from typing import Annotated, Literal, Union

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator

# E.164 digits, with or without the leading "+".
PHONE = r"^\+?[1-9]\d{6,14}$"
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


# ---------------------------------------------------------------- SMS

class JasminCredentials(_Strict):
    base_url: str = Field(description="Jasmin's HTTP API, e.g. http://jasmin:1401", max_length=512)
    username: SecretStr
    password: SecretStr


class InteliquentCredentials(_Strict):
    token: SecretStr = Field(description="Message Broker bearer token")
    base_url: str = Field(default="https://messagebroker.inteliquent.com/msgbroker/rest/", max_length=512)


class _SmsBase(_Strict):
    from_: str = Field(alias="from", pattern=PHONE)
    to: str = Field(pattern=PHONE)


class JasminSms(_SmsBase):
    provider: Literal["jasmin"]
    credentials: JasminCredentials
    body: str = Field(min_length=1, max_length=MAX_SMS_CHARS)
    route: str | None = Field(default=None, max_length=64)
    dlr_url: str | None = Field(default=None, max_length=512, description="Where Jasmin posts delivery receipts")
    dlr_level: Literal[1, 2, 3] = 2


class InteliquentSms(_SmsBase):
    provider: Literal["inteliquent"]
    credentials: InteliquentCredentials
    body: str | None = Field(default=None, min_length=1, max_length=MAX_SMS_CHARS)
    media_urls: list[Annotated[str, Field(max_length=2048)]] = Field(default_factory=list, max_length=10)

    @model_validator(mode="after")
    def _has_content(self):
        if not self.body and not self.media_urls:
            raise ValueError("body or media_urls is required")
        return self


SmsRequest = Annotated[Union[JasminSms, InteliquentSms], Field(discriminator="provider")]


# ---------------------------------------------------------------- email

class GraphCredentials(_Strict):
    tenant_id: str = Field(pattern=r"^[A-Za-z0-9.-]{1,128}$")
    client_id: str = Field(pattern=r"^[A-Za-z0-9-]{1,128}$")
    client_secret: SecretStr
    sender: str = Field(description="The mailbox Graph sends as")

    @field_validator("sender")
    @classmethod
    def _sender(cls, v: str) -> str:
        return _email(v)


class SmtpCredentials(_Strict):
    host: str = Field(max_length=253)
    port: int = Field(default=587, ge=1, le=65535)
    username: str | None = Field(default=None, max_length=320)
    password: SecretStr | None = None
    security: Literal["starttls", "tls", "none"] | None = Field(
        default=None, description="Default: tls on 465, starttls otherwise")
    verify_tls: bool = True

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


class _EmailBase(_Strict):
    to: list[str] = Field(min_length=1, max_length=MAX_EMAIL_RECIPIENTS)
    subject: str = Field(min_length=1, max_length=998)
    html: str | None = Field(default=None, max_length=MAX_EMAIL_BODY_CHARS)
    text: str | None = Field(default=None, max_length=MAX_EMAIL_BODY_CHARS)
    reply_to: str | None = None

    @field_validator("to")
    @classmethod
    def _to(cls, v: list[str]) -> list[str]:
        return [_email(item.strip()) for item in v]

    @field_validator("reply_to")
    @classmethod
    def _reply_to(cls, v: str | None) -> str | None:
        return None if v is None else _email(v)

    @field_validator("subject")
    @classmethod
    def _subject(cls, v: str) -> str:
        return _one_line(v)

    @model_validator(mode="after")
    def _has_body(self):
        if not self.html and not self.text:
            raise ValueError("html or text is required")
        return self


class GraphEmail(_EmailBase):
    provider: Literal["graph"]
    credentials: GraphCredentials


class SmtpEmail(_EmailBase):
    provider: Literal["smtp"]
    credentials: SmtpCredentials
    from_: str = Field(alias="from", description='Address, or "Name <address>"', max_length=400)

    @field_validator("from_")
    @classmethod
    def _from(cls, v: str) -> str:
        _one_line(v)
        match = re.match(r"^(.*)<([^<>]+)>$", v)
        _email(match.group(2).strip() if match else v)
        return v


EmailRequest = Annotated[Union[GraphEmail, SmtpEmail], Field(discriminator="provider")]


# ---------------------------------------------------------------- responses

class Accepted(BaseModel):
    status: Literal["accepted"] = "accepted"
    provider: str
    message_id: str | None = Field(description="The provider's reference for the message, when it gives one")
    refused: list[str] = Field(default_factory=list, description="SMTP: recipients the server refused while taking the rest")
