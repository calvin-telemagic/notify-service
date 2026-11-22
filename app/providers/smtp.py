"""
Email over SMTP, extracted from telemagic-utils' com.pti.utils.EmailSender
(jakarta.mail: TLS on 465, STARTTLS on 587, a login, an HTML body), with the
host, login and sender coming from the client's stored config.

Unlike EmailSender, the certificate is checked unless the config sets
verify_tls false (EmailSender's trust_host), plaintext ("none") needs
ALLOW_INSECURE_SMTP, and STARTTLS is required, not opportunistic, so a server
that doesn't offer it fails the send rather than getting the password in the
clear. Messages are multipart/alternative when both text and HTML are given.
"""

import ssl
from email.message import EmailMessage
from email.utils import make_msgid

import aiosmtplib

from ..config import settings
from ..errors import NotPermitted, ProviderAuthFailed, ProviderRejected, ProviderUnavailable
from ..models import EmailRequest, SmtpConfig


def build_message(cfg: SmtpConfig, req: EmailRequest) -> EmailMessage:
    msg = EmailMessage()
    msg["From"] = cfg.from_
    msg["To"] = ", ".join(req.to)
    msg["Subject"] = req.subject
    reply_to = req.reply_to or cfg.reply_to
    if reply_to:
        msg["Reply-To"] = reply_to
    domain = cfg.from_.rsplit("@", 1)[-1].strip(" >")
    msg["Message-ID"] = make_msgid(domain=domain)
    if req.text:
        msg.set_content(req.text)
        if req.html:
            msg.add_alternative(req.html, subtype="html")
    else:
        msg.set_content(req.html, subtype="html")
    return msg


def _tls_context(verify: bool) -> ssl.SSLContext:
    context = ssl.create_default_context()
    if not verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


async def send(cfg: SmtpConfig, req: EmailRequest, timeout: float) -> tuple[str, list[str]]:
    """The Message-ID, and any recipients the server refused while taking the rest."""
    creds = cfg
    security = creds.effective_security
    if security == "none" and not settings.allow_insecure_smtp:
        raise NotPermitted("SMTP without TLS is turned off here (ALLOW_INSECURE_SMTP)")

    msg = build_message(cfg, req)
    context = _tls_context(creds.verify_tls)
    smtp = aiosmtplib.SMTP(
        hostname=creds.host,
        port=creds.port,
        timeout=timeout,
        use_tls=security == "tls",
        start_tls=security == "starttls",
        tls_context=context,
    )
    try:
        await smtp.connect()
        if creds.username is not None:
            if smtp.last_ehlo_response is None:
                await smtp.ehlo()
            if not smtp.supports_extension("auth"):
                raise ProviderAuthFailed("SMTP server offers no login (AUTH) on this connection")
            await smtp.login(creds.username, creds.password.get_secret_value())
        rejected, _ = await smtp.send_message(msg)
    except ProviderAuthFailed:
        raise
    except aiosmtplib.SMTPAuthenticationError as exc:
        raise ProviderAuthFailed(f"SMTP server refused the login: {exc.code} {exc.message}") from None
    except aiosmtplib.SMTPRecipientsRefused as exc:
        raise ProviderRejected("SMTP server refused every recipient: "
                               + "; ".join(f"{r.recipient} {r.code}" for r in exc.recipients)) from None
    except aiosmtplib.SMTPResponseException as exc:
        error = ProviderUnavailable if 400 <= exc.code < 500 else ProviderRejected
        raise error(f"SMTP server answered {exc.code} {exc.message}") from None
    except ssl.SSLCertVerificationError as exc:
        # A retry won't change the certificate.
        raise ProviderRejected(f"SMTP server's certificate failed verification: {exc.verify_message}") from None
    except (aiosmtplib.SMTPException, OSError, TimeoutError) as exc:
        if isinstance(exc.__cause__ or exc.__context__, ssl.SSLCertVerificationError):
            cause = exc.__cause__ or exc.__context__
            raise ProviderRejected(f"SMTP server's certificate failed verification: {cause.verify_message}") from None
        raise ProviderUnavailable(f"SMTP server unreachable: {type(exc).__name__}: {exc}") from None
    finally:
        if smtp.is_connected:
            try:
                await smtp.quit()
            except (aiosmtplib.SMTPException, OSError):
                smtp.close()
    return msg["Message-ID"], sorted(rejected)
