"""What a provider send can fail with, and how each failure is answered."""

MAX_DETAIL_CHARS = 500


class SendError(Exception):
    """A send that didn't go out. status is the HTTP status notify-service answers with."""

    status = 502
    error = "provider_rejected"
    retryable = False

    def __init__(self, detail: str) -> None:
        super().__init__(detail)
        self.detail = detail[:MAX_DETAIL_CHARS]

    def body(self) -> dict:
        return {"error": self.error, "detail": self.detail, "retryable": self.retryable}


class ProviderRejected(SendError):
    """The provider answered and refused the message."""


class ProviderAuthFailed(SendError):
    """The provider refused the credentials in the config."""

    error = "provider_auth_failed"


class ProviderUnavailable(SendError):
    """The provider couldn't be reached, timed out, or failed on its side. Safe to retry."""

    status = 503
    error = "provider_unavailable"
    retryable = True


class NotPermitted(SendError):
    """The request asks for something this deployment has turned off."""

    status = 403
    error = "not_permitted"


class ConfigError(SendError):
    """The named config doesn't exist for this client, is off, is the wrong
    kind, or can't be read -- a setup problem, not the provider's."""

    status = 400
    error = "bad_config"
