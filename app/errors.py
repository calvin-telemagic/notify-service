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
    """The provider refused the credentials the caller passed."""

    error = "provider_auth_failed"


class ProviderUnavailable(SendError):
    """The provider couldn't be reached, timed out, or failed on its side. Safe to retry."""

    status = 503
    error = "provider_unavailable"
    retryable = True


class EgressRefused(SendError):
    """The request points at a host this deployment doesn't allow (EGRESS_ALLOWED_HOSTS)."""

    status = 403
    error = "host_not_allowed"


class NotPermitted(SendError):
    """The request asks for something this deployment has turned off."""

    status = 403
    error = "not_permitted"
