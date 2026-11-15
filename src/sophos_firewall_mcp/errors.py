"""Typed, sanitized exceptions raised by the Sophos Firewall REST transport.

Every exception carries only the HTTP method, the path template, the status code and, when the
appliance returned one, its short ``error`` code. Headers, the API key and raw response bodies are
never part of a message: the appliance returns JSON, HTML and plain-text error envelopes, and none
of them is safe to forward to a caller or a log line.

The hierarchy is the contract consumed by the domain adapters and by #26:

* :class:`SophosAPIError` -- base class, also used for unexpected statuses and malformed bodies.
* :class:`SophosAuthError` -- 401 (authentication) and 403 (authorization).
* :class:`SophosValidationError` -- 400.
* :class:`SophosNotFoundError` -- 404.
* :class:`SophosConflictError` -- 409.
* :class:`SophosTransportError` -- connect/DNS/TLS/timeout failures on a read.
* :class:`SophosAmbiguousWriteError` -- a write whose outcome is unknown; never retried.
"""

from __future__ import annotations


class SophosAPIError(Exception):
    """Base class for every failure reported by the Sophos REST transport.

    Args:
        message: Sanitized, human-readable description. It must never contain the API key, request
            headers or a raw response body.
        method: HTTP method of the failed request, when one was sent.
        path: Path template of the failed request (the caller-supplied path, never a full URL).
        status: HTTP status code, when the appliance answered.
        error_code: The appliance's short ``error`` code, when it could be extracted and sanitized.
    """

    def __init__(
        self,
        message: str,
        *,
        method: str | None = None,
        path: str | None = None,
        status: int | None = None,
        error_code: str | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.method = method
        self.path = path
        self.status = status
        self.error_code = error_code


class SophosAuthError(SophosAPIError):
    """Authentication or authorization failed (HTTP 401 or 403).

    The two statuses are different failures with different fixes, so they share this class
    but never a message: :attr:`~SophosAPIError.status` is the discriminator. A 401 means
    the API key itself is missing, invalid or expired; a 403 means the key is valid but the
    administrator profile behind it does not allow the operation. Callers that render a
    model-facing message must branch on the status instead of assuming a permission
    problem.
    """


class SophosValidationError(SophosAPIError):
    """The appliance rejected the request payload or parameters (HTTP 400)."""


class SophosNotFoundError(SophosAPIError):
    """The requested resource does not exist (HTTP 404)."""


class SophosConflictError(SophosAPIError):
    """The request conflicts with the current appliance state (HTTP 409)."""


class SophosAmbiguousWriteError(SophosAPIError):
    """A write may or may not have been applied; the outcome is unknown.

    Raised when a POST, PATCH or DELETE fails after the request may have reached the appliance
    (timeout, connection loss). The write is never retried automatically: reconcile with a read
    before repeating it.
    """


class SophosTransportError(SophosAPIError):
    """The appliance could not be reached or did not answer in time (read operations)."""
