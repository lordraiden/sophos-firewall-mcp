"""Asynchronous transport for the Sophos Firewall Configuration REST API.

One :class:`SophosRestClient` wraps exactly one :class:`httpx.AsyncClient` and is created by the MCP
lifespan, shared by every domain adapter and closed in ``finally``. The appliance base URL is fixed
by :class:`~sophos_firewall_mcp.config.Settings`; callers pass a validated ``/``-prefixed path and
can never supply an absolute URL, a host or a header.

Transport policy (ADR-001 §9):

* ``Authorization: Bearer <api key>`` and ``Accept: application/json`` on every request;
  ``Content-Type: application/json`` on POST and PATCH only (never ``application/merge-patch+json``);
* TLS verification on by default, optional private CA bundle, explicit timeout;
* redirects are not followed, so the Bearer token cannot cross origins;
* ``trust_env=False``: inherited proxy variables are ignored;
* reads retry at most twice, only for connect/read timeouts and 502/503/504, with jittered
  exponential backoff; writes are never retried and surface
  :class:`~sophos_firewall_mcp.errors.SophosAmbiguousWriteError` instead;
* at most :attr:`~sophos_firewall_mcp.config.Settings.max_concurrency` requests are in flight at
  once (four by default, ``SOPHOS_MAX_CONCURRENCY`` to change it), so a model that fans out cannot
  turn one tool call per connection into a burst against the appliance. This is a **concurrency**
  bound, not an invocation-rate limit; the server's rate policy is recorded in
  ``docs/SECURITY-RATE-POLICY.md``.
"""

from __future__ import annotations

import asyncio
import logging
import random
import re
from typing import Any, Mapping

import httpx

from .config import Settings
from .errors import (
    SophosAmbiguousWriteError,
    SophosAPIError,
    SophosAuthError,
    SophosConflictError,
    SophosNotFoundError,
    SophosTransportError,
    SophosValidationError,
)

__all__ = ["SophosRestClient"]

logger = logging.getLogger(__name__)

#: Methods that carry a JSON request body and therefore a ``Content-Type`` header.
_JSON_BODY_METHODS = frozenset({"POST", "PATCH"})

#: Statuses that are worth retrying for an idempotent read.
_RETRYABLE_STATUSES = frozenset({502, 503, 504})

#: Statuses the contract uses for a successful response (204 is handled defensively).
_SUCCESS_STATUSES = frozenset({200, 201, 204})

#: Transport failures that are safe to retry for a read: the request was not applied.
_RETRYABLE_EXCEPTIONS = (httpx.ConnectTimeout, httpx.ReadTimeout)

#: Maximum attempts for a read (one initial attempt plus one retry).
_MAX_READ_ATTEMPTS = 2

#: Base delay of the jittered exponential backoff, in seconds.
_BACKOFF_BASE_SECONDS = 0.5

#: Documented status mapping. Anything else maps to the base :class:`SophosAPIError`.
#: 401 and 403 share :class:`SophosAuthError` because both are auth failures, but they are
#: not the same failure: the exception keeps ``status`` so the model-facing message can say
#: "the key is invalid" (401) instead of "the profile forbids this" (403).
_STATUS_EXCEPTIONS: dict[int, type[SophosAPIError]] = {
    400: SophosValidationError,
    401: SophosAuthError,
    403: SophosAuthError,
    404: SophosNotFoundError,
    409: SophosConflictError,
}

#: Characters allowed in the appliance's short ``error`` code before it reaches a message.
_ERROR_CODE_PATTERN = re.compile(r"[^A-Za-z0-9_.:-]")

#: Sentinel distinguishing "no body" from a JSON ``null`` body.
_NO_BODY = object()


async def _sleep(seconds: float) -> None:
    """Backoff sleep, kept module-level so tests can replace it with a no-op."""
    await asyncio.sleep(seconds)


def _backoff_delay(attempt: int) -> float:
    """Jittered exponential backoff for the given (1-based) retry attempt."""
    exponential: float = _BACKOFF_BASE_SECONDS * (2.0 ** (attempt - 1))
    jitter: float = random.uniform(0.5, 1.0)
    return exponential * jitter


def _describe_exception(exc: BaseException) -> str:
    """Short, single-line description of a transport exception (no headers, no body)."""
    name = type(exc).__name__
    detail = " ".join(str(exc).split())[:200]
    return f"{name}: {detail}" if detail else name


def _extract_error_code(response: httpx.Response) -> str | None:
    """Return the appliance's short ``error`` code, sanitized, or ``None``.

    The body may be JSON, HTML or plain text. Only a string ``error`` member is used; the
    ``message`` member and the raw body are deliberately discarded.
    """
    try:
        payload = response.json()
    except ValueError:
        return None
    if not isinstance(payload, dict):
        return None
    code = payload.get("error")
    if not isinstance(code, str):
        return None
    sanitized = _ERROR_CODE_PATTERN.sub("", code.strip())[:64]
    return sanitized or None


class SophosRestClient:
    """One shared async client for the Sophos Firewall Configuration REST API.

    Args:
        settings: Validated connection settings. The API key is read once and only ever placed in
            the ``Authorization`` header.

    The client owns an HTTP connection pool: create one instance per process, reuse it for every
    tool call and close it with :meth:`aclose` (or ``async with``).

    Concurrency is bounded by one semaphore shared by every primitive: at most
    ``settings.max_concurrency`` requests are in flight at once, and a request waiting for a slot
    holds no connection. The slot is released when the attempt finishes, including when it raises,
    so a failing request cannot starve the client.

    This is a concurrency bound, not a rate limit: it does not cap how many invocations a client may
    issue over time. See ``docs/SECURITY-RATE-POLICY.md`` for the server's invocation-rate policy.
    """

    def __init__(self, settings: Settings) -> None:
        if not isinstance(settings, Settings):
            raise TypeError("settings must be a Settings instance")
        self._settings = settings
        self._api_key = settings.api_key.get_secret_value()
        self._base_url = settings.base_url
        self._closed = False
        # Created here, not lazily: since Python 3.10 a Semaphore binds to the running loop on first
        # use, so constructing the client outside a loop is safe and the bound is fixed at startup.
        self._semaphore = asyncio.Semaphore(settings.max_concurrency)
        self._client = httpx.AsyncClient(
            base_url=self._base_url,
            headers={
                "Authorization": f"Bearer {self._api_key}",
                "Accept": "application/json",
            },
            verify=settings.tls_verify,
            timeout=httpx.Timeout(settings.timeout),
            follow_redirects=False,
            trust_env=False,
        )

    def __repr__(self) -> str:
        return f"{type(self).__name__}(base_url={self._base_url!r})"

    @property
    def max_concurrency(self) -> int:
        """Maximum number of requests this client keeps in flight at once."""
        return self._settings.max_concurrency

    # -- Public interface -----------------------------------------------------

    async def get(self, path: str, *, params: Mapping[str, Any] | None = None) -> Any:
        """Read one resource or collection page.

        Args:
            path: ``/``-prefixed API path, a module constant in the domain adapters.
            params: Query parameters (filters, sort). Pagination belongs in :meth:`get_page`.

        Returns:
            The decoded JSON body, or ``None`` for an empty/204 response.
        """
        self._validate_path(path)
        return await self._read("GET", path, params=params)

    async def post(self, path: str, *, json: Any) -> Any:
        """Create a resource. Never retried: a failure after the request may be ambiguous."""
        self._validate_path(path)
        return await self._write("POST", path, body=json)

    async def patch(self, path: str, *, json: Any) -> Any:
        """Partially update a resource with a JSON Merge Patch body.

        The body must already be a partial document (``model_dump(exclude_unset=True)`` in the
        domain models); omitted properties keep their persisted value. Never retried.
        """
        self._validate_path(path)
        return await self._write("PATCH", path, body=json)

    async def delete(self, path: str) -> None:
        """Delete a resource. Never retried: a failure after the request may be ambiguous."""
        self._validate_path(path)
        await self._write("DELETE", path)
        return None

    async def get_page(
        self,
        path: str,
        *,
        page: int = 1,
        page_size: int = 50,
        page_total: bool = False,
        params: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Read one page of a paginated collection.

        Only for the 83 GET operations whose contract declares ``page``/``pageSize``/``pageTotal``.
        Validation happens before any I/O: the appliance accepts ``page=0`` but the contract does
        not, and it rejects ``pageSize`` above 100 with ``400 invalidPageSizeParam``.

        Args:
            path: ``/``-prefixed API path of the collection.
            page: 1-based page number (``>= 1``).
            page_size: Page size (``1 <= page_size <= 100``).
            page_total: Ask the appliance for ``pages.total``/``pages.items`` metadata.
            params: Additional query parameters (for example ``nameContains``).

        Returns:
            The page object exactly as returned, with ``items`` preserved and ``pages`` preserved
            when the operation declares it. ``pages`` is optional in the contract
            (``listNetworkInterfaces`` is in the v1 network domain), so it is never invented.

        Raises:
            ValueError: ``page`` or ``page_size`` is out of range; nothing is sent.
            SophosAPIError: The response is not a page object.
        """
        if isinstance(page, bool) or not isinstance(page, int) or page < 1:
            raise ValueError("page must be an integer greater than or equal to 1")
        if (
            isinstance(page_size, bool)
            or not isinstance(page_size, int)
            or not 1 <= page_size <= 100
        ):
            raise ValueError("page_size must be an integer between 1 and 100")

        query: dict[str, Any] = dict(params or {})
        query["page"] = page
        query["pageSize"] = page_size
        query["pageTotal"] = page_total

        payload = await self.get(path, params=query)
        if not isinstance(payload, dict):
            raise SophosAPIError(
                f"GET {path} returned a non-object body for a paginated operation",
                method="GET",
                path=path,
            )
        if not isinstance(payload.get("items"), list):
            raise SophosAPIError(
                f"GET {path} returned a paginated body without a list 'items'",
                method="GET",
                path=path,
            )
        pages = payload.get("pages")
        if pages is not None and not isinstance(pages, dict):
            raise SophosAPIError(
                f"GET {path} returned a non-object 'pages' in a paginated body",
                method="GET",
                path=path,
            )
        return payload

    async def aclose(self) -> None:
        """Close the connection pool. Safe to call more than once."""
        if self._closed:
            return
        self._closed = True
        await self._client.aclose()

    async def __aenter__(self) -> "SophosRestClient":
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    # -- Path validation ------------------------------------------------------

    @staticmethod
    def _validate_path(path: str) -> None:
        """Reject anything that is not a plain API path, before any I/O."""
        if not isinstance(path, str):
            raise ValueError("path must be a string")
        if path == "":
            raise ValueError("path must not be empty")
        if "://" in path:
            raise ValueError("path must not contain a scheme or an absolute URL")
        if not path.startswith("/"):
            raise ValueError("path must start with '/'")
        if path.startswith("//"):
            raise ValueError(
                "path must not start with '//'; absolute URLs and host overrides are not allowed"
            )
        if "%2e" in path.lower():
            # httpx sends percent-encoded segments verbatim; an appliance that decodes the path
            # first could turn %2e%2e into '..' and escape the fixed API prefix.
            raise ValueError(
                "path must not contain percent-encoded dots ('%2e'); they can be decoded into "
                "'..' and escape the API prefix"
            )
        for token, description in (
            ("..", "'..'"),
            ("\\", "a backslash"),
            ("?", "'?'"),
            ("#", "'#'"),
        ):
            if token in path:
                raise ValueError(
                    f"path must not contain {description}; pass query values through 'params'"
                )
        if path != path.strip():
            raise ValueError("path must not have leading or trailing whitespace")
        if any(ord(character) < 0x20 or ord(character) == 0x7F for character in path):
            raise ValueError("path must not contain control characters")

    # -- Request pipeline -----------------------------------------------------

    async def _send(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
        body: Any = _NO_BODY,
    ) -> httpx.Response:
        url = f"{self._base_url}{path}"
        request_headers = (
            {"Content-Type": "application/json"} if method in _JSON_BODY_METHODS else None
        )
        kwargs: dict[str, Any] = {}
        if params is not None:
            kwargs["params"] = dict(params)
        if body is not _NO_BODY:
            kwargs["json"] = body
        # The single choke point for every request: the semaphore is held for exactly one attempt,
        # so a retry waiting on its backoff does not occupy a slot. This bounds concurrency, not
        # invocation rate (see docs/SECURITY-RATE-POLICY.md).
        async with self._semaphore:
            return await self._client.request(method, url, headers=request_headers, **kwargs)

    async def _read(
        self, method: str, path: str, *, params: Mapping[str, Any] | None = None
    ) -> Any:
        """Send an idempotent read with the bounded retry policy."""
        for attempt in range(1, _MAX_READ_ATTEMPTS + 1):
            try:
                response = await self._send(method, path, params=params)
            except _RETRYABLE_EXCEPTIONS as exc:
                if attempt < _MAX_READ_ATTEMPTS:
                    logger.debug("%s %s: retrying after %s", method, path, type(exc).__name__)
                    await _sleep(_backoff_delay(attempt))
                    continue
                raise self._transport_error(method, path, exc) from exc
            except httpx.TransportError as exc:
                raise self._transport_error(method, path, exc) from exc

            if response.status_code in _RETRYABLE_STATUSES and attempt < _MAX_READ_ATTEMPTS:
                logger.debug("%s %s: retrying after HTTP %s", method, path, response.status_code)
                await _sleep(_backoff_delay(attempt))
                continue
            return self._decode(method, path, response)

        raise AssertionError("unreachable: the read loop always returns or raises")

    async def _write(self, method: str, path: str, *, body: Any = _NO_BODY) -> Any:
        """Send a write exactly once; a transport failure is ambiguous, never retried."""
        try:
            response = await self._send(method, path, body=body)
        except httpx.TransportError as exc:
            raise self._ambiguous_error(method, path, exc) from exc
        return self._decode(method, path, response)

    # -- Response handling ----------------------------------------------------

    def _decode(self, method: str, path: str, response: httpx.Response) -> Any:
        status = response.status_code
        if status in _SUCCESS_STATUSES:
            if status == 204 or not response.content:
                return None
            try:
                return response.json()
            except ValueError as exc:
                raise SophosAPIError(
                    f"{method} {path} returned HTTP {status} with a body that is not valid JSON",
                    method=method,
                    path=path,
                    status=status,
                ) from exc
        raise self._response_error(method, path, response)

    def _response_error(self, method: str, path: str, response: httpx.Response) -> SophosAPIError:
        status = response.status_code
        error_code = _extract_error_code(response)
        exception_type = _STATUS_EXCEPTIONS.get(status, SophosAPIError)
        message = f"{method} {path} failed with HTTP {status}"
        if error_code is not None:
            message = f"{message} (error: {error_code})"
        logger.debug("%s %s -> HTTP %s", method, path, status)
        return exception_type(
            self._scrub(message),
            method=method,
            path=path,
            status=status,
            error_code=error_code,
        )

    def _transport_error(
        self, method: str, path: str, exc: httpx.TransportError
    ) -> SophosTransportError:
        message = f"{method} {path} failed: {_describe_exception(exc)}"
        return SophosTransportError(self._scrub(message), method=method, path=path)

    def _ambiguous_error(
        self, method: str, path: str, exc: httpx.TransportError
    ) -> SophosAmbiguousWriteError:
        message = (
            f"{method} {path} may have been applied: {_describe_exception(exc)}; "
            "the outcome is unknown, reconcile with a read before retrying"
        )
        return SophosAmbiguousWriteError(self._scrub(message), method=method, path=path)

    def _scrub(self, text: str) -> str:
        """Defense in depth: the API key must never reach an exception message."""
        if self._api_key and self._api_key in text:
            return text.replace(self._api_key, "[REDACTED]")
        return text
