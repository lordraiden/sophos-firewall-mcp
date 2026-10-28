"""Async Sophos Firewall XML API Client."""

import logging
import os
from typing import Any, Dict, FrozenSet, List, Optional, Tuple, Union, cast
from xml.parsers.expat import ExpatError

import httpx
import xmltodict

logger = logging.getLogger(__name__)

# --- Response diagnostics ----------------------------------------------------
# An empty or non-XML body used to surface as `ExpatError: no element found: line 1, column 0`, which names
# neither the appliance nor the cause. The body is empty for real, ordinary reasons -- API access disabled,
# client IP missing from Allowed IP Addresses, wrong port, or a proxy eating the form body -- so the error
# spells those out instead of looking like a parser bug.
_EMPTY_BODY_MESSAGE = (
    "the appliance accepted the request and returned an empty body (HTTP {status}). "
    "This is a configuration problem, not a credentials problem: check that (1) API access is enabled "
    "under System > Administration > API Access, (2) this client's IP is in Allowed IP Addresses, "
    "(3) the port ({port}) is the Admin Console HTTPS port configured on the appliance, and (4) no proxy "
    "or WAF is stripping the request body. The XML must travel in the 'reqxml' form field."
)

_TIMEOUT_MESSAGE = (
    "SFOS did not answer within {seconds:g}s (operation={operation}, tag={tag}, endpoint={endpoint}). "
    "A full listing on a large configuration can take longer than that: raise SOPHOS_TIMEOUT "
    "(for example SOPHOS_TIMEOUT=300) or request less data. Without a message like this the caller only "
    "saw 'Error executing tool <name>: ' with nothing after the colon, because str(httpx.ReadTimeout()) "
    "is empty."
)
_CONNECT_MESSAGE = (
    "Could not reach SFOS at {endpoint} (operation={operation}, tag={tag}): {reason}. Check "
    "SOPHOS_HOST/SOPHOS_PORT, that the admin console is reachable from this host, and that API access "
    "is enabled for this client IP."
)
DEFAULT_TIMEOUT = 120.0


def _env_timeout() -> float:
    """HTTP timeout: ``SOPHOS_TIMEOUT`` in seconds, else :data:`DEFAULT_TIMEOUT`.

    The old hardcoded 30s is below what a full ``Get FirewallRule`` takes on a real configuration (~64 KB
    over a VPN), so legitimate calls failed as if the server had died. An invalid value falls back to the
    default with a warning rather than raising: a typo in an env var must not stop the server from booting.
    """
    raw = os.getenv("SOPHOS_TIMEOUT", "").strip()
    if not raw:
        return DEFAULT_TIMEOUT
    try:
        value = float(raw)
    except ValueError:
        logger.warning("SOPHOS_TIMEOUT=%r is not a number; using %ss", raw, DEFAULT_TIMEOUT)
        return DEFAULT_TIMEOUT
    if value <= 0 or value != value:  # non-positive or NaN
        logger.warning("SOPHOS_TIMEOUT=%r is not a usable timeout; using %ss", raw, DEFAULT_TIMEOUT)
        return DEFAULT_TIMEOUT
    return value


_NOT_XML_MESSAGE = (
    "the appliance answered HTTP {status} with a body that is not XML. First {limit} characters "
    "received (credentials redacted): {snippet}"
)


def _redacted_snippet(text: str, secret: str, limit: int = 240) -> str:
    """First *limit* characters of a body, with the account password removed.

    The snippet exists so the failure can be diagnosed, so it must not become a new way for the password
    to reach a log line or a tool result.
    """
    snippet = " ".join(text.split())[:limit]
    if secret:
        snippet = snippet.replace(secret, "[REDACTED]")
    return snippet or "<empty>"


# --- Payload hardening -------------------------------------------------------
# The SFOS XML API returns credential material inside some Get payloads: the
# <Interface> entity carries the PPPoE Username and an encrypted Password.
SECRET_KEYS: FrozenSet[str] = frozenset(
    {
        "password",
        "passwordhash",
        "presharedkey",
        "passphrase",
        "secret",
        "token",
        "privatekey",
        "clientsecret",
    }
)

# Tags carrying credentials beyond the global denylist. "username" stays out of
# SECRET_KEYS on purpose: the User entity uses it as the account identifier, and
# sophos_list_users would otherwise lose its primary field.
TAG_SECRET_KEYS: Dict[str, FrozenSet[str]] = {"interface": frozenset({"username"})}

# --- SFOS status codes -------------------------------------------------------
# Official table: https://docs.sophos.com/nsg/sophos-firewall/22.0/api/apicontentpage.html
# The previous logic guessed from the message text and exempted 500 outright, so a 500 ("Operation could
# not be performed on Entity") was reported as success and a 203 ("successful but few configurations could
# not be applied") looked identical to a clean 200. For a server an agent uses to change firewall
# configuration, a partial apply reported as success is the most expensive mistake available.
_STATUS_DESCRIPTIONS: Dict[str, str] = {
    "200": "Configuration applied successfully",
    "201": "Operation partially successful",
    "203": "Operation successful but few configurations could not be applied",
    "216": "Operation successful",
    "500": "Operation could not be performed on Entity",
    "501": "Configuration parameters validation failed",
    "502": "Entity having same name already exists",
    "503": "Entity having same parameter details already exists",
    "521": "XML request not compatible with current API version",
    "526": "Record does not exist",
    "528": "Trying to update default entities which are not editable",
    "529": "Invalid XML request for entity/entities",
    "530": "API version not supported for specific entity",
    "599": "Not having privilege to add/modify configuration",
}

# 200/216 are the only codes that mean "fully applied".
_STATUS_OK = frozenset({"200", "216"})
# 201/203 say so in their own text; 211-215 are warning messages attached to an operation.
_STATUS_WARNING = frozenset({"201", "203", "211", "212", "213", "214", "215"})
# 204-210 "partially failed", 504-510/511-520/522-525/541-590 failed or limit reached: errors by default,
# which is what an unlisted code falls back to as well.


def _classify_status(code: str) -> str:
    """Map an SFOS status code to ``ok`` / ``warning`` / ``error`` using the documented table."""
    if code in _STATUS_OK:
        return "ok"
    if code in _STATUS_WARNING:
        return "warning"
    return "error"


def _status_message(code: str, text: str = "") -> str:
    """Human-readable meaning of a status code, keeping whatever the appliance itself said."""
    described = _STATUS_DESCRIPTIONS.get(code, text or "no description provided by the appliance")
    if text and text != described:
        return f"{described} ({text})"
    return described


def _scrub_secrets(node: Any, keys: FrozenSet[str] = SECRET_KEYS) -> Any:
    """Return a copy of an API payload with credential-bearing keys removed."""
    if isinstance(node, dict):
        return {
            key: _scrub_secrets(value, keys)
            for key, value in node.items()
            if str(key).lower() not in keys
        }
    if isinstance(node, list):
        return [_scrub_secrets(item, keys) for item in node]
    return node


def _find_error_status(node: Any) -> Optional[Tuple[str, str]]:
    """Locate an error <Status> nested anywhere in the response tree.

    SFOS nests the error inside the echoed tag, for example::

        <Response><SystemInformation>
            <Status code="529">Input request module is Invalid</Status>
        </SystemInformation></Response>

    so a top-level-only check misses it and the error is returned as data.

    Only mappings carrying an "@code" attribute are considered: per-record
    Status fields are plain strings ("Enable"/"Disable") and must survive.
    """
    if isinstance(node, dict):
        code = node.get("@code")
        if isinstance(code, str) and _classify_status(code) != "ok":
            return code, str(node.get("#text", ""))
        for value in node.values():
            found = _find_error_status(value)
            if found is not None:
                return found
    elif isinstance(node, list):
        for item in node:
            found = _find_error_status(item)
            if found is not None:
                return found
    return None


class SophosAPIError(Exception):
    """Base exception for Sophos Firewall API errors."""

    pass


class SophosAuthenticationError(SophosAPIError):
    """Raised when authentication with Sophos Firewall fails."""

    pass


class SophosResponseError(SophosAPIError):
    """Raised when Sophos Firewall returns an API error status code."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(f"Sophos API Error {code}: {message}")


class SophosPartialResultError(SophosResponseError):
    """Raised when SFOS reports a partial result: some of the requested change was not applied.

    A separate class because ``except SophosResponseError`` should still catch it, while a caller that
    wants to distinguish "nothing happened" from "half of it happened" can. Treating this as success is the
    failure mode that matters: an agent that believes a firewall rule was applied when only part of it was
    will not retry.
    """


class SophosFirewallClient:
    """Asynchronous client for interacting with Sophos Firewall (SFOS) XML API."""

    def __init__(
        self,
        host: Optional[str] = None,
        port: Optional[int] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        api_version: Optional[str] = None,
        verify_ssl: Optional[bool] = None,
        timeout: Optional[float] = None,
    ) -> None:
        """Initialize Sophos Firewall XML API client.

        Args:
            host: Firewall IP or domain. Defaults to SOPHOS_HOST env var or 172.16.16.16.
            port: API Web Console port. Defaults to SOPHOS_PORT env var or 4444.
            username: Admin username. Defaults to SOPHOS_USERNAME env var or admin.
            password: Admin password. Defaults to SOPHOS_PASSWORD env var.
            api_version: Sophos API Version. Defaults to SOPHOS_API_VERSION env var or 2200.1.
            verify_ssl: Validate SSL certs. Defaults to SOPHOS_VERIFY_SSL env var or False.
            timeout: Request timeout in seconds. Defaults to ``SOPHOS_TIMEOUT`` or 120.
        """
        self.host = host or os.environ.get("SOPHOS_HOST", "172.16.16.16")
        self.port = port or int(os.environ.get("SOPHOS_PORT", "4444"))
        self.username = username or os.environ.get("SOPHOS_USERNAME", "admin")
        self.password = password or os.environ.get("SOPHOS_PASSWORD", "")
        self.api_version = api_version or os.environ.get("SOPHOS_API_VERSION", "2200.1")

        if verify_ssl is None:
            v_env = os.environ.get("SOPHOS_VERIFY_SSL", "true").lower()
            self.verify_ssl = v_env in ("1", "true", "yes")
        else:
            self.verify_ssl = verify_ssl

        if not self.verify_ssl:
            logger.warning(
                "SSL certificate verification is disabled (verify_ssl=False). "
                "HTTPS requests to Sophos Firewall appliance will not validate TLS certificates."
            )

        self.timeout = _env_timeout() if timeout is None else timeout
        self.endpoint_url = f"https://{self.host}:{self.port}/webconsole/APIController"

        self._client = httpx.AsyncClient(
            verify=self.verify_ssl,
            timeout=self.timeout,
        )

    def build_xml_request(
        self,
        operation: str,
        tag: str,
        params: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Build SFOS XML request string with embedded authentication credentials.

        Args:
            operation: Operation tag ('Get', 'Set', 'Remove').
            tag: Entity tag (e.g., 'SystemInformation', 'FirewallRule', 'IPHost').
            params: Optional child parameters or entity definitions.

        Returns:
            Formatted XML request string.
        """
        req: Dict[str, Any] = {
            "Request": {
                "@APIVersion": self.api_version,
                "Login": {
                    "Username": self.username,
                    "Password": self.password,
                },
                operation: {
                    tag: params if params is not None else {}
                },
            }
        }
        return cast(str, xmltodict.unparse(req, pretty=True))

    def _applied(self, code: str, text: str, *, operation: str) -> bool:
        """Decide what a status code means, raising unless the operation genuinely applied.

        Returns False only for the one case that is an answer rather than a failure: a Get for a record
        that does not exist (526), where callers get an empty result instead of an exception.
        """
        verdict = _classify_status(code)
        if verdict == "ok":
            return True
        if verdict == "warning":
            raise SophosPartialResultError(code=code, message=_status_message(code, text))
        if code == "526" and operation.lower() == "get":
            logger.warning("SFOS answered 526 (record does not exist) for a Get; returning no rows")
            return False
        raise SophosResponseError(code=code, message=_status_message(code, text))

    async def send_request(
        self,
        operation: str,
        tag: str,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Send an XML API request to the Sophos Firewall appliance.

        Args:
            operation: API operation ('Get', 'Set', 'Remove').
            tag: Target XML tag/object.
            params: Parameters for the payload or query filters.

        Returns:
            Parsed response payload dictionary.

        Raises:
            SophosAuthenticationError: If login credentials are invalid.
            SophosResponseError: If SFOS returns a non-200 status code.
            SophosResponseError: Also for timeouts (code TIMEOUT) and unreachable hosts (code CONNECT).
        """
        xml_payload = self.build_xml_request(operation, tag, params)
        data = {"reqxml": xml_payload}

        try:
            response = await self._client.post(self.endpoint_url, data=data)
            response.raise_for_status()
        except httpx.TimeoutException as exc:
            raise SophosResponseError(
                code="TIMEOUT",
                message=_TIMEOUT_MESSAGE.format(
                    seconds=self.timeout,
                    operation=operation,
                    tag=tag,
                    endpoint=self.endpoint_url,
                ),
            ) from exc
        except httpx.TransportError as exc:
            reason = f"{type(exc).__name__}: {exc}".rstrip(": ")
            raise SophosResponseError(
                code="CONNECT",
                message=_CONNECT_MESSAGE.format(
                    endpoint=self.endpoint_url,
                    operation=operation,
                    tag=tag,
                    reason=reason,
                ),
            ) from exc

        body = response.text or ""
        if not body.strip():
            raise SophosResponseError(
                code="EMPTY",
                message=_EMPTY_BODY_MESSAGE.format(status=response.status_code, port=self.port),
            )

        try:
            parsed: Dict[str, Any] = xmltodict.parse(body)
        except ExpatError:
            raise SophosResponseError(
                code="NOT-XML",
                message=_NOT_XML_MESSAGE.format(
                    status=response.status_code,
                    limit=240,
                    snippet=_redacted_snippet(body, self.password),
                ),
            ) from None

        resp_data = parsed.get("Response", {})

        # Check login status
        login_info = resp_data.get("Login", {})
        if isinstance(login_info, dict):
            status_text = login_info.get("status", "")
            if "Authentication Failed" in status_text:
                raise SophosAuthenticationError(f"Authentication failed: {status_text}")

        # Check API status response against the documented SFOS table.
        status_info = resp_data.get("Status", {})
        code, text = "200", ""
        if isinstance(status_info, dict):
            code = str(status_info.get("@code", "200"))
            text = str(status_info.get("#text", ""))
        elif isinstance(status_info, str):
            text = status_info

        if not self._applied(code, text, operation=operation):
            return {}

        # SFOS nests the status inside the echoed tag, where the top-level check
        # above cannot see it.
        nested = _find_error_status(resp_data)
        if nested is not None:
            nested_code, nested_message = nested
            self._applied(nested_code, nested_message, operation=operation)

        return cast(Dict[str, Any], resp_data)

    async def get_tag(
        self,
        tag: str,
        filter_criteria: Optional[Dict[str, Any]] = None,
    ) -> Union[Dict[str, Any], List[Dict[str, Any]]]:
        """Query data for a specific XML tag.

        Args:
            tag: Sophos XML entity tag (e.g. 'FirewallRule', 'IPHost').
            filter_criteria: Optional XML filter tag parameters.

        Returns:
            Dictionary or list of objects matching the query.
        """
        res = await self.send_request("Get", tag, filter_criteria)
        payload = res.get(tag, res)
        extra_keys = TAG_SECRET_KEYS.get(str(tag).lower(), frozenset())
        return cast(
            Union[Dict[str, Any], List[Dict[str, Any]]],
            _scrub_secrets(payload, SECRET_KEYS | extra_keys),
        )

    async def set_tag(
        self,
        tag: str,
        payload: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Create or update an object using a 'Set' operation.

        Args:
            tag: Sophos XML entity tag (e.g. 'FirewallRule', 'IPHost').
            payload: Parameters defining the entity state.

        Returns:
            API response status dictionary.
        """
        res = await self.send_request("Set", tag, payload)
        return cast(Dict[str, Any], res)

    async def remove_tag(
        self,
        tag: str,
        name: str,
    ) -> Dict[str, Any]:
        """Delete an object using a 'Remove' operation.

        Args:
            tag: Sophos XML entity tag (e.g. 'FirewallRule', 'IPHost').
            name: Name attribute of the entity to delete.

        Returns:
            API response status dictionary.
        """
        payload = {"Name": name}
        res = await self.send_request("Remove", tag, payload)
        return cast(Dict[str, Any], res)

    async def close(self) -> None:
        """Close the underlying HTTPX client connection pool."""
        await self._client.aclose()

    async def __aenter__(self) -> "SophosFirewallClient":
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.close()
