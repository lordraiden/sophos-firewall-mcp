"""Typed, validated configuration for the Sophos Firewall Configuration REST API.

The settings are a plain Pydantic v2 model with an explicit :meth:`Settings.from_env` constructor.
``pydantic-settings`` is intentionally not used: it is not a project dependency, and an explicit
mapping makes the configuration testable without mutating ``os.environ``.

Security rules enforced here:

* exactly one of ``SOPHOS_API_KEY`` / ``SOPHOS_API_KEY_FILE`` is required, and the key is stored as
  :class:`pydantic.SecretStr` so ``repr``, ``str``, ``model_dump_json`` and validation errors never
  contain it;
* ``SOPHOS_HOST`` is a bare hostname or IP address -- no scheme, user information, port, path,
  query or fragment -- so the base URL cannot be pointed at another origin;
* the base URL is HTTPS by construction;
* no legacy XML-era setting is read: the only recognised variables are the nine listed above.
"""

from __future__ import annotations

import ipaddress
import math
import os
import re
from pathlib import Path
from typing import Any, Mapping

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    ValidationError,
    field_validator,
    model_validator,
)

__all__ = ["ConfigurationError", "Settings"]

#: Fixed API root of the Sophos Firewall Configuration REST API.
API_PATH_PREFIX = "/api/firewall-config/v1"

#: Default HTTPS port of the SFOS Web Admin Console (``servers`` variable in the OpenAPI contract).
DEFAULT_PORT = 4444

#: Default read/write/connect timeout in seconds.
DEFAULT_TIMEOUT = 30.0

#: Default number of requests the shared client keeps in flight at once.
#:
#: The MCP specification lists "rate limit tool invocations" among the things a server MUST do, and
#: a model that fans out can otherwise open one connection per tool call. Four is enough to keep a
#: composite tool parallel without turning a runaway loop into a burst against the appliance, which
#: rate-limits on its own side.
DEFAULT_MAX_CONCURRENCY = 4

#: Upper bound for ``SOPHOS_MAX_CONCURRENCY``.
#:
#: The setting exists to *bound* concurrency; accepting an arbitrarily large value would let a
#: misconfiguration switch the protection off, so the ceiling is enforced here rather than trusted.
MAX_CONCURRENCY_LIMIT = 64

_HOST_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_HOSTNAME_PATTERN = re.compile(rf"^{_HOST_LABEL}(?:\.{_HOST_LABEL})*$")

_ENV_HOST = "SOPHOS_HOST"
_ENV_PORT = "SOPHOS_PORT"
_ENV_API_KEY = "SOPHOS_API_KEY"
_ENV_API_KEY_FILE = "SOPHOS_API_KEY_FILE"
_ENV_VERIFY_SSL = "SOPHOS_VERIFY_SSL"
_ENV_CA_BUNDLE = "SOPHOS_CA_BUNDLE"
_ENV_TIMEOUT = "SOPHOS_TIMEOUT"
_ENV_READ_ONLY_MODE = "SOPHOS_READ_ONLY_MODE"
_ENV_MAX_CONCURRENCY = "SOPHOS_MAX_CONCURRENCY"


class ConfigurationError(ValueError):
    """The environment does not describe a usable appliance connection.

    Messages name the offending setting and the rule it broke. They never contain the API key.
    """


def _raw(env: Mapping[str, str], name: str) -> str | None:
    """Return the raw value of *name*, or ``None`` when it is absent.

    A non-string value is a programming error in the caller-supplied mapping, not a secret, so it is
    reported by name only.
    """
    value = env.get(name)
    if value is None:
        return None
    if not isinstance(value, str):
        raise ConfigurationError(f"{name} must be a string")
    return value


def _optional(env: Mapping[str, str], name: str) -> str | None:
    """Return *name* stripped, or ``None`` when it is absent or blank.

    Stripping here keeps every optional setting consistent: a ``.env`` line such as
    ``SOPHOS_VERIFY_SSL= false `` must mean the same as ``SOPHOS_VERIFY_SSL=false``, exactly as
    Pydantic already tolerates surrounding whitespace for the numeric settings.
    """
    value = _raw(env, name)
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


def _summarize(exc: ValidationError) -> str:
    """Render a Pydantic error without its ``input`` values.

    ``str(ValidationError)`` echoes the input it rejected, which would leak the API key. Only the
    field location and the validator message are kept.
    """
    details: list[str] = []
    for error in exc.errors():
        location = ".".join(str(part) for part in error.get("loc", ())) or "configuration"
        details.append(f"{location}: {error.get('msg', 'invalid value')}")
    return "invalid configuration: " + "; ".join(details)


def _validate_host(value: str) -> str:
    """Accept a bare hostname or IP address and reject anything that could change the origin."""
    if not isinstance(value, str):  # pragma: no cover - Pydantic already enforces the type
        raise ValueError("host must be a string")
    if value == "":
        raise ValueError("host must not be empty")
    if value != value.strip():
        raise ValueError("host must not have leading or trailing whitespace")
    if any(character.isspace() for character in value):
        raise ValueError("host must not contain whitespace")
    if "://" in value:
        raise ValueError("host must not include a scheme; use the bare hostname or IP address")
    if "@" in value:
        raise ValueError("host must not include user information")
    if "[" in value or "]" in value:
        raise ValueError("host must not include brackets")
    if any(separator in value for separator in "/?#"):
        raise ValueError("host must not include a path, query or fragment")
    if "\\" in value:
        raise ValueError("host must not include a backslash")

    if ":" in value:
        # The only legitimate colon in a bare host is an IPv6 literal.
        try:
            address = ipaddress.IPv6Address(value)
        except ValueError:
            raise ValueError("host must not include a port; set SOPHOS_PORT instead") from None
        if address.scope_id:
            raise ValueError("host must not include an IPv6 scope id")
        return value

    if "%" in value:
        raise ValueError("host must not include an IPv6 scope id")

    try:
        ipaddress.IPv4Address(value)
        return value
    except ValueError:
        pass

    if not value.isascii():
        raise ValueError("host must be ASCII; use punycode for international hostnames")
    if len(value) > 253:
        raise ValueError("host is longer than 253 characters")
    if _HOSTNAME_PATTERN.match(value) is None:
        raise ValueError("host must be a valid hostname or IP address")
    return value


class Settings(BaseModel):
    """Validated connection settings for one Sophos Firewall appliance.

    Build it with :meth:`from_env` in production and directly in tests. ``api_key`` always holds the
    resolved secret; ``api_key_file`` records the path it was read from, if any, for diagnostics.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    host: str
    port: int = Field(default=DEFAULT_PORT)
    api_key: SecretStr
    api_key_file: Path | None = None
    verify_ssl: bool = True
    ca_bundle: Path | None = None
    timeout: float = Field(default=DEFAULT_TIMEOUT)
    read_only_mode: bool = False
    max_concurrency: int = Field(default=DEFAULT_MAX_CONCURRENCY)

    @field_validator("host")
    @classmethod
    def _check_host(cls, value: str) -> str:
        return _validate_host(value)

    @field_validator("api_key")
    @classmethod
    def _check_api_key(cls, value: SecretStr) -> SecretStr:
        """Reject an empty secret, including on direct construction.

        ``from_env`` already rejects a missing or blank key, but ``Settings(...)`` is also a public
        constructor: without this check the server could start with ``Authorization: Bearer `` and
        fail only on the first API call. Surrounding whitespace is stripped for the same reason
        ``from_env`` strips it; the key itself never appears in the error.
        """
        secret = value.get_secret_value()
        stripped = secret.strip()
        if stripped == "":
            raise ValueError("api_key must not be empty")
        if stripped != secret:
            return SecretStr(stripped)
        return value

    @field_validator("port")
    @classmethod
    def _check_port(cls, value: int) -> int:
        if not 1 <= value <= 65535:
            raise ValueError("port must be between 1 and 65535")
        return value

    @field_validator("timeout")
    @classmethod
    def _check_timeout(cls, value: float) -> float:
        if not math.isfinite(value) or value <= 0:
            raise ValueError("timeout must be a finite number of seconds greater than 0")
        return value

    @field_validator("max_concurrency")
    @classmethod
    def _check_max_concurrency(cls, value: int) -> int:
        if not 1 <= value <= MAX_CONCURRENCY_LIMIT:
            raise ValueError(
                f"max_concurrency must be between 1 and {MAX_CONCURRENCY_LIMIT} concurrent requests"
            )
        return value

    @field_validator("ca_bundle")
    @classmethod
    def _check_ca_bundle(cls, value: Path | None) -> Path | None:
        if value is None:
            return None
        if not value.is_file():
            raise ValueError(f"CA bundle does not exist or is not a file: {value}")
        return value

    @model_validator(mode="after")
    def _check_tls_combination(self) -> "Settings":
        if self.ca_bundle is not None and not self.verify_ssl:
            raise ValueError(
                "a CA bundle implies TLS verification; do not combine SOPHOS_CA_BUNDLE with "
                "SOPHOS_VERIFY_SSL=false"
            )
        return self

    @property
    def authority(self) -> str:
        """``host:port`` authority, with IPv6 literals bracketed for use in a URL."""
        if ":" in self.host:
            return f"[{self.host}]:{self.port}"
        return f"{self.host}:{self.port}"

    @property
    def base_url(self) -> str:
        """Fixed HTTPS base URL of the appliance API; never influenced by MCP input."""
        return f"https://{self.authority}{API_PATH_PREFIX}"

    @property
    def tls_verify(self) -> bool | str:
        """Value for ``httpx``'s ``verify``: a CA bundle path, or the boolean verification flag."""
        if self.ca_bundle is not None:
            return str(self.ca_bundle)
        return self.verify_ssl

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "Settings":
        """Build settings from an environment mapping.

        Args:
            env: Mapping to read. Defaults to :data:`os.environ`. Passing an explicit mapping never
                touches the process environment, which keeps tests isolated.

        Raises:
            ConfigurationError: A required value is missing, the two key sources are both set, the
                secret file cannot be read, or a value is invalid. The message never contains the
                API key.
        """
        source: Mapping[str, str] = os.environ if env is None else env

        host = _raw(source, _ENV_HOST)
        if host is None or host.strip() == "":
            raise ConfigurationError(
                f"{_ENV_HOST} is required (the firewall hostname or IP address, without scheme or port)"
            )

        raw_key = _optional(source, _ENV_API_KEY)
        raw_key_file = _optional(source, _ENV_API_KEY_FILE)
        if raw_key is not None and raw_key_file is not None:
            raise ConfigurationError(
                f"{_ENV_API_KEY} and {_ENV_API_KEY_FILE} are mutually exclusive; set exactly one"
            )
        if raw_key is None and raw_key_file is None:
            raise ConfigurationError(f"one of {_ENV_API_KEY} or {_ENV_API_KEY_FILE} is required")

        key_file: Path | None = None
        if raw_key_file is not None:
            key_file = Path(raw_key_file.strip()).expanduser()
            secret = _read_secret_file(key_file)
        else:
            assert raw_key is not None  # narrowed by the checks above
            secret = raw_key

        values: dict[str, Any] = {
            "host": host,
            "api_key": secret,
            "api_key_file": key_file,
        }
        port = _optional(source, _ENV_PORT)
        if port is not None:
            values["port"] = port
        verify_ssl = _optional(source, _ENV_VERIFY_SSL)
        if verify_ssl is not None:
            values["verify_ssl"] = verify_ssl
        ca_bundle = _optional(source, _ENV_CA_BUNDLE)
        if ca_bundle is not None:
            values["ca_bundle"] = Path(ca_bundle.strip()).expanduser()
        timeout = _optional(source, _ENV_TIMEOUT)
        if timeout is not None:
            values["timeout"] = timeout
        read_only_mode = _optional(source, _ENV_READ_ONLY_MODE)
        if read_only_mode is not None:
            values["read_only_mode"] = read_only_mode
        max_concurrency = _optional(source, _ENV_MAX_CONCURRENCY)
        if max_concurrency is not None:
            values["max_concurrency"] = max_concurrency

        try:
            return cls(**values)
        except ValidationError as exc:
            # ``from None`` keeps the original ValidationError (which echoes its input) out of the
            # traceback, so the API key cannot leak through exception chaining.
            raise ConfigurationError(_summarize(exc)) from None


def _read_secret_file(path: Path) -> str:
    """Read and strip the API key from a mounted secret file."""
    if not path.is_file():
        raise ConfigurationError(f"{_ENV_API_KEY_FILE} does not point to a readable file: {path}")
    try:
        secret = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise ConfigurationError(
            f"{_ENV_API_KEY_FILE} could not be read: {path} ({type(exc).__name__})"
        ) from None
    if secret == "":
        raise ConfigurationError(f"{_ENV_API_KEY_FILE} is empty: {path}")
    return secret
