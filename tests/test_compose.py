"""Tests for the shipped Docker Compose example (``docker-compose.yml``).

Docker is not available in CI, so these tests validate the Compose file as data: they parse it
with PyYAML and assert the properties the example promises -- read-only by default, the
concurrency limit passed through with the application default, the API key mounted as a file,
and the container hardening flags intact. They also cross-check ``.env.example`` so the two
examples cannot drift apart.

The Compose interpolation syntax (``${VAR:-default}``) is parsed here rather than delegated to
``docker compose config``, which would require a Docker daemon.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from sophos_firewall_mcp.config import DEFAULT_MAX_CONCURRENCY

ROOT = Path(__file__).resolve().parents[1]
COMPOSE_PATH = ROOT / "docker-compose.yml"
ENV_EXAMPLE_PATH = ROOT / ".env.example"
README_PATH = ROOT / "README.md"

SERVICE_NAME = "sophos-firewall-mcp"
SECRET_NAME = "sophos_api_key"
SECRET_MOUNT = "/run/secrets/sophos_api_key"

#: ``${NAME:-default}`` or ``${NAME:?message}``.
_INTERPOLATION = re.compile(r"^\$\{(?P<name>[A-Z0-9_]+):(?P<op>[-?])(?P<rest>.*)\}$")


def load_compose() -> dict[str, Any]:
    """Return the parsed Compose document."""
    document = yaml.safe_load(COMPOSE_PATH.read_text(encoding="utf-8"))
    assert isinstance(document, dict)
    return document


def service() -> dict[str, Any]:
    """Return the single service definition."""
    services = load_compose()["services"]
    assert list(services) == [SERVICE_NAME]
    return services[SERVICE_NAME]


def environment() -> dict[str, str]:
    """Return the service environment map."""
    values = service()["environment"]
    assert isinstance(values, dict)
    return values


def interpolation_default(value: str) -> str:
    """Return the default of a ``${VAR:-default}`` entry, or the literal value.

    A ``${VAR:?message}`` entry has no default and is a hard requirement, so it is returned
    unchanged to make the distinction visible to the caller.
    """
    match = _INTERPOLATION.match(value)
    if match is None:
        return value
    if match.group("op") == "?":
        return value
    return match.group("rest")


def env_example() -> dict[str, str]:
    """Return the uncommented ``KEY=VALUE`` pairs of ``.env.example``."""
    values: dict[str, str] = {}
    for raw_line in ENV_EXAMPLE_PATH.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        values[key.strip()] = value.strip()
    return values


# -- Read-only by default ----------------------------------------------------


def test_compose_defaults_to_read_only_mode() -> None:
    """A default Compose configuration registers no mutation tools."""
    value = environment()["SOPHOS_READ_ONLY_MODE"]

    assert interpolation_default(value) == "true"
    # The host can still opt in explicitly; the default is what matters here.
    assert value == "${SOPHOS_READ_ONLY_MODE:-true}"


def test_env_example_defaults_to_read_only_mode() -> None:
    """The copy-and-run environment template also starts read-only."""
    assert env_example()["SOPHOS_READ_ONLY_MODE"] == "true"


def test_application_default_stays_writable() -> None:
    """The Compose/example default is a deployment choice, not an application change."""
    from sophos_firewall_mcp.config import Settings

    settings = Settings.from_env({"SOPHOS_HOST": "fw.example.com", "SOPHOS_API_KEY": "k"})

    assert settings.read_only_mode is False


# -- Concurrency -------------------------------------------------------------


def test_compose_passes_max_concurrency_with_application_default() -> None:
    value = environment()["SOPHOS_MAX_CONCURRENCY"]

    assert interpolation_default(value) == str(DEFAULT_MAX_CONCURRENCY)
    assert value == f"${{SOPHOS_MAX_CONCURRENCY:-{DEFAULT_MAX_CONCURRENCY}}}"


def test_env_example_max_concurrency_matches_application_default() -> None:
    assert env_example()["SOPHOS_MAX_CONCURRENCY"] == str(DEFAULT_MAX_CONCURRENCY)


# -- Secret handling ---------------------------------------------------------


def test_api_key_is_a_mounted_secret_file() -> None:
    document = load_compose()
    env = environment()

    # The key is never a literal in the environment.
    assert "SOPHOS_API_KEY" not in env
    assert env["SOPHOS_API_KEY_FILE"] == SECRET_MOUNT

    # The service mounts the declared secret, and the secret is a host file.
    assert service()["secrets"] == [SECRET_NAME]
    secret = document["secrets"][SECRET_NAME]
    assert set(secret) == {"file"}
    assert secret["file"] == "${SOPHOS_API_KEY_FILE:-./secrets/sophos_api_key}"


def test_compose_contains_no_literal_api_key() -> None:
    text = COMPOSE_PATH.read_text(encoding="utf-8")

    assert "SOPHOS_API_KEY:" not in text
    assert "SOPHOS_API_KEY=" not in text


def test_env_example_prefers_the_file_based_credential() -> None:
    """The template must not advertise an inline key as its uncommented default."""
    values = env_example()

    assert "SOPHOS_API_KEY_FILE" in values
    assert "SOPHOS_API_KEY" not in values


def test_env_example_secret_path_matches_compose_default() -> None:
    """The host path in the template is the Compose secret source default."""
    compose_default = interpolation_default(load_compose()["secrets"][SECRET_NAME]["file"])

    assert env_example()["SOPHOS_API_KEY_FILE"] == compose_default


# -- Container hardening -----------------------------------------------------


def test_stdio_lifecycle_flags_are_intact() -> None:
    definition = service()

    assert definition["stdin_open"] is True
    assert definition["tty"] is False
    # No published port: this is not an HTTP service.
    assert "ports" not in definition


def test_no_restart_policy_for_a_client_owned_stdio_process() -> None:
    """A restart policy would re-spawn a server whose stdin has already closed."""
    assert "restart" not in service()


def test_container_hardening_flags_are_intact() -> None:
    definition = service()

    assert definition["read_only"] is True
    assert "no-new-privileges:true" in definition["security_opt"]
    assert "ALL" in definition["cap_drop"]


def test_tls_verification_is_on_by_default() -> None:
    value = environment()["SOPHOS_VERIFY_SSL"]

    assert interpolation_default(value) == "true"


# -- Documentation consistency ----------------------------------------------


def test_readme_documents_the_supported_compose_invocation() -> None:
    readme = README_PATH.read_text(encoding="utf-8")

    assert "docker compose run --rm -T sophos-firewall-mcp" in readme
    assert "`docker compose up` is **not** the supported invocation" in readme
    assert "no `restart` policy" in readme


def test_readme_documents_the_socket_bridge_escape_hatch() -> None:
    """A TCP/SSE bridge is a different deployment and may add its own restart policy."""
    readme = README_PATH.read_text(encoding="utf-8")

    assert "bridges STDIO over TCP/SSE" in readme
    assert "`restart: unless-stopped` in an override file" in readme


def test_readme_does_not_advertise_a_writable_container_default() -> None:
    readme = README_PATH.read_text(encoding="utf-8")

    assert '"SOPHOS_READ_ONLY_MODE": "false"' not in readme
