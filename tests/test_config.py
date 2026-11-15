"""Tests for the typed REST configuration (``sophos_firewall_mcp.config``).

These tests never contact a firewall: they exercise validation, secret handling and the fixed base
URL through ``Settings.from_env`` with an explicit mapping, so ``os.environ`` is never mutated.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from pydantic import ValidationError

from sophos_firewall_mcp.config import (
    API_PATH_PREFIX,
    DEFAULT_MAX_CONCURRENCY,
    DEFAULT_PORT,
    DEFAULT_TIMEOUT,
    MAX_CONCURRENCY_LIMIT,
    ConfigurationError,
    Settings,
)

KEY = "sfos_test_key_0123456789abcdef"


def env(**overrides: str) -> dict[str, str]:
    """Minimal valid environment, with overrides applied."""
    values = {"SOPHOS_HOST": "fw.example.com", "SOPHOS_API_KEY": KEY}
    values.update(overrides)
    return values


# -- Defaults and successful parsing -----------------------------------------


def test_from_env_defaults() -> None:
    settings = Settings.from_env(env())

    assert settings.host == "fw.example.com"
    assert settings.port == DEFAULT_PORT == 4444
    assert settings.verify_ssl is True
    assert settings.timeout == DEFAULT_TIMEOUT == 30.0
    assert settings.read_only_mode is False
    assert settings.ca_bundle is None
    assert settings.api_key_file is None
    assert settings.api_key.get_secret_value() == KEY
    assert settings.base_url == f"https://fw.example.com:4444{API_PATH_PREFIX}"


def test_from_env_all_fields(tmp_path: Path) -> None:
    ca_bundle = tmp_path / "sophos-ca.pem"
    ca_bundle.write_text("-----BEGIN CERTIFICATE-----\n", encoding="utf-8")

    settings = Settings.from_env(
        env(
            SOPHOS_PORT="8443",
            SOPHOS_VERIFY_SSL="true",
            SOPHOS_TIMEOUT="12.5",
            SOPHOS_READ_ONLY_MODE="true",
        )
        | {"SOPHOS_CA_BUNDLE": str(ca_bundle)}
    )

    assert settings.port == 8443
    assert settings.timeout == 12.5
    assert settings.read_only_mode is True
    assert settings.ca_bundle == ca_bundle
    assert settings.tls_verify == str(ca_bundle)


def test_from_env_reads_os_environ_when_mapping_is_omitted(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SOPHOS_HOST", "10.10.10.1")
    monkeypatch.setenv("SOPHOS_API_KEY", KEY)

    settings = Settings.from_env()

    assert settings.host == "10.10.10.1"
    assert settings.base_url == f"https://10.10.10.1:4444{API_PATH_PREFIX}"


def test_explicit_mapping_wins_over_os_environ(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SOPHOS_HOST", "wrong.example.com")
    monkeypatch.setenv("SOPHOS_API_KEY", "wrong-key")

    settings = Settings.from_env(env(SOPHOS_HOST="right.example.com"))

    assert settings.host == "right.example.com"
    assert settings.api_key.get_secret_value() == KEY


def test_from_env_does_not_mutate_os_environ() -> None:
    before = dict(os.environ)

    Settings.from_env(env())

    assert dict(os.environ) == before


def test_unrelated_environment_variables_are_ignored() -> None:
    settings = Settings.from_env(
        env(
            SOPHOS_EXTRA_SETTING="ignored",
            UNRELATED_SETTING="ignored",
        )
    )

    assert settings.base_url == f"https://fw.example.com:4444{API_PATH_PREFIX}"


def test_settings_expose_only_the_documented_fields() -> None:
    assert set(Settings.model_fields) == {
        "host",
        "port",
        "api_key",
        "api_key_file",
        "verify_ssl",
        "ca_bundle",
        "timeout",
        "read_only_mode",
        "max_concurrency",
    }


def test_blank_optional_values_use_defaults() -> None:
    settings = Settings.from_env(
        env(
            SOPHOS_PORT="",
            SOPHOS_TIMEOUT="",
            SOPHOS_VERIFY_SSL="",
            SOPHOS_READ_ONLY_MODE="",
            SOPHOS_MAX_CONCURRENCY="",
        )
    )

    assert settings.port == 4444
    assert settings.timeout == 30.0
    assert settings.verify_ssl is True
    assert settings.read_only_mode is False
    assert settings.max_concurrency == DEFAULT_MAX_CONCURRENCY == 4


def test_optional_boolean_and_numeric_values_are_stripped() -> None:
    settings = Settings.from_env(
        env(
            SOPHOS_PORT=" 8443 ",
            SOPHOS_VERIFY_SSL=" false ",
            SOPHOS_TIMEOUT=" 12.5 ",
            SOPHOS_READ_ONLY_MODE=" true ",
        )
    )

    assert settings.port == 8443
    assert settings.timeout == 12.5
    assert settings.verify_ssl is False
    assert settings.read_only_mode is True


def test_optional_paths_and_inline_key_are_stripped(tmp_path: Path) -> None:
    ca_bundle = tmp_path / "ca.pem"
    ca_bundle.write_text("cert", encoding="utf-8")
    key_file = tmp_path / "key"
    key_file.write_text("file-secret\n", encoding="utf-8")

    settings = Settings.from_env(
        {
            "SOPHOS_HOST": "fw.example.com",
            "SOPHOS_API_KEY_FILE": f"  {key_file}  ",
            "SOPHOS_CA_BUNDLE": f"  {ca_bundle}  ",
        }
    )

    assert settings.api_key.get_secret_value() == "file-secret"
    assert settings.api_key_file == key_file
    assert settings.ca_bundle == ca_bundle


def test_inline_api_key_is_stripped() -> None:
    settings = Settings.from_env(env(SOPHOS_API_KEY="  inline-secret  "))

    assert settings.api_key.get_secret_value() == "inline-secret"


def test_whitespace_only_api_key_is_treated_as_missing() -> None:
    with pytest.raises(ConfigurationError) as info:
        Settings.from_env({"SOPHOS_HOST": "fw.example.com", "SOPHOS_API_KEY": "   "})

    assert "SOPHOS_API_KEY" in str(info.value)
    assert info.value.__cause__ is None


# -- API key sources ---------------------------------------------------------


def test_missing_credentials_is_rejected() -> None:
    with pytest.raises(ConfigurationError) as info:
        Settings.from_env({"SOPHOS_HOST": "fw.example.com"})

    message = str(info.value)
    assert "SOPHOS_API_KEY" in message
    assert "SOPHOS_API_KEY_FILE" in message
    assert info.value.__cause__ is None


def test_both_credential_sources_are_mutually_exclusive(tmp_path: Path) -> None:
    key_file = tmp_path / "key"
    key_file.write_text("file-secret", encoding="utf-8")

    with pytest.raises(ConfigurationError) as info:
        Settings.from_env(env(SOPHOS_API_KEY_FILE=str(key_file)))

    message = str(info.value)
    assert "mutually exclusive" in message
    assert KEY not in message
    assert "file-secret" not in message


def test_api_key_file_is_read_and_stripped(tmp_path: Path) -> None:
    key_file = tmp_path / "key"
    key_file.write_text("  file-secret-value\n\n", encoding="utf-8")

    settings = Settings.from_env(
        {"SOPHOS_HOST": "fw.example.com", "SOPHOS_API_KEY_FILE": str(key_file)}
    )

    assert settings.api_key.get_secret_value() == "file-secret-value"
    assert settings.api_key_file == key_file


def test_missing_api_key_file_is_rejected(tmp_path: Path) -> None:
    missing = tmp_path / "missing-key"

    with pytest.raises(ConfigurationError) as info:
        Settings.from_env({"SOPHOS_HOST": "fw.example.com", "SOPHOS_API_KEY_FILE": str(missing)})

    assert str(missing) in str(info.value)
    assert info.value.__cause__ is None


def test_empty_api_key_file_is_rejected(tmp_path: Path) -> None:
    key_file = tmp_path / "key"
    key_file.write_text("  \n\n", encoding="utf-8")

    with pytest.raises(ConfigurationError) as info:
        Settings.from_env({"SOPHOS_HOST": "fw.example.com", "SOPHOS_API_KEY_FILE": str(key_file)})

    assert "empty" in str(info.value)


# -- Host validation ---------------------------------------------------------


@pytest.mark.parametrize(
    "host",
    [
        "",
        " ",
        " fw.example.com",
        "fw.example.com ",
        "fw example.com",
        "fw\texample.com",
        "https://fw.example.com",
        "http://10.0.0.1",
        "fw.example.com:4444",
        "user@fw.example.com",
        "fw.example.com/path",
        "fw.example.com?page=1",
        "fw.example.com#fragment",
        "fw.example.com\\path",
        "[::1]",
        "fe80::1%eth0",
        "bad_host",
        "-fw.example.com",
        "fw-.example.com",
        "fw..example.com",
        "fw.example.com.",
        ".",
        "..",
        "10.0.0.1/24",
        "a" * 64,
        "f" * 254,
        "münchen.example.com",
    ],
)
def test_invalid_host_is_rejected(host: str) -> None:
    with pytest.raises(ConfigurationError) as info:
        Settings.from_env({"SOPHOS_HOST": host, "SOPHOS_API_KEY": KEY})

    assert KEY not in str(info.value)
    assert KEY not in repr(info.value)


@pytest.mark.parametrize(
    ("host", "expected_base_url"),
    [
        ("10.0.0.1", f"https://10.0.0.1:4444{API_PATH_PREFIX}"),
        ("fw", f"https://fw:4444{API_PATH_PREFIX}"),
        ("fw.example.com", f"https://fw.example.com:4444{API_PATH_PREFIX}"),
        ("FW.EXAMPLE.COM", f"https://FW.EXAMPLE.COM:4444{API_PATH_PREFIX}"),
        ("xn--mnchen-3ya.example", f"https://xn--mnchen-3ya.example:4444{API_PATH_PREFIX}"),
        ("2001:db8::1", f"https://[2001:db8::1]:4444{API_PATH_PREFIX}"),
        ("::1", f"https://[::1]:4444{API_PATH_PREFIX}"),
    ],
)
def test_valid_host_is_accepted(host: str, expected_base_url: str) -> None:
    settings = Settings.from_env({"SOPHOS_HOST": host, "SOPHOS_API_KEY": KEY})

    assert settings.base_url == expected_base_url


def test_host_must_not_include_a_port() -> None:
    with pytest.raises(ConfigurationError) as info:
        Settings.from_env({"SOPHOS_HOST": "10.0.0.1:4444", "SOPHOS_API_KEY": KEY})

    assert "SOPHOS_PORT" in str(info.value)


# -- Port, timeout, TLS ------------------------------------------------------


@pytest.mark.parametrize("port", ["0", "65536", "-1", "abc", "4444.5"])
def test_invalid_port_is_rejected(port: str) -> None:
    with pytest.raises(ConfigurationError) as info:
        Settings.from_env(env(SOPHOS_PORT=port))

    assert KEY not in str(info.value)


@pytest.mark.parametrize("port", ["1", "4444", "65535"])
def test_valid_port_is_accepted(port: str) -> None:
    assert Settings.from_env(env(SOPHOS_PORT=port)).port == int(port)


@pytest.mark.parametrize("timeout", ["0", "-1", "abc", "nan", "inf", "-inf"])
def test_invalid_timeout_is_rejected(timeout: str) -> None:
    with pytest.raises(ConfigurationError) as info:
        Settings.from_env(env(SOPHOS_TIMEOUT=timeout))

    assert KEY not in str(info.value)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("true", True),
        ("TRUE", True),
        ("1", True),
        ("yes", True),
        ("on", True),
        ("false", False),
        ("FALSE", False),
        ("0", False),
        ("no", False),
        ("off", False),
    ],
)
def test_verify_ssl_parsing(raw: str, expected: bool) -> None:
    assert Settings.from_env(env(SOPHOS_VERIFY_SSL=raw)).verify_ssl is expected


def test_invalid_verify_ssl_is_rejected() -> None:
    with pytest.raises(ConfigurationError) as info:
        Settings.from_env(env(SOPHOS_VERIFY_SSL="maybe"))

    assert "verify_ssl" in str(info.value)
    assert KEY not in str(info.value)


def test_invalid_read_only_mode_is_rejected() -> None:
    with pytest.raises(ConfigurationError):
        Settings.from_env(env(SOPHOS_READ_ONLY_MODE="sometimes"))


def test_missing_ca_bundle_is_rejected(tmp_path: Path) -> None:
    missing = tmp_path / "missing-ca.pem"

    with pytest.raises(ConfigurationError) as info:
        Settings.from_env(env() | {"SOPHOS_CA_BUNDLE": str(missing)})

    assert str(missing) in str(info.value)


def test_ca_bundle_cannot_be_combined_with_verification_off(tmp_path: Path) -> None:
    ca_bundle = tmp_path / "ca.pem"
    ca_bundle.write_text("cert", encoding="utf-8")

    with pytest.raises(ConfigurationError) as info:
        Settings.from_env(env(SOPHOS_VERIFY_SSL="false") | {"SOPHOS_CA_BUNDLE": str(ca_bundle)})

    message = str(info.value)
    assert "SOPHOS_CA_BUNDLE" in message
    assert "SOPHOS_VERIFY_SSL" in message
    assert KEY not in message


def test_verify_ssl_false_is_allowed_without_ca_bundle() -> None:
    settings = Settings.from_env(env(SOPHOS_VERIFY_SSL="false"))

    assert settings.verify_ssl is False
    assert settings.tls_verify is False


# -- Concurrency bound -------------------------------------------------------


def test_max_concurrency_defaults_to_four() -> None:
    """L3: the shared client is bounded by default, without any configuration."""
    settings = Settings.from_env(env())

    assert settings.max_concurrency == DEFAULT_MAX_CONCURRENCY == 4


@pytest.mark.parametrize("raw", ["1", "2", "8", "64"])
def test_max_concurrency_is_read_from_env(raw: str) -> None:
    assert Settings.from_env(env(SOPHOS_MAX_CONCURRENCY=raw)).max_concurrency == int(raw)


def test_max_concurrency_is_stripped_like_every_other_optional_value() -> None:
    assert Settings.from_env(env(SOPHOS_MAX_CONCURRENCY=" 3 ")).max_concurrency == 3


@pytest.mark.parametrize("raw", ["0", "-1", "65", "1000"])
def test_out_of_range_max_concurrency_is_rejected(raw: str) -> None:
    """The setting exists to bound concurrency, so it cannot be set to "unbounded"."""
    with pytest.raises(ConfigurationError) as info:
        Settings.from_env(env(SOPHOS_MAX_CONCURRENCY=raw))

    message = str(info.value)
    assert "max_concurrency" in message
    assert str(MAX_CONCURRENCY_LIMIT) in message
    assert KEY not in message


@pytest.mark.parametrize("raw", ["abc", "2.5", "four"])
def test_non_integer_max_concurrency_is_rejected(raw: str) -> None:
    with pytest.raises(ConfigurationError) as info:
        Settings.from_env(env(SOPHOS_MAX_CONCURRENCY=raw))

    assert "max_concurrency" in str(info.value)
    assert KEY not in str(info.value)


def test_max_concurrency_is_validated_on_direct_construction() -> None:
    with pytest.raises(ValidationError):
        Settings(host="fw.example.com", api_key=KEY, max_concurrency=0)


# -- Secret handling ---------------------------------------------------------


def test_repr_and_serialization_never_contain_the_key() -> None:
    settings = Settings.from_env(env())

    rendered = [
        repr(settings),
        str(settings),
        settings.model_dump_json(),
        repr(settings.model_dump()),
        repr(list(settings.model_dump().values())),
    ]
    for text in rendered:
        assert KEY not in text
    assert "**********" in repr(settings)


def test_validation_errors_never_contain_the_key() -> None:
    with pytest.raises(ConfigurationError) as info:
        Settings.from_env({"SOPHOS_HOST": "https://not-a-host", "SOPHOS_API_KEY": KEY})

    assert KEY not in str(info.value)
    assert KEY not in repr(info.value)
    assert info.value.__cause__ is None


def test_direct_construction_redacts_the_key() -> None:
    settings = Settings(host="fw.example.com", api_key=KEY)

    assert KEY not in repr(settings)
    assert settings.api_key.get_secret_value() == KEY


@pytest.mark.parametrize("api_key", ["", "   ", "\n\t "])
def test_direct_construction_rejects_an_empty_api_key(api_key: str) -> None:
    with pytest.raises(ValidationError) as info:
        Settings(host="fw.example.com", api_key=api_key)

    assert "api_key" in str(info.value)


def test_direct_construction_strips_api_key_whitespace() -> None:
    settings = Settings(host="fw.example.com", api_key="  direct-secret  ")

    assert settings.api_key.get_secret_value() == "direct-secret"
    assert "direct-secret" not in repr(settings)


def test_unknown_fields_are_rejected() -> None:
    with pytest.raises(ValidationError):
        Settings(host="fw.example.com", api_key=KEY, username="admin")  # type: ignore[call-arg]
