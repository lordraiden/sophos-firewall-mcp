"""Tests for the shared application context (issue #26).

The context is the contract #27-#31 import: one REST client, the validated settings and
the read-only flag, created once by the lifespan. These tests pin its shape and prove it
cannot be mutated or leak the API key through ``repr``.
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from typing import Any

import pytest

from sophos_firewall_mcp.client import SophosRestClient
from sophos_firewall_mcp.config import Settings
from sophos_firewall_mcp.context import AppContext


class _FakeClient:
    """Stand-in for the REST client when a test does not need an HTTP pool."""

    def __repr__(self) -> str:
        return "<fake SophosRestClient>"


def make_settings(**overrides: Any) -> Settings:
    """Build valid settings without touching the process environment."""
    values: dict[str, Any] = {
        "host": "192.0.2.10",
        "port": 4444,
        "api_key": "test-api-key",
        "verify_ssl": False,
        "timeout": 5.0,
        "read_only_mode": False,
    }
    values.update(overrides)
    return Settings(**values)


def test_app_context_exposes_the_three_fields():
    settings = make_settings(read_only_mode=True)
    client = _FakeClient()

    context = AppContext(client=client, settings=settings, read_only=True)  # type: ignore[arg-type]

    assert context.client is client
    assert context.settings is settings
    assert context.read_only is True
    assert context.settings.read_only_mode is True


def test_app_context_is_frozen():
    context = AppContext(client=_FakeClient(), settings=make_settings(), read_only=False)  # type: ignore[arg-type]

    with pytest.raises(FrozenInstanceError):
        context.read_only = True  # type: ignore[misc]


def test_app_context_repr_does_not_leak_the_api_key():
    context = AppContext(  # type: ignore[arg-type]
        client=_FakeClient(),
        settings=make_settings(api_key="super-secret-api-key"),
        read_only=False,
    )

    rendered = repr(context)

    assert "super-secret-api-key" not in rendered
    assert "192.0.2.10" in rendered


async def test_app_context_accepts_a_real_client_and_its_repr_is_safe():
    settings = make_settings(api_key="super-secret-api-key")
    client = SophosRestClient(settings)
    try:
        context = AppContext(client=client, settings=settings, read_only=False)

        assert context.client is client
        assert "super-secret-api-key" not in repr(context)
        assert "super-secret-api-key" not in repr(context.client)
    finally:
        await client.aclose()
