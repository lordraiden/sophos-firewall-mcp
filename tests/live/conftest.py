"""Live (opt-in) appliance verification for the read-only surface.

These tests are skipped unless the lab connection is configured, exactly as
``docs/live-evidence/README.md`` requires:

* ``SOPHOS_HOST``
* ``SOPHOS_PORT``
* ``SOPHOS_API_KEY`` or ``SOPHOS_API_KEY_FILE`` (exactly one source)

They are marked ``live`` and are **read-only by construction**: the server is built with
``read_only_mode=True``, so the 54 mutation tools are never registered and cannot be
called even by mistake. The suite asserts that invariant before it calls anything.

Run them with::

    SOPHOS_HOST=10.10.10.1 SOPHOS_PORT=443 \\
    SOPHOS_API_KEY="<read-only key>" SOPHOS_VERIFY_SSL=false \\
    uv run pytest -m live -q

The default run (``uv run pytest -q``) skips every test in this directory.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import pytest
from mcp import Client

from sophos_firewall_mcp.config import Settings
from sophos_firewall_mcp.server import create_server

#: The lab key is read-only; a live run must never be able to register a mutation tool.
EXPECTED_LIVE_TOOL_COUNT = 98

_LIVE_READY = bool(
    os.getenv("SOPHOS_HOST")
    and os.getenv("SOPHOS_PORT")
    and (os.getenv("SOPHOS_API_KEY") or os.getenv("SOPHOS_API_KEY_FILE"))
)

live = pytest.mark.skipif(
    not _LIVE_READY,
    reason="live appliance credentials are not configured (SOPHOS_HOST/PORT/API_KEY)",
)


def live_settings() -> Settings:
    """Settings from the environment, forced into read-only mode.

    ``read_only_mode=True`` is not configurable here: the lab key is read-only and the
    suite must not be able to register a mutation tool even if the environment says
    otherwise. ``Settings.from_env`` resolves the key source (env or file) and validates
    the rest exactly as the server does at startup.
    """
    return Settings.from_env().model_copy(update={"read_only_mode": True})


@asynccontextmanager
async def open_live_client() -> AsyncIterator[Client]:
    """The real server, read-only, connected to the lab appliance."""
    async with Client(create_server(live_settings())) as client:
        yield client


async def assert_read_only_surface(client: Client) -> None:
    """Assert the no-mutation invariant before any live call is made.

    The MCP client owns anyio task groups, so it must be entered and exited in the same
    task as the test body: the tests use :func:`open_live_client` directly instead of a
    pytest fixture, which would run the teardown in a different task.
    """
    tools = (await client.list_tools()).tools
    assert (
        len(tools) == EXPECTED_LIVE_TOOL_COUNT
    ), f"the read-only server must publish {EXPECTED_LIVE_TOOL_COUNT} tools, got {len(tools)}"
    for tool in tools:
        assert tool.annotations is not None, tool.name
        assert tool.annotations.read_only_hint is True, tool.name
