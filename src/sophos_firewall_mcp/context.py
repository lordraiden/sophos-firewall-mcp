"""Shared application context for the Sophos Firewall MCP server.

The context is created exactly once per process by the MCP lifespan in
:mod:`sophos_firewall_mcp.server` and is the only way a tool handler obtains the shared
REST client. Domain modules (#27-#31) import :class:`AppContext` from here instead of
redefining it, importing the client constructor, or creating a client per tool call.

The SDK injects a typed ``Context`` into every handler; the application context lives at
``ctx.request_context.lifespan_context``::

    from mcp.server.mcpserver import Context

    from sophos_firewall_mcp.context import AppContext

    async def list_rules(request: ListRulesInput, ctx: Context[AppContext]) -> ListRulesOutput:
        app = ctx.request_context.lifespan_context
        payload = await app.client.get("/firewall/rules/ipv4")
        ...
"""

from __future__ import annotations

from dataclasses import dataclass

from .client import SophosRestClient
from .config import Settings

__all__ = ["AppContext"]


@dataclass(frozen=True, slots=True)
class AppContext:
    """Validated configuration plus the one REST client shared by every tool call.

    Attributes:
        client: The single :class:`~sophos_firewall_mcp.client.SophosRestClient` created
            by the MCP lifespan. It owns one HTTP connection pool for the whole process;
            handlers and domain adapters must reuse it and never construct another one.
        settings: The validated :class:`~sophos_firewall_mcp.config.Settings` the client
            and the registered tool set were built from. The API key is a ``SecretStr``
            and must never be logged, echoed in tool output or placed in an error message.
        read_only: ``True`` when ``SOPHOS_READ_ONLY_MODE`` was enabled at startup. In that
            mode mutation tools are not registered at all; domain adapters may also use
            this flag to refuse a write defensively.

    The dataclass is frozen: the lifespan builds it once and every handler sees the same
    instance, which is what makes the client identity stable across tool calls.
    """

    client: SophosRestClient
    settings: Settings
    read_only: bool
