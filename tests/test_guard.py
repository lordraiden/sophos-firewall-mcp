"""No tool failure may reach the client without a name (issue #21).

The MCP SDK formats a tool error as ``Error executing tool <name>: <exc>``. ``str(TimeoutError())`` and
``str(asyncio.CancelledError())`` are both ``''``, so an unguarded failure arrives as a colon and nothing
else -- which is what made this server's intermittent failures look like a dead process and then like a
slow appliance, two wrong diagnoses in a row.
"""

import asyncio
import inspect
import logging

import pytest

from sophos_firewall_mcp._guard import guard_module_tools, guard_tool
from sophos_firewall_mcp.client import SophosAPIError


def test_unexpected_exception_is_named_and_logged(caplog):
    @guard_tool
    def tool() -> None:
        raise RuntimeError("the appliance returned something odd")

    with caplog.at_level(logging.ERROR), pytest.raises(SophosAPIError) as excinfo:
        tool()

    message = str(excinfo.value)
    assert "RuntimeError" in message
    assert "the appliance returned something odd" in message
    assert "tool failed unexpectedly" in caplog.text          # the traceback lands in the server log


def test_exception_with_empty_message_is_still_named():
    """The exact regression: a bare TimeoutError has str() == '', which used to become a blank error."""

    @guard_tool
    def tool() -> None:
        raise TimeoutError()

    with pytest.raises(SophosAPIError) as excinfo:
        tool()

    message = str(excinfo.value)
    assert message.strip()
    assert "TimeoutError" in message
    assert "no message" in message


@pytest.mark.asyncio
async def test_async_tool_is_named_too(caplog):
    @guard_tool
    async def tool() -> None:
        raise KeyError  # a KeyError with no argument stringifies to ''

    with caplog.at_level(logging.ERROR), pytest.raises(SophosAPIError) as excinfo:
        await tool()

    assert "KeyError" in str(excinfo.value)


@pytest.mark.asyncio
async def test_cancellation_propagates_untouched():
    """Converting a cancellation would hide it from the SDK and from the caller."""

    @guard_tool
    async def tool() -> None:
        raise asyncio.CancelledError()

    with pytest.raises(asyncio.CancelledError):
        await tool()


def test_domain_errors_keep_their_own_text():
    """SophosAPIError already carries a message; wrapping it again would nest two prefixes."""

    @guard_tool
    def tool() -> None:
        raise SophosAPIError("Sophos API Error 526: Record does not exist")

    with pytest.raises(SophosAPIError) as excinfo:
        tool()

    assert str(excinfo.value) == "Sophos API Error 526: Record does not exist"


def test_wrapper_preserves_the_signature_the_sdk_needs():
    """The SDK builds each tool's JSON schema from the signature; functools.wraps must keep it."""

    @guard_tool
    def tool(client: object = None, limit: int = 10) -> str:
        """List things."""
        return "ok"

    assert tool.__name__ == "tool"
    assert tool.__doc__ == "List things."
    params = list(inspect.signature(tool).parameters)
    assert params == ["client", "limit"]


def test_guarding_twice_is_a_no_op():
    @guard_tool
    def tool() -> str:
        return "ok"

    assert guard_tool(tool) is tool


def test_guard_module_tools_wraps_only_the_tool_functions():
    class FakeModule:
        def sophos_thing(self) -> str:      # noqa: D401 - stand-in for a tool
            return "ok"

        def helper(self) -> str:
            return "not a tool"

    module = FakeModule()
    assert guard_module_tools([module]) == 1
    assert getattr(module.sophos_thing, "__sophos_guarded__", False) is True
    assert getattr(module.helper, "__sophos_guarded__", False) is False


def test_every_registered_tool_is_guarded():
    """The wiring check: an unguarded tool is a tool that can still fail silently.

    Enumerates what the SDK actually registered (41 today) and proves each one is wrapped, so adding a
    tool without the guard fails here instead of surfacing months later as another blank error.
    """
    import asyncio

    from sophos_firewall_mcp import server
    from sophos_firewall_mcp.tools import (
        firewall_rules,
        hosts_objects,
        nat_rules,
        raw_api,
        services_objects,
        system,
        users_auth,
        vpn,
    )

    guarded = {}
    for module in (firewall_rules, hosts_objects, nat_rules, raw_api, services_objects, system,
                   users_auth, vpn):
        for name in dir(module):
            fn = getattr(module, name)
            if name.startswith("sophos_") and callable(fn):
                guarded[name] = getattr(fn, "__sophos_guarded__", False)
    # The two routing tools are defined in server.py, not in a tools module.
    guarded["route_tools"] = getattr(server.route_tools, "__sophos_guarded__", False)
    guarded["call_routed_tool"] = getattr(server.call_routed_tool, "__sophos_guarded__", False)

    registered = [t.name for t in asyncio.run(server.mcp.list_tools())]
    assert registered, "no tools registered at all"
    unguarded = [name for name in registered if not guarded.get(name)]
    assert unguarded == [], f"registered but not guarded: {unguarded}"
    assert server._GUARDED_TOOLS >= 39
