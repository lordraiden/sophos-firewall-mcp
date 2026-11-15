"""Confirmation before the highest-blast-radius deletes (MCP standards review, L4).

The four deletes that can take a firewall rule, a NAT rule, a network-user account or a
VLAN interface away ask the client to confirm first, through the SDK's elicitation support
(``Context.elicit``, ``mcp`` 2.3.0). The affordance is additive: a client that cannot be
asked -- no ``elicitation`` capability, or a transport with no back-channel for
server-initiated requests -- keeps the previous behaviour, so a non-interactive client is
never broken.

Two layers are covered:

* the :func:`~sophos_firewall_mcp.tools.confirm_destructive` helper in isolation, with a
  stub context, for every outcome the SDK can report (accept/decline/cancel, no
  capability, no back-channel, an unusable answer);
* the four handlers end to end over the in-memory transport, proving that a declined
  confirmation sends **no** HTTP request at all and that an accepted one does.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest
import respx
from mcp import Client, types
from mcp.server.elicitation import (
    AcceptedElicitation,
    CancelledElicitation,
    DeclinedElicitation,
)
from mcp.server.mcpserver.exceptions import ToolError
from mcp.shared.exceptions import NoBackChannelError
from mcp.types import (
    ClientCapabilities,
    ElicitationCapability,
    FormElicitationCapability,
)
from pydantic import BaseModel

from sophos_firewall_mcp.config import Settings
from sophos_firewall_mcp.server import create_server
from sophos_firewall_mcp.tools import confirm_destructive

HOST = "192.0.2.10"
KEY = "sfos_test_key_0123456789abcdef"
BASE = f"https://{HOST}:4444/api/firewall-config/v1"

#: The four tools the confirmation gates, with a request that reaches the delete.
GATED: dict[str, dict[str, Any]] = {
    "firewall_rule_delete": {"ip_family": "ipv4", "id_or_name": "allow-lan-to-wan"},
    "nat_rule_delete": {"ip_family": "ipv4", "id_or_name": "masq-lan"},
    "network_user_delete": {"id_or_name": "jdoe"},
    "network_interface_delete_vlan": {"id_or_name": "VLAN 20"},
}

#: The DELETE path each gated tool would hit, so a test can prove it was not hit.
DELETE_PATHS: dict[str, str] = {
    "firewall_rule_delete": f"{BASE}/firewall/rules/ipv4/allow-lan-to-wan",
    "nat_rule_delete": f"{BASE}/nat/rules/ipv4/masq-lan",
    "network_user_delete": f"{BASE}/authentication/users/network-users/jdoe",
    "network_interface_delete_vlan": f"{BASE}/network/interfaces/network-interfaces/VLAN%2020",
}

#: The pre-read ``network_interface_delete_vlan`` performs before the delete.
INTERFACE_ITEM = f"{BASE}/network/interfaces/network-interfaces/VLAN%2020"


class _Answer(BaseModel):
    """The shape the helper's schema validates an accepted answer into."""

    confirm: bool


def make_settings() -> Settings:
    return Settings(
        host=HOST,
        port=4444,
        api_key=KEY,
        verify_ssl=False,
        timeout=5.0,
        read_only_mode=False,
    )


def make_server() -> Any:
    return create_server(make_settings())


@pytest.fixture
def router() -> Any:
    with respx.mock(assert_all_called=False) as mocked:
        yield mocked


# -- The helper in isolation -----------------------------------------------------------


class _StubContext:
    """The two attributes :func:`confirm_destructive` reads, and nothing else."""

    def __init__(self, capabilities: ClientCapabilities | None, outcome: Any) -> None:
        self.client_capabilities = capabilities
        self._outcome = outcome
        self.asked: list[tuple[str, type[BaseModel]]] = []

    async def elicit(self, message: str, schema: type[BaseModel]) -> Any:
        self.asked.append((message, schema))
        if isinstance(self._outcome, BaseException):
            raise self._outcome
        return self._outcome


def _capabilities(*, form: bool = True) -> ClientCapabilities:
    return ClientCapabilities(
        elicitation=ElicitationCapability(form=FormElicitationCapability() if form else None)
    )


async def test_no_capabilities_keeps_the_previous_behaviour() -> None:
    """A client that declared nothing is never asked and never blocked."""
    ctx = _StubContext(None, AcceptedElicitation(data=_Answer(confirm=True)))

    await confirm_destructive(ctx, action="delete the firewall rule", target="'r'")

    assert ctx.asked == []


async def test_a_client_without_the_elicitation_capability_is_not_asked() -> None:
    ctx = _StubContext(ClientCapabilities(), AcceptedElicitation(data=_Answer(confirm=True)))

    await confirm_destructive(ctx, action="delete the firewall rule", target="'r'")

    assert ctx.asked == []


async def test_a_client_without_the_form_mode_is_not_asked() -> None:
    """``url``-only elicitation cannot answer a boolean question."""
    ctx = _StubContext(_capabilities(form=False), AcceptedElicitation(data=_Answer(confirm=True)))

    await confirm_destructive(ctx, action="delete the firewall rule", target="'r'")

    assert ctx.asked == []


async def test_an_accepted_confirmation_returns() -> None:
    ctx = _StubContext(_capabilities(), AcceptedElicitation(data=_Answer(confirm=True)))

    await confirm_destructive(ctx, action="delete the firewall rule", target="'r'")

    assert len(ctx.asked) == 1


async def test_the_question_names_the_object_and_the_irreversibility() -> None:
    ctx = _StubContext(_capabilities(), AcceptedElicitation(data=_Answer(confirm=True)))

    await confirm_destructive(
        ctx,
        action="delete the firewall rule",
        target="'allow-lan-to-wan' from the ipv4 rule base",
    )

    message, schema = ctx.asked[0]
    assert "delete the firewall rule" in message
    assert "'allow-lan-to-wan' from the ipv4 rule base" in message
    assert "irreversible" in message
    # The schema is the single boolean the client answers with.
    assert set(schema.model_fields) == {"confirm"}


async def test_a_rejected_confirmation_aborts() -> None:
    ctx = _StubContext(_capabilities(), AcceptedElicitation(data=_Answer(confirm=False)))

    with pytest.raises(ToolError) as caught:
        await confirm_destructive(ctx, action="delete the firewall rule", target="'r'")

    assert "not confirmed" in str(caught.value)
    assert "nothing was changed" in str(caught.value)


async def test_a_declined_confirmation_aborts() -> None:
    ctx = _StubContext(_capabilities(), DeclinedElicitation())

    with pytest.raises(ToolError) as caught:
        await confirm_destructive(ctx, action="delete the firewall rule", target="'r'")

    assert "declined" in str(caught.value)


async def test_a_cancelled_confirmation_aborts() -> None:
    ctx = _StubContext(_capabilities(), CancelledElicitation())

    with pytest.raises(ToolError) as caught:
        await confirm_destructive(ctx, action="delete the firewall rule", target="'r'")

    assert "cancelled" in str(caught.value)


async def test_an_unusable_answer_aborts() -> None:
    """An ``accept`` with no content is not a confirmation."""
    ctx = _StubContext(_capabilities(), ValueError("Received an accepted elicitation"))

    with pytest.raises(ToolError) as caught:
        await confirm_destructive(ctx, action="delete the firewall rule", target="'r'")

    assert "not confirmed" in str(caught.value)


async def test_a_transport_without_a_back_channel_keeps_the_previous_behaviour() -> None:
    """The modern per-request path cannot carry a server-initiated request."""
    ctx = _StubContext(_capabilities(), NoBackChannelError("elicitation/create"))

    await confirm_destructive(ctx, action="delete the firewall rule", target="'r'")

    assert len(ctx.asked) == 1


# -- The four handlers, end to end -----------------------------------------------------


def _elicitation_callback(action: str, confirm: bool | None = None) -> Any:
    async def callback(context: Any, params: types.ElicitRequestParams) -> types.ElicitResult:
        if action == "accept":
            return types.ElicitResult(action="accept", content={"confirm": confirm})
        return types.ElicitResult(action=action)

    return callback


def _mock_delete(router: Any, name: str) -> Any:
    """Mock the HTTP the tool would perform once the confirmation is accepted."""
    if name == "network_interface_delete_vlan":
        router.get(INTERFACE_ITEM).mock(
            return_value=httpx.Response(200, json={"name": "VLAN 20", "type": "vlan"})
        )
    return router.delete(DELETE_PATHS[name]).mock(
        return_value=httpx.Response(200, json={"deleted": True})
    )


@pytest.mark.parametrize("name", sorted(GATED))
async def test_a_declined_confirmation_sends_no_request(router: Any, name: str) -> None:
    """The whole point: a declined answer must not reach the appliance."""
    async with Client(
        make_server(), mode="legacy", elicitation_callback=_elicitation_callback("decline")
    ) as client:
        result = await client.call_tool(name, GATED[name])

    assert result.is_error is True
    assert "declined" in result.content[0].text
    assert router.calls == []


@pytest.mark.parametrize("name", sorted(GATED))
async def test_a_cancelled_confirmation_sends_no_request(router: Any, name: str) -> None:
    async with Client(
        make_server(), mode="legacy", elicitation_callback=_elicitation_callback("cancel")
    ) as client:
        result = await client.call_tool(name, GATED[name])

    assert result.is_error is True
    assert "cancelled" in result.content[0].text
    assert router.calls == []


@pytest.mark.parametrize("name", sorted(GATED))
async def test_an_accepted_confirmation_performs_the_delete(router: Any, name: str) -> None:
    route = _mock_delete(router, name)

    async with Client(
        make_server(),
        mode="legacy",
        elicitation_callback=_elicitation_callback("accept", confirm=True),
    ) as client:
        result = await client.call_tool(name, GATED[name])

    assert result.is_error is False, result.content[0].text
    assert route.called
    assert route.calls.last.request.method == "DELETE"


@pytest.mark.parametrize("name", sorted(GATED))
async def test_a_client_without_elicitation_keeps_the_previous_behaviour(
    router: Any, name: str
) -> None:
    """No capability declared: the delete runs exactly as it did before the gate existed."""
    route = _mock_delete(router, name)

    async with Client(make_server()) as client:
        result = await client.call_tool(name, GATED[name])

    assert result.is_error is False, result.content[0].text
    assert route.called


@pytest.mark.parametrize("name", sorted(GATED))
async def test_a_modern_transport_falls_back_instead_of_failing(router: Any, name: str) -> None:
    """The client declares elicitation but the modern path cannot deliver the question.

    ``mcp`` 2.3.0 refuses a standalone server-to-client request on the modern per-request
    path, so the handler must fall back instead of failing the delete.
    """
    route = _mock_delete(router, name)

    async with Client(
        make_server(),
        elicitation_callback=_elicitation_callback("accept", confirm=True),
    ) as client:
        result = await client.call_tool(name, GATED[name])

    assert result.is_error is False, result.content[0].text
    assert route.called


async def test_the_gated_tools_are_the_four_highest_blast_radius_deletes() -> None:
    """Pin the scope: adding or dropping a gated tool must be a deliberate edit."""
    names = {tool.name for tool in await make_server().list_tools()}

    assert set(GATED) <= names
    assert set(GATED) == {
        "firewall_rule_delete",
        "nat_rule_delete",
        "network_interface_delete_vlan",
        "network_user_delete",
    }
