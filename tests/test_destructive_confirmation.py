"""Confirmation before the highest-blast-radius deletes (issue #54, MCP MRTR).

The four deletes that can take a firewall rule, a NAT rule, a network-user account or a
VLAN interface away require an explicit client confirmation before the appliance is
touched. The confirmation is a ``Resolve``-injected parameter, so the SDK asks the
question *before* the handler body runs:

* on the modern ``2026-07-28`` protocol the question is an ``InputRequiredResult`` round
  trip: the client answers and retries the same call with ``inputResponses`` and
  ``requestState``, and the SDK resumes the handler exactly once;
* on the legacy handshake the SDK sends the same question as a standalone elicitation.

The gate fails closed. A declined or cancelled answer, an ``accept`` that does not set
``confirm``, a client that declared no form-mode ``elicitation`` capability, and a
transport that cannot carry the question all abort the call before any HTTP request is
made. The SDK seals the resume state and binds it to the tool name, the canonical
arguments, the authenticated principal and a TTL, so a missing, malformed, expired or
mismatched state is rejected before the handler runs.

Two layers are covered:

* the :func:`~sophos_firewall_mcp.tools.destructive_confirmation` resolver and
  :func:`~sophos_firewall_mcp.tools.require_confirmation` in isolation, with a stub
  context, for every capability and outcome the SDK can report;
* the four handlers end to end over the in-memory transport, on both protocol eras,
  proving that a rejected or unanswerable confirmation sends **no** HTTP request and that
  an accepted one performs the delete only after the question was answered.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

import httpx
import pytest
import respx
from mcp import Client, MCPError, types
from mcp.server.elicitation import (
    AcceptedElicitation,
    CancelledElicitation,
    DeclinedElicitation,
)
from mcp.server.mcpserver import Context
from mcp.server.mcpserver.exceptions import ToolError
from mcp.server.mcpserver.resolve import Elicit
from mcp.shared.exceptions import NoBackChannelError
from mcp.types import (
    ClientCapabilities,
    ElicitationCapability,
    FormElicitationCapability,
    UrlElicitationCapability,
)
from pydantic import BaseModel

from sophos_firewall_mcp.config import Settings
from sophos_firewall_mcp import mrtr
from sophos_firewall_mcp.mrtr import consumed_state_count, reset_consumed_states
from sophos_firewall_mcp.server import create_server
from sophos_firewall_mcp.tools import (
    CONFIRMATION_NOTE,
    DestructiveConfirmation,
    destructive_confirmation,
    require_confirmation,
)

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


class _Request(BaseModel):
    """The request shape the resolver's target function reads."""

    name: str


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


@pytest.fixture(autouse=True)
def _fresh_replay_guard() -> None:
    """Every test starts with an empty single-use set."""
    reset_consumed_states()


# -- The resolver and the outcome check, in isolation ----------------------------------


class _StubContext:
    """The one attribute the resolver reads, and nothing else."""

    def __init__(self, capabilities: ClientCapabilities | None) -> None:
        self.client_capabilities = capabilities


def _capabilities(*, form: bool = True) -> ClientCapabilities:
    return ClientCapabilities(
        elicitation=ElicitationCapability(form=FormElicitationCapability() if form else None)
    )


def _url_only_capabilities() -> ClientCapabilities:
    """A client that declared ``url`` mode only: it cannot answer a boolean question."""
    return ClientCapabilities(elicitation=ElicitationCapability(url=UrlElicitationCapability()))


def _empty_elicitation_capabilities() -> ClientCapabilities:
    """The spec's backwards-compatible ``"elicitation": {}`` declaration."""
    return ClientCapabilities(elicitation=ElicitationCapability())


def _resolver() -> Any:
    return destructive_confirmation("delete the firewall rule", lambda request: f"{request.name!r}")


async def test_no_capabilities_fails_closed() -> None:
    """A client that declared nothing cannot confirm, so the delete must not proceed."""
    ctx = _StubContext(None)

    with pytest.raises(ToolError) as caught:
        await _resolver()(_Request(name="r"), ctx)

    assert "requires confirmation" in str(caught.value)
    assert "nothing was changed" in str(caught.value)


async def test_a_client_without_the_elicitation_capability_fails_closed() -> None:
    ctx = _StubContext(ClientCapabilities())

    with pytest.raises(ToolError) as caught:
        await _resolver()(_Request(name="r"), ctx)

    assert "requires confirmation" in str(caught.value)


async def test_a_client_without_the_form_mode_fails_closed() -> None:
    """``url``-only elicitation cannot answer a boolean question."""
    ctx = _StubContext(_url_only_capabilities())

    with pytest.raises(ToolError) as caught:
        await _resolver()(_Request(name="r"), ctx)

    assert "requires confirmation" in str(caught.value)


async def test_an_empty_elicitation_object_counts_as_form_mode() -> None:
    """M5: the spec defines ``"elicitation": {}`` as form-mode support, so the gate fires."""
    ctx = _StubContext(_empty_elicitation_capabilities())

    marker = await _resolver()(_Request(name="r"), ctx)

    assert isinstance(marker, Elicit)


async def test_the_question_names_the_object_and_the_irreversibility() -> None:
    ctx = _StubContext(_capabilities())

    marker = await _resolver()(_Request(name="allow-lan-to-wan"), ctx)

    assert isinstance(marker, Elicit)
    assert "delete the firewall rule" in marker.message
    assert "'allow-lan-to-wan'" in marker.message
    assert "irreversible" in marker.message
    # The schema is the single boolean the client answers with.
    assert set(marker.schema.model_fields) == {"confirm"}


def test_a_declined_outcome_aborts() -> None:
    with pytest.raises(ToolError) as caught:
        require_confirmation(DeclinedElicitation(), action="delete the firewall rule")

    assert "declined" in str(caught.value)
    assert "nothing was changed" in str(caught.value)


def test_a_cancelled_outcome_aborts() -> None:
    with pytest.raises(ToolError) as caught:
        require_confirmation(CancelledElicitation(), action="delete the firewall rule")

    assert "cancelled" in str(caught.value)


def test_an_accept_without_confirm_aborts() -> None:
    """An ``accept`` that does not set ``confirm`` is not a confirmation."""
    outcome = AcceptedElicitation(data=DestructiveConfirmation(confirm=False))

    with pytest.raises(ToolError) as caught:
        require_confirmation(outcome, action="delete the firewall rule")

    assert "not confirmed" in str(caught.value)


def test_an_accepted_confirmation_returns() -> None:
    outcome = AcceptedElicitation(data=DestructiveConfirmation(confirm=True))

    require_confirmation(outcome, action="delete the firewall rule")


def test_the_confirmation_schema_description_is_plain_prose() -> None:
    """L9: the client renders this description in a confirmation dialog.

    It must not leak the implementation note (a Sphinx role, "elicitation schemas are
    restricted to primitive properties") that belongs in a code comment.
    """
    description = DestructiveConfirmation.model_json_schema().get("description", "")

    assert description
    assert ":func:" not in description
    assert "Elicitation schemas" not in description
    assert "primitive" not in description


# -- The four handlers, end to end -----------------------------------------------------


def _elicitation_callback(
    action: str, confirm: bool | None = None, seen: list[str] | None = None
) -> Any:
    async def callback(context: Any, params: types.ElicitRequestParams) -> types.ElicitResult:
        if seen is not None:
            seen.append(params.message)
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


# -- Legacy handshake ------------------------------------------------------------------


@pytest.mark.parametrize("name", sorted(GATED))
async def test_a_legacy_declined_confirmation_sends_no_request(router: Any, name: str) -> None:
    """The whole point: a declined answer must not reach the appliance."""
    async with Client(
        make_server(), mode="legacy", elicitation_callback=_elicitation_callback("decline")
    ) as client:
        result = await client.call_tool(name, GATED[name])

    assert result.is_error is True
    assert "declined" in result.content[0].text
    assert router.calls == []


@pytest.mark.parametrize("name", sorted(GATED))
async def test_a_legacy_cancelled_confirmation_sends_no_request(router: Any, name: str) -> None:
    async with Client(
        make_server(), mode="legacy", elicitation_callback=_elicitation_callback("cancel")
    ) as client:
        result = await client.call_tool(name, GATED[name])

    assert result.is_error is True
    assert "cancelled" in result.content[0].text
    assert router.calls == []


@pytest.mark.parametrize("name", sorted(GATED))
async def test_a_legacy_accepted_confirmation_performs_the_delete(router: Any, name: str) -> None:
    route = _mock_delete(router, name)

    async with Client(
        make_server(),
        mode="legacy",
        elicitation_callback=_elicitation_callback("accept", confirm=True),
    ) as client:
        result = await client.call_tool(name, GATED[name])

    assert result.is_error is False, result.content[0].text
    assert route.call_count == 1
    assert route.calls.last.request.method == "DELETE"


@pytest.mark.parametrize("name", sorted(GATED))
async def test_a_legacy_transport_without_a_back_channel_fails_closed(
    router: Any, name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A legacy transport that cannot carry the question must not delete unconfirmed."""

    async def _no_back_channel(self: Any, message: str, schema: Any) -> Any:
        raise NoBackChannelError("elicitation/create")

    monkeypatch.setattr(Context, "elicit", _no_back_channel)

    async with Client(
        make_server(),
        mode="legacy",
        elicitation_callback=_elicitation_callback("accept", confirm=True),
    ) as client:
        with pytest.raises(MCPError):
            await client.call_tool(name, GATED[name])

    assert router.calls == []


# -- Modern 2026-07-28 protocol --------------------------------------------------------


@pytest.mark.parametrize("name", sorted(GATED))
async def test_a_modern_transport_asks_for_confirmation_and_resumes(router: Any, name: str) -> None:
    """The modern path must ask, then resume the same call exactly once."""
    route = _mock_delete(router, name)
    seen: list[str] = []

    async with Client(
        make_server(),
        elicitation_callback=_elicitation_callback("accept", confirm=True, seen=seen),
    ) as client:
        result = await client.call_tool(name, GATED[name])

    assert result.is_error is False, result.content[0].text
    assert len(seen) == 1, seen
    assert "Confirm:" in seen[0]
    assert "irreversible" in seen[0]
    assert route.call_count == 1
    assert route.calls.last.request.method == "DELETE"


@pytest.mark.parametrize("name", sorted(GATED))
async def test_a_modern_declined_confirmation_sends_no_request(router: Any, name: str) -> None:
    async with Client(
        make_server(), elicitation_callback=_elicitation_callback("decline")
    ) as client:
        result = await client.call_tool(name, GATED[name])

    assert result.is_error is True
    assert "declined" in result.content[0].text
    assert router.calls == []


@pytest.mark.parametrize("name", sorted(GATED))
async def test_a_modern_cancelled_confirmation_sends_no_request(router: Any, name: str) -> None:
    async with Client(
        make_server(), elicitation_callback=_elicitation_callback("cancel")
    ) as client:
        result = await client.call_tool(name, GATED[name])

    assert result.is_error is True
    assert "cancelled" in result.content[0].text
    assert router.calls == []


@pytest.mark.parametrize("name", sorted(GATED))
async def test_a_modern_accept_without_confirm_sends_no_request(router: Any, name: str) -> None:
    async with Client(
        make_server(), elicitation_callback=_elicitation_callback("accept", confirm=False)
    ) as client:
        result = await client.call_tool(name, GATED[name])

    assert result.is_error is True
    assert "not confirmed" in result.content[0].text
    assert router.calls == []


@pytest.mark.parametrize("name", sorted(GATED))
async def test_a_client_without_elicitation_fails_closed(router: Any, name: str) -> None:
    """No capability declared: the delete must not run unconfirmed."""
    async with Client(make_server()) as client:
        result = await client.call_tool(name, GATED[name])

    assert result.is_error is True
    assert "requires confirmation" in result.content[0].text
    assert router.calls == []


@pytest.mark.parametrize("name", sorted(GATED))
async def test_the_first_round_returns_input_required_and_sends_no_request(
    router: Any, name: str
) -> None:
    """The first round is a question, not a write: it must not reach the appliance."""
    async with Client(
        make_server(), elicitation_callback=_elicitation_callback("accept", confirm=True)
    ) as client:
        result = await client.session.call_tool(name, GATED[name], allow_input_required=True)

    assert isinstance(result, types.InputRequiredResult)
    assert result.request_state
    assert result.input_requests
    assert router.calls == []


@pytest.mark.parametrize("name", sorted(GATED))
async def test_a_mismatched_target_is_rejected_before_the_handler(router: Any, name: str) -> None:
    """A resume for a different target must not reuse the confirmation."""
    async with Client(
        make_server(), elicitation_callback=_elicitation_callback("accept", confirm=True)
    ) as client:
        first = await client.session.call_tool(name, GATED[name], allow_input_required=True)
        assert isinstance(first, types.InputRequiredResult)

        other = dict(GATED[name])
        other["id_or_name"] = "some-other-object"
        with pytest.raises(MCPError) as rejected:
            await client.session.call_tool(
                name,
                other,
                allow_input_required=True,
                input_responses={},
                request_state=first.request_state,
            )

    assert rejected.value.code == types.INVALID_PARAMS
    assert router.calls == []


@pytest.mark.parametrize("name", sorted(GATED))
async def test_a_malformed_state_is_rejected_before_the_handler(router: Any, name: str) -> None:
    async with Client(make_server()) as client:
        with pytest.raises(MCPError) as rejected:
            await client.session.call_tool(
                name,
                GATED[name],
                allow_input_required=True,
                input_responses={},
                request_state="v1.not-a-real-token",
            )

    assert rejected.value.code == types.INVALID_PARAMS
    assert router.calls == []


@pytest.mark.parametrize("name", sorted(GATED))
async def test_an_expired_state_is_rejected_before_the_handler(
    router: Any, name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The sealed state carries a TTL; an expired resume must not execute the delete."""
    async with Client(
        make_server(), elicitation_callback=_elicitation_callback("accept", confirm=True)
    ) as client:
        first = await client.session.call_tool(name, GATED[name], allow_input_required=True)
        assert isinstance(first, types.InputRequiredResult)

        class _FutureTime:
            @staticmethod
            def time() -> float:
                # The default request-state TTL is 600 seconds.
                return 10**12

        monkeypatch.setattr("mcp.server.request_state.time", _FutureTime)

        with pytest.raises(MCPError) as rejected:
            await client.session.call_tool(
                name,
                GATED[name],
                allow_input_required=True,
                input_responses={},
                request_state=first.request_state,
            )

    assert rejected.value.code == types.INVALID_PARAMS
    assert router.calls == []


# -- Single-use request state ----------------------------------------------------------


@pytest.mark.parametrize("name", sorted(GATED))
async def test_a_replayed_confirmation_is_rejected_and_deletes_once(router: Any, name: str) -> None:
    """The same sealed state must not execute the delete twice.

    The first resume is the legitimate one and must be allowed; replaying the same
    ``requestState`` afterwards must be refused before the handler runs.
    """
    route = _mock_delete(router, name)

    async with Client(
        make_server(), elicitation_callback=_elicitation_callback("accept", confirm=True)
    ) as client:
        first = await client.session.call_tool(name, GATED[name], allow_input_required=True)
        assert isinstance(first, types.InputRequiredResult)
        key = next(iter(first.input_requests or {}))
        answer = types.ElicitResult(action="accept", content={"confirm": True})

        resumed = await client.session.call_tool(
            name,
            GATED[name],
            allow_input_required=True,
            input_responses={key: answer},
            request_state=first.request_state,
        )
        assert isinstance(resumed, types.CallToolResult)
        assert resumed.is_error is False, resumed.content[0].text
        assert route.call_count == 1

        with pytest.raises(MCPError) as rejected:
            await client.session.call_tool(
                name,
                GATED[name],
                allow_input_required=True,
                input_responses={key: answer},
                request_state=first.request_state,
            )

    assert rejected.value.code == types.INVALID_PARAMS
    assert "already used" in str(rejected.value)
    assert route.call_count == 1


@pytest.mark.parametrize("name", sorted(GATED))
async def test_a_fresh_confirmation_after_a_consumed_one_is_allowed(router: Any, name: str) -> None:
    """The guard is per-token, not per-target: a new confirmation still works."""
    route = _mock_delete(router, name)

    async with Client(
        make_server(), elicitation_callback=_elicitation_callback("accept", confirm=True)
    ) as client:
        for expected in (1, 2):
            first = await client.session.call_tool(name, GATED[name], allow_input_required=True)
            assert isinstance(first, types.InputRequiredResult)
            key = next(iter(first.input_requests or {}))
            resumed = await client.session.call_tool(
                name,
                GATED[name],
                allow_input_required=True,
                input_responses={
                    key: types.ElicitResult(action="accept", content={"confirm": True})
                },
                request_state=first.request_state,
            )
            assert isinstance(resumed, types.CallToolResult)
            assert resumed.is_error is False, resumed.content[0].text
            assert route.call_count == expected


# -- Flood and cap resistance ----------------------------------------------------------


async def test_a_forged_state_does_not_consume_a_slot(router: Any) -> None:
    """A state the boundary rejects must release its reservation, not fill the cap."""
    async with Client(make_server()) as client:
        with pytest.raises(MCPError):
            await client.session.call_tool(
                "firewall_rule_delete",
                GATED["firewall_rule_delete"],
                allow_input_required=True,
                input_responses={},
                request_state="v1.forged-token",
            )

    assert consumed_state_count() == 0
    assert router.calls == []


async def test_a_flood_of_forged_states_cannot_evict_a_legitimate_one(
    router: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The reviewer's bypass: forged states must not push the legitimate digest out."""
    monkeypatch.setattr(mrtr, "MAX_CONSUMED_STATES", 5)
    name = "firewall_rule_delete"
    args = GATED[name]
    route = _mock_delete(router, name)

    async with Client(
        make_server(), elicitation_callback=_elicitation_callback("accept", confirm=True)
    ) as client:
        first = await client.session.call_tool(name, args, allow_input_required=True)
        assert isinstance(first, types.InputRequiredResult)
        key = next(iter(first.input_requests or {}))
        answer = types.ElicitResult(action="accept", content={"confirm": True})

        resumed = await client.session.call_tool(
            name,
            args,
            allow_input_required=True,
            input_responses={key: answer},
            request_state=first.request_state,
        )
        assert isinstance(resumed, types.CallToolResult)
        assert resumed.is_error is False, resumed.content[0].text
        assert route.call_count == 1
        assert consumed_state_count() == 1

        # A flood of forged states: each is rejected by the boundary and must not consume
        # a slot, so the legitimate digest survives.
        for index in range(20):
            with pytest.raises(MCPError):
                await client.session.call_tool(
                    name,
                    args,
                    allow_input_required=True,
                    input_responses={},
                    request_state=f"v1.forged-{index}",
                )
        assert consumed_state_count() == 1

        with pytest.raises(MCPError) as rejected:
            await client.session.call_tool(
                name,
                args,
                allow_input_required=True,
                input_responses={key: answer},
                request_state=first.request_state,
            )

    assert rejected.value.code == types.INVALID_PARAMS
    assert "already used" in str(rejected.value)
    assert route.call_count == 1


async def test_the_cap_refuses_a_new_state_instead_of_evicting_a_live_one(
    router: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """At the cap the guard fails closed: a live entry is never displaced."""
    monkeypatch.setattr(mrtr, "MAX_CONSUMED_STATES", 2)
    now = time.time()
    mrtr._consumed.clear()
    mrtr._consumed["a" * 64] = now
    mrtr._consumed["b" * 64] = now

    async with Client(make_server()) as client:
        with pytest.raises(MCPError) as rejected:
            await client.session.call_tool(
                "firewall_rule_delete",
                GATED["firewall_rule_delete"],
                allow_input_required=True,
                input_responses={},
                request_state="v1.some-new-state",
            )

    assert rejected.value.code == types.INVALID_PARAMS
    assert "too many confirmations" in str(rejected.value)
    assert consumed_state_count() == 2
    assert router.calls == []


async def test_a_legitimate_state_whose_handler_failed_stays_consumed(router: Any) -> None:
    """A handler failure is a returned result, not a boundary rejection: the state is used."""
    name = "firewall_rule_delete"
    args = GATED[name]
    route = router.delete(DELETE_PATHS[name]).mock(
        return_value=httpx.Response(404, json={"error": "resourceNotFound"})
    )

    async with Client(
        make_server(), elicitation_callback=_elicitation_callback("accept", confirm=True)
    ) as client:
        first = await client.session.call_tool(name, args, allow_input_required=True)
        assert isinstance(first, types.InputRequiredResult)
        key = next(iter(first.input_requests or {}))
        answer = types.ElicitResult(action="accept", content={"confirm": True})

        resumed = await client.session.call_tool(
            name,
            args,
            allow_input_required=True,
            input_responses={key: answer},
            request_state=first.request_state,
        )
        assert isinstance(resumed, types.CallToolResult)
        assert resumed.is_error is True
        assert route.call_count == 1

        with pytest.raises(MCPError) as rejected:
            await client.session.call_tool(
                name,
                args,
                allow_input_required=True,
                input_responses={key: answer},
                request_state=first.request_state,
            )

    assert rejected.value.code == types.INVALID_PARAMS
    assert route.call_count == 1


# -- Cancellation and concurrency ------------------------------------------------------


class _GuardContext:
    """The two attributes the replay guard reads."""

    def __init__(self, state: str) -> None:
        self.method = "tools/call"
        self.params = {"requestState": state}


async def test_the_guard_keeps_the_reservation_on_cancellation() -> None:
    """Cancellation is not a boundary rejection: the confirmation stays used."""
    reset_consumed_states()
    ctx = _GuardContext("v1.cancelled-state")

    async def call_next(_: Any) -> Any:
        raise asyncio.CancelledError()

    with pytest.raises(asyncio.CancelledError):
        await mrtr.mrtr_replay_guard(ctx, call_next)

    assert consumed_state_count() == 1


async def test_the_guard_releases_the_reservation_on_a_boundary_rejection() -> None:
    """A state the boundary rejects was never accepted, so it must not fill the cache."""
    reset_consumed_states()
    ctx = _GuardContext("v1.rejected-state")

    async def call_next(_: Any) -> Any:
        raise MCPError(code=types.INVALID_PARAMS, message="Invalid or expired requestState")

    with pytest.raises(MCPError):
        await mrtr.mrtr_replay_guard(ctx, call_next)

    assert consumed_state_count() == 0


@pytest.mark.parametrize("name", sorted(GATED))
async def test_cancellation_after_the_delete_reached_the_appliance_keeps_the_state(
    router: Any, name: str
) -> None:
    """An ambiguous write must not become repeatable after cancellation.

    The mocked DELETE records that it reached the transport, then blocks. The tool task is
    cancelled before the response; the same sealed state must then be refused, with only
    the one DELETE ever started.
    """
    args = GATED[name]
    reached = asyncio.Event()
    release = asyncio.Event()
    started: list[httpx.Request] = []

    async def _blocking_delete(request: httpx.Request) -> httpx.Response:
        started.append(request)
        reached.set()
        await release.wait()
        return httpx.Response(200, json={"deleted": True})

    if name == "network_interface_delete_vlan":
        router.get(INTERFACE_ITEM).mock(
            return_value=httpx.Response(200, json={"name": "VLAN 20", "type": "vlan"})
        )
    router.delete(DELETE_PATHS[name]).mock(side_effect=_blocking_delete)

    async with Client(
        make_server(), elicitation_callback=_elicitation_callback("accept", confirm=True)
    ) as client:
        first = await client.session.call_tool(name, args, allow_input_required=True)
        assert isinstance(first, types.InputRequiredResult)
        key = next(iter(first.input_requests or {}))
        answer = types.ElicitResult(action="accept", content={"confirm": True})

        task = asyncio.create_task(
            client.session.call_tool(
                name,
                args,
                allow_input_required=True,
                input_responses={key: answer},
                request_state=first.request_state,
            )
        )
        await asyncio.wait_for(reached.wait(), timeout=5)
        assert len(started) == 1

        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, timeout=5)

        # The confirmation was used: the reservation survives the cancellation.
        assert consumed_state_count() == 1

        release.set()
        await asyncio.sleep(0)

        with pytest.raises(MCPError) as rejected:
            await asyncio.wait_for(
                client.session.call_tool(
                    name,
                    args,
                    allow_input_required=True,
                    input_responses={key: answer},
                    request_state=first.request_state,
                ),
                timeout=5,
            )

    assert rejected.value.code == types.INVALID_PARAMS
    assert "already used" in str(rejected.value)
    assert len(started) == 1


async def test_concurrent_reuse_of_one_state_permits_at_most_one_execution(
    router: Any,
) -> None:
    """Two concurrent resumes with the same state: one executes, one is refused."""
    name = "firewall_rule_delete"
    args = GATED[name]
    route = _mock_delete(router, name)

    async with Client(
        make_server(), elicitation_callback=_elicitation_callback("accept", confirm=True)
    ) as client:
        first = await client.session.call_tool(name, args, allow_input_required=True)
        assert isinstance(first, types.InputRequiredResult)
        key = next(iter(first.input_requests or {}))
        answer = types.ElicitResult(action="accept", content={"confirm": True})

        async def resume() -> Any:
            return await client.session.call_tool(
                name,
                args,
                allow_input_required=True,
                input_responses={key: answer},
                request_state=first.request_state,
            )

        results = await asyncio.gather(resume(), resume(), return_exceptions=True)

    successes = [
        result
        for result in results
        if isinstance(result, types.CallToolResult) and not result.is_error
    ]
    rejections = [result for result in results if isinstance(result, MCPError)]
    assert len(successes) == 1, results
    assert len(rejections) == 1, results
    assert rejections[0].code == types.INVALID_PARAMS
    assert route.call_count == 1


# -- Surface invariants ----------------------------------------------------------------


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


async def test_the_gated_descriptions_state_the_real_behaviour() -> None:
    """The description must describe the confirmation that actually happens."""
    tools = {tool.name: tool for tool in await make_server().list_tools()}

    for name in sorted(GATED):
        description = tools[name].description
        assert CONFIRMATION_NOTE in description, name
        assert "2026-07-28" in description, name
        assert "skipped" not in description, name
        assert "best-effort" not in description, name
        assert "proceeds" not in description, name
