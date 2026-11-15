"""Contract tests for the read-only VPN domain (issue #31, ``tools/vpn.py``).

Every test runs against RESPX: no firewall, no network, no real credentials. The tests prove
the exact request each tool builds, that configured state and live state stay separate, that
the eight clientless bookmark variants are projected into one bounded model, that no VPN
mutation exists, and that the whole surface is registered in read-only mode too.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import httpx
import pytest
import respx
from mcp import Client

from sophos_firewall_mcp.config import Settings
from sophos_firewall_mcp.models.vpn import (
    FailoverGroupListInput,
    IpsecConnection,
    IpsecFailoverGroup,
    IpsecLiveConnection,
    IpsecProfile,
    IpsecRemoteAccessSettings,
    IpsecRouteBasedConnection,
    SslVpnBookmark,
    SslVpnBookmarkGroup,
    SslVpnClientlessPolicy,
    SslVpnGlobalSettings,
    SslVpnRemoteAccessPolicy,
    VpnFilteredPageInput,
    VpnPageInput,
    VpnProfileRefInput,
)
from sophos_firewall_mcp.server import create_server
from sophos_firewall_mcp.tools.vpn import register_vpn_tools

HOST = "fw.example.com"
KEY = "sfos_test_key_0123456789abcdef"
BASE = f"https://{HOST}:4444/api/firewall-config/v1"
API_PREFIX = "/api/firewall-config/v1"

PAGE = {"current": 1, "size": 50, "maxSize": 100}
DEFAULT_PAGE_QUERY = {"page": "1", "pageSize": "10", "pageTotal": "false"}


def make_settings(**overrides: Any) -> Settings:
    values: dict[str, Any] = {
        "host": HOST,
        "port": 4444,
        "api_key": KEY,
        "verify_ssl": False,
        "timeout": 5.0,
        "read_only_mode": False,
    }
    values.update(overrides)
    return Settings(**values)


def make_server(**overrides: Any) -> Any:
    return create_server(make_settings(**overrides), domains=[register_vpn_tools])


async def call_tool(name: str, arguments: dict[str, Any], *, read_only: bool = False) -> Any:
    server = make_server(read_only_mode=read_only)
    async with Client(server) as client:
        return await client.call_tool(name, arguments)


async def tool_map(*, read_only: bool = False) -> dict[str, Any]:
    server = make_server(read_only_mode=read_only)
    return {tool.name: tool for tool in await server.list_tools()}


@pytest.fixture
def router() -> Any:
    with respx.mock(assert_all_called=False) as mocked:
        yield mocked


# -- Read operations: one contract test per operation ----------------------------------

READ_CASES: list[tuple[str, str, dict[str, Any] | None, dict[str, str], dict[str, Any]]] = [
    # IPsec profiles
    (
        "ipsec_profile_list",
        "/ipsec-vpn/profiles",
        {"page": 2, "pageSize": 10, "nameContains": "site"},
        {"page": "2", "pageSize": "10", "pageTotal": "false", "nameContains": "site"},
        {"items": [], "pages": PAGE},
    ),
    (
        "ipsec_profile_get",
        "/ipsec-vpn/profiles/prof1",
        {"idOrName": "prof1"},
        {},
        {"name": "prof1"},
    ),
    # IPsec failover groups (extra filter/sort parameters)
    (
        "ipsec_failover_group_list",
        "/ipsec-vpn/site-to-site/failover-groups",
        {"filter": "active", "sort": "name"},
        {**DEFAULT_PAGE_QUERY, "filter": "active", "sort": "name"},
        {"items": [], "pages": PAGE},
    ),
    (
        "ipsec_failover_group_get",
        "/ipsec-vpn/site-to-site/failover-groups/fg1",
        {"idOrName": "fg1"},
        {},
        {"id": "u-1", "name": "fg1"},
    ),
    # IPsec site-to-site connections
    (
        "ipsec_connection_list_ipv4",
        "/ipsec-vpn/site-to-site/connections/ipv4",
        {},
        DEFAULT_PAGE_QUERY,
        {"items": [], "pages": PAGE},
    ),
    (
        "ipsec_policy_based_connection_list_ipv4",
        "/ipsec-vpn/site-to-site/connections/policy-based/ipv4",
        {},
        DEFAULT_PAGE_QUERY,
        {"items": [], "pages": PAGE},
    ),
    (
        "ipsec_policy_based_connection_get_ipv4",
        "/ipsec-vpn/site-to-site/connections/policy-based/ipv4/pb1",
        {"idOrName": "pb1"},
        {},
        {"id": "u-2", "name": "pb1"},
    ),
    (
        "ipsec_route_based_connection_list_ipv4",
        "/ipsec-vpn/site-to-site/connections/route-based/ipv4",
        {},
        DEFAULT_PAGE_QUERY,
        {"items": [], "pages": PAGE},
    ),
    (
        "ipsec_route_based_connection_get_ipv4",
        "/ipsec-vpn/site-to-site/connections/route-based/ipv4/rb1",
        {"idOrName": "rb1"},
        {},
        {"id": "u-3", "name": "rb1"},
    ),
    # Live state (no pagination parameters declared)
    (
        "ipsec_live_connection_list_ipv4",
        "/ipsec-vpn/site-to-site/live-connections/ipv4",
        None,
        {},
        {"items": [], "pages": {"current": 1, "size": 50, "maxSize": 100}},
    ),
    (
        "ipsec_remote_access_settings_get",
        "/ipsec-vpn/remote-access/settings",
        None,
        {},
        {"connectionState": "disabled"},
    ),
    # SSL VPN remote-access policies
    (
        "sslvpn_remote_access_policy_list",
        "/ssl-vpn/remote-access/policies",
        {},
        DEFAULT_PAGE_QUERY,
        {"items": [], "pages": PAGE},
    ),
    (
        "sslvpn_remote_access_policy_get",
        "/ssl-vpn/remote-access/policies/pol1",
        {"idOrName": "pol1"},
        {},
        {"id": "u-4", "name": "pol1"},
    ),
    # SSL VPN clientless bookmark groups and bookmarks
    (
        "sslvpn_bookmark_group_list",
        "/ssl-vpn/clientless/bookmark-groups",
        {},
        DEFAULT_PAGE_QUERY,
        {"items": [], "pages": PAGE},
    ),
    (
        "sslvpn_bookmark_group_get",
        "/ssl-vpn/clientless/bookmark-groups/grp1",
        {"idOrName": "grp1"},
        {},
        {"id": "u-5", "name": "grp1"},
    ),
    (
        "sslvpn_bookmark_list",
        "/ssl-vpn/clientless/bookmarks",
        {},
        DEFAULT_PAGE_QUERY,
        {"items": [], "pages": PAGE},
    ),
    (
        "sslvpn_bookmark_get",
        "/ssl-vpn/clientless/bookmarks/bm1",
        {"idOrName": "bm1"},
        {},
        {"id": "u-6", "name": "bm1"},
    ),
    # SSL VPN clientless policies and global settings
    (
        "sslvpn_clientless_policy_list",
        "/ssl-vpn/clientless/policies",
        {},
        DEFAULT_PAGE_QUERY,
        {"items": [], "pages": PAGE},
    ),
    (
        "sslvpn_clientless_policy_get",
        "/ssl-vpn/clientless/policies/cl1",
        {"idOrName": "cl1"},
        {},
        {"id": "u-7", "name": "cl1"},
    ),
    ("sslvpn_global_settings_get", "/ssl-vpn/global-settings", None, {}, {}),
]


@pytest.mark.parametrize(
    ("tool", "path", "arguments", "query", "body"),
    READ_CASES,
    ids=[case[0] for case in READ_CASES],
)
async def test_read_operation_contract(
    router: Any,
    tool: str,
    path: str,
    arguments: dict[str, Any] | None,
    query: dict[str, str],
    body: dict[str, Any],
) -> None:
    route = router.get(f"{BASE}{path}").mock(return_value=httpx.Response(200, json=body))

    result = await call_tool(tool, {} if arguments is None else {"request": arguments})

    assert result.is_error is False
    request = route.calls.last.request
    assert request.method == "GET"
    assert request.url.path == f"{API_PREFIX}{path}"
    assert dict(request.url.params) == query
    assert request.headers["authorization"] == f"Bearer {KEY}"
    assert request.headers["accept"] == "application/json"
    assert "content-type" not in request.headers
    assert request.content == b""


# -- Configured state vs live state ----------------------------------------------------


async def test_configured_and_live_connections_are_separate_operations(router: Any) -> None:
    configured = router.get(f"{BASE}/ipsec-vpn/site-to-site/connections/ipv4").mock(
        return_value=httpx.Response(200, json={"items": [], "pages": PAGE})
    )
    live = router.get(f"{BASE}/ipsec-vpn/site-to-site/live-connections/ipv4").mock(
        return_value=httpx.Response(200, json={"items": [], "pages": PAGE})
    )

    configured_result = await call_tool("ipsec_connection_list_ipv4", {"request": {}})
    live_result = await call_tool("ipsec_live_connection_list_ipv4", {})

    assert configured_result.is_error is False
    assert live_result.is_error is False
    assert configured.call_count == 1
    assert live.call_count == 1
    # The configured tool never queries the live endpoint and vice versa.
    assert "live-connections" not in str(configured.calls.last.request.url)
    assert "connections/ipv4" in str(live.calls.last.request.url)


async def test_live_connections_project_security_associations(router: Any) -> None:
    router.get(f"{BASE}/ipsec-vpn/site-to-site/live-connections/ipv4").mock(
        return_value=httpx.Response(
            200,
            json={
                "items": [
                    {
                        "connectionName": "pbvpn_19",
                        "type": "policyBased",
                        "ikeSecurityAssociation": {
                            "ikeSecurityAssociationId": 5,
                            "name": "pbvpn_19-1",
                            "localId": "10.179.8.22",
                            "remoteId": "10.179.8.23",
                            "localGatewayIpv4": "10.179.8.22",
                            "remoteGatewayIpv4": "10.179.8.23",
                            "ikeVersion": "ikev2",
                            "ipsecSecurityAssociations": [
                                {
                                    "ipsecSecurityAssociationId": 1,
                                    "name": "pbvpn_19-1",
                                    "trafficSelectors": {
                                        "localNetworkIpv4": "192.168.77.0/24",
                                        "remoteNetworkIpv4": "192.168.55.0/24",
                                    },
                                    "packetsSent": 10,
                                    "bytesReceived": 2048,
                                }
                            ],
                        },
                    }
                ],
                "pages": PAGE,
            },
        )
    )

    result = await call_tool("ipsec_live_connection_list_ipv4", {})

    assert result.is_error is False
    item = IpsecLiveConnection.model_validate(result.structured_content["items"][0])
    assert item.ikeSecurityAssociation is not None
    assert item.ikeSecurityAssociation.ikeVersion == "ikev2"
    association = item.ikeSecurityAssociation.ipsecSecurityAssociations[0]
    assert association.trafficSelectors is not None
    assert association.trafficSelectors.localNetworkIpv4 == "192.168.77.0/24"
    assert association.bytesReceived == 2048


async def test_live_connection_list_states_the_1000_item_ceiling() -> None:
    """L9: the appliance caps the response at 1000 items and there is no way to page.

    The operation declares no ``page``/``pageSize`` parameters, so the tool must not invent
    them; it must state the ceiling so a full page is not read as a complete list.
    """
    tools = await tool_map()
    tool = tools["ipsec_live_connection_list_ipv4"]

    assert "1000" in tool.description
    assert "truncated" in tool.description
    assert tool.input_schema.get("properties", {}) == {}


async def test_remote_access_settings_flag_an_unset_configuration(router: Any) -> None:
    """L10: an all-null object with ``connectionState: "unset"`` must read as unconfigured."""
    router.get(f"{BASE}/ipsec-vpn/remote-access/settings").mock(
        return_value=httpx.Response(200, json={"connectionState": "unset"})
    )

    result = await call_tool("ipsec_remote_access_settings_get", {})

    assert result.is_error is False
    assert result.structured_content["configured"] is False
    assert result.structured_content["connectionState"] == "unset"

    tools = await tool_map()
    assert "configured" in tools["ipsec_remote_access_settings_get"].description


def test_configured_is_derived_from_the_connection_state() -> None:
    """L10: ``configured`` is true only when a configuration exists (enabled or disabled)."""
    assert (
        IpsecRemoteAccessSettings.model_validate({"connectionState": "unset"}).configured is False
    )
    assert (
        IpsecRemoteAccessSettings.model_validate({"connectionState": "enabled"}).configured is True
    )
    assert (
        IpsecRemoteAccessSettings.model_validate({"connectionState": "disabled"}).configured is True
    )
    # A missing connectionState violates the contract: report unconfigured, never guess.
    assert IpsecRemoteAccessSettings.model_validate({}).configured is False
    # The flag is published in the output schema, so an agent can see it before calling.
    schema = IpsecRemoteAccessSettings.model_json_schema()["properties"]
    assert schema["configured"]["type"] == "boolean"


# -- Discovery, annotations and the read-only guarantee --------------------------------


EXPECTED_VPN_TOOLS = {case[0] for case in READ_CASES}


async def test_the_vpn_domain_publishes_its_20_read_tools() -> None:
    tools = await tool_map()

    assert len(EXPECTED_VPN_TOOLS) == 20
    assert set(tools) == EXPECTED_VPN_TOOLS


async def test_no_vpn_mutation_is_registered() -> None:
    tools = await tool_map()

    for name, tool in tools.items():
        assert tool.annotations is not None
        assert tool.annotations.read_only_hint is True, name
        assert tool.annotations.destructive_hint is None, name
        assert tool.annotations.idempotent_hint is None, name
        for forbidden in ("create", "update", "delete", "move", "start", "stop", "enable"):
            assert forbidden not in name, name


async def test_read_only_mode_registers_the_same_vpn_surface() -> None:
    assert set(await tool_map(read_only=True)) == EXPECTED_VPN_TOOLS


async def test_authorization_failure_is_a_sanitized_tool_error(router: Any) -> None:
    router.get(f"{BASE}/ipsec-vpn/profiles").mock(
        return_value=httpx.Response(403, json={"error": "forbidden", "message": "raw detail"})
    )

    result = await call_tool("ipsec_profile_list", {"request": {}})

    assert result.is_error is True
    text = result.content[0].text
    assert "not allowed" in text
    assert "raw detail" not in text
    assert KEY not in text


async def test_a_malformed_profile_payload_is_a_sanitized_tool_error(router: Any) -> None:
    """A 200 body that does not match the output model becomes a sanitized ToolError."""
    router.get(f"{BASE}/ipsec-vpn/profiles/prof1").mock(
        return_value=httpx.Response(200, json={"id": "u-1", "name": 123})
    )

    result = await call_tool("ipsec_profile_get", {"request": {"idOrName": "prof1"}})

    assert result.is_error is True
    text = result.content[0].text
    assert "does not match the documented schema" in text
    assert "123" not in text
    assert KEY not in text


# -- Model tests -----------------------------------------------------------------------


def test_ipsec_profile_projection_covers_both_phases() -> None:
    profile = IpsecProfile.model_validate(
        {
            "name": "site-profile",
            "id": "u-1",
            "keyExchange": "ikev2",
            "authenticationMode": "main",
            "phase1": {
                "dhGroup": ["DH2048", "ECP256"],
                "keyLife": 28800,
                "rekeyMargin": 120,
                "rekeyFuzz": 10,
                "algorithms": [
                    {"encryptionAlgorithm": "AES256", "authenticationAlgorithm": "SHA2_256"}
                ],
            },
            "phase2": {
                "dhGroup": "sameAsPhaseOne",
                "keyLife": 3600,
                "algorithms": [
                    {"encryptionAlgorithm": "AES256GCM16", "authenticationAlgorithm": "SHA2_512"}
                ],
            },
            "deadPeerDetection": {"enabled": True, "delay": 30, "timeout": 120, "action": "hold"},
            "unknownField": "ignored",
        }
    )

    assert profile.phase1 is not None
    assert profile.phase1.dhGroup == ["DH2048", "ECP256"]
    assert profile.phase1.algorithms[0].encryptionAlgorithm == "AES256"
    assert profile.phase2 is not None and profile.phase2.dhGroup == "sameAsPhaseOne"
    assert profile.deadPeerDetection is not None
    assert profile.deadPeerDetection.action == "hold"
    assert "unknownField" not in profile.model_dump()


def test_bookmark_projection_flattens_the_rdp_variant() -> None:
    bookmark = SslVpnBookmark.model_validate(
        {
            "id": "u-1",
            "name": "rdp-gw",
            "description": "Jump host",
            "createdAt": "2026-02-26T07:46:33.000Z",
            "rdp": {
                "url": "rdp-gw.corp.local",
                "port": 3389,
                "protocolSecurity": "nla",
                "automaticLogin": {"username": "administrator"},
                "domain": "corp",
            },
        }
    )

    assert bookmark.protocol == "rdp"
    assert bookmark.url == "rdp-gw.corp.local"
    assert bookmark.port == 3389
    assert bookmark.protocolSecurity == "nla"
    assert bookmark.automaticLoginUsername == "administrator"
    assert bookmark.domain == "corp"


def test_bookmark_projection_flattens_the_ssh_variant() -> None:
    bookmark = SslVpnBookmark.model_validate(
        {
            "id": "u-2",
            "name": "jump",
            "ssh": {
                "url": "jump.corp.local",
                "port": 22,
                "username": "ops",
                "automaticLogin": {"authenticationMethod": "privateKey"},
                "publicHostKey": "ssh-ed25519 AAAA",
            },
        }
    )

    assert bookmark.protocol == "ssh"
    assert bookmark.username == "ops"
    assert bookmark.authenticationMethod == "privateKey"
    assert bookmark.publicHostKey == "ssh-ed25519 AAAA"


def test_bookmark_projection_without_a_protocol_payload_is_still_valid() -> None:
    bookmark = SslVpnBookmark.model_validate({"id": "u-3", "name": "orphan"})

    assert bookmark.protocol is None
    assert bookmark.url is None


def test_failover_group_list_input_merges_filter_and_sort() -> None:
    request = FailoverGroupListInput(nameContains="vpn", filter="active", sort="name")

    assert request.name_filters() == {"nameContains": "vpn"}
    assert request.extra_filters() == {"filter": "active", "sort": "name"}


def test_vpn_name_filters_are_mutually_exclusive() -> None:
    """The contract declares ``nameContains`` and ``nameNotEquals`` mutually exclusive."""
    with pytest.raises(ValueError, match="mutually exclusive"):
        VpnFilteredPageInput(nameContains="vpn", nameNotEquals="legacy")
    assert VpnFilteredPageInput(nameContains="vpn").name_filters() == {"nameContains": "vpn"}


def test_vpn_ref_input_accepts_a_uuid_and_rejects_a_comma() -> None:
    uuid = "6f1c2d3e-4b5a-4c7d-8e9f-0a1b2c3d4e5f"
    assert VpnProfileRefInput(idOrName=uuid).id_or_name == uuid
    with pytest.raises(ValueError):
        VpnProfileRefInput(idOrName="a,b")


# -- Phase-5 polish: the uniform default page size (M11) --------------------------------


def test_vpn_page_input_defaults_to_ten() -> None:
    """M11: the VPN list tools share the same small default as every other list tool."""
    for model in (VpnPageInput, VpnFilteredPageInput):
        parsed = model()

        assert (parsed.page, parsed.page_size, parsed.page_total) == (1, 10, False)
        description = model.model_json_schema()["properties"]["page_size"]["description"]
        assert "Defaults to 10" in description
        # The bounds are unchanged: this is a default, not a schema break.
        assert model(page_size=100).page_size == 100


async def test_vpn_list_descriptions_state_the_default_page_size() -> None:
    """M11: every VPN list tool documents the default it applies."""
    tools = await tool_map()

    for name in (
        "ipsec_profile_list",
        "ipsec_failover_group_list",
        "sslvpn_remote_access_policy_list",
        "sslvpn_bookmark_group_list",
        "sslvpn_bookmark_list",
        "sslvpn_clientless_policy_list",
    ):
        assert "default 10" in tools[name].description, name


# -- Phase-5 review, Medium finding 2: the epoch sentinel in the VPN outputs (L6) -------


VPN_EPOCH_MODELS: list[tuple[str, type[Any]]] = [
    ("IpsecProfile", IpsecProfile),
    ("IpsecFailoverGroup", IpsecFailoverGroup),
    ("IpsecConnection", IpsecConnection),
    ("IpsecRouteBasedConnection", IpsecRouteBasedConnection),
    ("IpsecRemoteAccessSettings", IpsecRemoteAccessSettings),
    ("SslVpnRemoteAccessPolicy", SslVpnRemoteAccessPolicy),
    ("SslVpnBookmark", SslVpnBookmark),
    ("SslVpnBookmarkGroup", SslVpnBookmarkGroup),
    ("SslVpnClientlessPolicy", SslVpnClientlessPolicy),
    ("SslVpnGlobalSettings", SslVpnGlobalSettings),
]


@pytest.mark.parametrize(
    ("name", "model"), VPN_EPOCH_MODELS, ids=[case[0] for case in VPN_EPOCH_MODELS]
)
def test_vpn_epoch_sentinel_is_published_as_null(name: str, model: type[Any]) -> None:
    """L6: every VPN output model publishes the epoch "never" sentinel as null.

    The shared serializer was added to the other output bases but not to ``vpn._Output``,
    so the VPN projections still published ``1970-01-01T00:00:00Z`` (phase-5 review,
    Medium finding 2). Only the exact sentinel is mapped, and the parsed value stays
    available to server-side logic.
    """
    fields = model.model_fields
    timestamped = [field for field in ("createdAt", "updatedAt") if field in fields]
    assert timestamped, name

    payload: dict[str, Any] = {"name": "DefaultHeadOffice"}
    payload.update({field: "1970-01-01T00:00:00Z" for field in timestamped})
    parsed = model.model_validate(payload)

    # The parsed value stays available: the audit heuristic detects built-in objects from
    # the epoch stamp, so hiding it from the model would silently disable it.
    for field in timestamped:
        assert getattr(parsed, field) == datetime(1970, 1, 1, tzinfo=UTC), (name, field)

    published = parsed.model_dump(mode="json", by_alias=True)
    for field in timestamped:
        assert published[field] is None, (name, field)

    # A real timestamp is preserved, and one second past the epoch is not the sentinel.
    real = model.model_validate(
        {"name": "DefaultHeadOffice", **{field: "2026-11-15T10:00:00Z" for field in timestamped}}
    )
    real_published = real.model_dump(mode="json", by_alias=True)
    for field in timestamped:
        assert real_published[field] == "2026-11-15T10:00:00Z", (name, field)

    near = model.model_validate(
        {"name": "DefaultHeadOffice", **{field: "1970-01-01T00:00:01Z" for field in timestamped}}
    )
    near_published = near.model_dump(mode="json", by_alias=True)
    for field in timestamped:
        assert near_published[field] == "1970-01-01T00:00:01Z", (name, field)


async def test_ipsec_profile_get_publishes_the_epoch_sentinel_as_null(router: Any) -> None:
    """L6 end-to-end: the real server publishes ``createdAt: null`` for the sentinel.

    The review proved the leak through ``structuredContent``; this pins the same path so a
    regression in the VPN output base is visible at the tool boundary, not only on the
    model.
    """
    router.get(f"{BASE}/ipsec-vpn/profiles/DefaultHeadOffice").mock(
        return_value=httpx.Response(
            200,
            json={
                "name": "DefaultHeadOffice",
                "createdAt": "1970-01-01T00:00:00Z",
                "updatedAt": "2026-11-15T10:00:00Z",
            },
        )
    )

    result = await call_tool("ipsec_profile_get", {"request": {"idOrName": "DefaultHeadOffice"}})

    assert result.is_error is False
    assert result.structured_content is not None
    assert result.structured_content["createdAt"] is None
    assert result.structured_content["updatedAt"] == "2026-11-15T10:00:00Z"
