"""Contract, model and discovery tests for the user/live-session tools (#30).

Every test runs against RESPX: no firewall, no network, no real credentials. The tests prove
the exact request each tool builds (method, path, query, body, content type), the
``{items, pages}`` projections, the JSON Merge Patch semantics of ``updateNetworkUser``, the
documented error mapping, the read-only filter, the published annotations and the
credential-redaction guarantee.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
import yaml
from mcp import Client
from mcp.server.mcpserver import MCPServer
from pydantic import SecretStr, ValidationError

from sophos_firewall_mcp.config import Settings
from sophos_firewall_mcp.context import AppContext
from sophos_firewall_mcp.models.users import (
    LIVE_USER_CLIENT_TYPES,
    AllowedNetworksIpv4Input,
    LiveUserDisconnectInput,
    LiveUserListInput,
    NetworkUserCreateInput,
    NetworkUserDeleteInput,
    NetworkUserGetInput,
    NetworkUserListInput,
    NetworkUserUpdateInput,
    PolicyRefInput,
    SimultaneousLoginsInput,
    UserGroupRefInput,
    UserListInput,
    project_disconnect_live_user,
    project_live_user_page,
    project_network_user,
    project_network_user_page,
    project_user_page,
)
from sophos_firewall_mcp.server import create_server
from sophos_firewall_mcp.tools.users_auth import (
    LIVE_USERS_DISCONNECT_PATH,
    LIVE_USERS_PATH,
    NETWORK_USERS_PATH,
    USERS_PATH,
    register_users_tools,
)

HOST = "fw.example.com"
KEY = "sfos_test_key_0123456789abcdef"
BASE = f"https://{HOST}:4444/api/firewall-config/v1"
PASSWORD = "S3cret-Passw0rd!"
ROOT = Path(__file__).resolve().parents[1]
SPEC_PATH = ROOT / "firewall_config_openapi.yaml"

READ_TOOL_NAMES = {"user_list", "network_user_list", "network_user_get", "live_user_list"}
MUTATION_TOOL_NAMES = {
    "network_user_create",
    "network_user_update",
    "network_user_delete",
    "live_user_disconnect",
}
ALL_TOOL_NAMES = READ_TOOL_NAMES | MUTATION_TOOL_NAMES

UUID = "3f2504e0-4f89-11d3-9a0c-0305e82c3301"

PAGES: dict[str, Any] = {
    "current": 2,
    "size": 10,
    "maxSize": 100,
    "total": 3,
    "items": 1,
}

USER_SUMMARY_PAYLOAD: dict[str, Any] = {
    "id": UUID,
    "name": "alice",
    "displayName": "Alice Example",
    "description": "General authentication user.",
    "active": True,
    "emailAddresses": ["alice@example.com"],
    "group": {"name": "users"},
    "additionalGroups": [{"name": "vpn-users"}],
    "administrativeAccess": False,
    "createdAt": "2026-06-09T07:00:00Z",
    "updatedAt": "2026-06-09T07:10:00Z",
}

NETWORK_USER_PAYLOAD: dict[str, Any] = {
    "id": "c652e7d0-1fa2-457d-a7d3-6f7e3d65f946",
    "name": "user-ops",
    "displayName": "Operations user",
    "description": "Operations network user account.",
    "active": True,
    "emailAddresses": ["user-ops@example.com"],
    "group": {"name": "users"},
    "additionalGroups": [{"name": "engineering-users"}],
    "policies": {
        "surfingQuotaPolicy": {"name": "default-surfing-quota"},
        "accessTimePolicy": {"name": "always"},
        "trafficShapingPolicy": {"name": "user-qos-policy"},
        "macBinding": False,
        "allowedNetworksIpv4": {"any": True},
        "simultaneousLogins": {"limit": 3},
    },
    "vpnAccess": {"l2tp": False, "pptp": False, "ipsecVpnRemoteAccess": False},
    "emailQuarantineDigest": True,
    "createdAt": "2026-06-09T07:00:00Z",
    "updatedAt": "2026-06-09T07:10:00Z",
}

LIVE_USER_PAYLOAD: dict[str, Any] = {
    "liveUserId": 41,
    "userName": "user-ops",
    "clientType": "sslVpnTunnel",
    "ipv4Address": "10.10.10.50",
    "ipv6Address": "2001:db8::50",
    "macAddress": "00:11:22:33:44:55",
    "loggedInTime": "2026-11-15T09:30:00.123Z",
    "uploadData": 1024,
    "downloadData": 2048,
    "transferRate": 12,
    "duration": 3600,
}

MINIMAL_CREATE: dict[str, Any] = {
    "name": "user-ops",
    "display_name": "Operations user",
    "password": PASSWORD,
    "group": {"name": "users"},
}


# -- Helpers ---------------------------------------------------------------------------


def make_settings(*, read_only: bool = False) -> Settings:
    """Build valid settings without touching the process environment."""
    return Settings(
        host=HOST,
        port=4444,
        api_key=KEY,
        verify_ssl=False,
        timeout=5.0,
        read_only_mode=read_only,
    )


def make_server(*, read_only: bool = False) -> MCPServer[AppContext]:
    """Build a server with only the user/live-session domain registered."""
    return create_server(make_settings(read_only=read_only), domains=[register_users_tools])


@pytest.fixture
def router() -> Any:
    """RESPX router; unmatched calls are not an error so each test asserts its own route."""
    with respx.mock(assert_all_called=False) as mocked:
        yield mocked


async def call(server: MCPServer[AppContext], name: str, request: dict[str, Any]) -> Any:
    """Call one tool through the official SDK client (full schema validation included)."""
    async with Client(server) as client:
        return await client.call_tool(name, request)


def body_of(request: httpx.Request) -> Any:
    """Decode the JSON body of a recorded request."""
    return json.loads(request.content)


def request_model_schema(tool: Any) -> dict[str, Any]:
    """Return the JSON schema of the tool's request model.

    Since 0.7 the request model's fields are published flat at the root of ``inputSchema``,
    so the root *is* the request model's schema.
    """
    return tool.input_schema


def find_password_schema(schema: Any) -> dict[str, Any]:
    """Find the ``format: password`` sub-schema inside an input schema fragment."""
    if isinstance(schema, dict):
        if schema.get("format") == "password":
            return schema
        for value in schema.values():
            found = find_password_schema(value)
            if found:
                return found
    elif isinstance(schema, list):
        for value in schema:
            found = find_password_schema(value)
            if found:
                return found
    return {}


def schema_property_names(node: Any) -> set[str]:
    """Every ``properties`` key reachable in a JSON schema, at every depth.

    The walk is structural rather than ``$ref``-aware: it descends into ``$defs``,
    ``items``, ``anyOf``/``oneOf``/``allOf`` and every other nested object, so a property
    declared one level down is found without resolving references.
    """
    found: set[str] = set()
    if isinstance(node, dict):
        properties = node.get("properties")
        if isinstance(properties, dict):
            found.update(properties)
        for value in node.values():
            found |= schema_property_names(value)
    elif isinstance(node, list):
        for value in node:
            found |= schema_property_names(value)
    return found


def load_spec() -> dict[str, Any]:
    """Parse the checked-in OpenAPI contract."""
    loader = getattr(yaml, "CSafeLoader", yaml.SafeLoader)
    with SPEC_PATH.open("rb") as handle:
        return yaml.load(handle, Loader=loader)


# -- Input models ----------------------------------------------------------------------


def test_page_input_defaults_match_the_contract():
    for model in (UserListInput, NetworkUserListInput):
        parsed = model()

        assert (parsed.page, parsed.page_size, parsed.page_total) == (1, 10, False)
        assert parsed.name_contains is None
        assert parsed.name_not_equals is None


@pytest.mark.parametrize(
    "payload",
    [
        {"page": 0},
        {"page": -1},
        {"page_size": 0},
        {"page_size": 101},
        {"name_contains": ""},
        {"name_contains": "x" * 256},
        {"name_not_equals": ""},
    ],
)
def test_page_and_filter_bounds_are_enforced(payload: dict[str, Any]):
    with pytest.raises(ValidationError):
        UserListInput(**payload)


def test_page_and_filter_bounds_accept_the_documented_limits():
    parsed = UserListInput(page=1, page_size=100, name_contains="x" * 255)

    assert parsed.page_size == 100
    assert parsed.name_contains == "x" * 255


def test_name_filters_are_mutually_exclusive():
    with pytest.raises(ValidationError, match="mutually exclusive"):
        NetworkUserListInput(name_contains="ops", name_not_equals="bob")


@pytest.mark.parametrize(
    ("model", "payload"),
    [
        (UserListInput, {"limit": 10}),
        (UserListInput, {"cursor": "abc"}),
        (NetworkUserListInput, {"offset": 5}),
        (NetworkUserCreateInput, {**MINIMAL_CREATE, "password_hash": "x"}),
        (NetworkUserUpdateInput, {"id_or_name": "user-ops", "active": True, "force": True}),
        (NetworkUserGetInput, {"id_or_name": "user-ops", "select": "*"}),
        (NetworkUserDeleteInput, {"id_or_name": "user-ops", "force": True}),
        (LiveUserListInput, {"page": 1}),
        (LiveUserDisconnectInput, {"live_user_id": 1, "message": "bye", "reason": "x"}),
    ],
)
def test_closed_inputs_reject_unknown_fields(model: Any, payload: dict[str, Any]):
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        model(**payload)


@pytest.mark.parametrize("identifier", ["user-ops", "User Ops 1", "user.ops", UUID, "a/b"])
def test_identifier_accepts_names_and_uuids(identifier: str):
    assert NetworkUserGetInput(id_or_name=identifier).id_or_name == identifier


@pytest.mark.parametrize(
    "identifier",
    ["", " leading", "trailing ", "a,b", "a;b", "a\x00b", "a..b", "a?b", "a#b", "a\\b", "a%2eb"],
)
def test_identifier_rejects_unaddressable_or_invalid_names(identifier: str):
    with pytest.raises(ValidationError):
        NetworkUserDeleteInput(id_or_name=identifier)


@pytest.mark.parametrize("missing", ["name", "display_name", "password", "group"])
def test_create_input_requires_the_four_contract_fields(missing: str):
    payload = {key: value for key, value in MINIMAL_CREATE.items() if key != missing}

    with pytest.raises(ValidationError):
        NetworkUserCreateInput(**payload)


def test_create_password_is_a_secret_and_never_rendered():
    parsed = NetworkUserCreateInput(**MINIMAL_CREATE)

    assert isinstance(parsed.password, SecretStr)
    assert PASSWORD not in repr(parsed)
    assert PASSWORD not in str(parsed)
    assert PASSWORD not in str(parsed.model_dump())
    assert PASSWORD not in parsed.model_dump_json()
    assert parsed.password.get_secret_value() == PASSWORD


def test_update_input_requires_at_least_one_body_field():
    with pytest.raises(ValidationError, match="at least one field"):
        NetworkUserUpdateInput(id_or_name="user-ops")


def test_update_input_rejects_a_null_password():
    with pytest.raises(ValidationError, match="password cannot be null"):
        NetworkUserUpdateInput(id_or_name="user-ops", password=None)


def test_policy_reference_requires_exactly_one_variant():
    assert PolicyRefInput(name="always").name == "always"
    assert PolicyRefInput(no_policy=True).no_policy is True

    with pytest.raises(ValidationError, match="exactly one"):
        PolicyRefInput()
    with pytest.raises(ValidationError, match="exactly one"):
        PolicyRefInput(name="always", no_policy=True)


def test_allowed_networks_requires_exactly_one_variant():
    assert AllowedNetworksIpv4Input(any=True).any is True
    assert AllowedNetworksIpv4Input(ipv4_addresses=["10.0.0.1"]).ipv4_addresses == ["10.0.0.1"]
    assert (
        AllowedNetworksIpv4Input(
            ipv4_address_start="10.0.0.1", ipv4_address_end="10.0.0.9"
        ).ipv4_address_end
        == "10.0.0.9"
    )

    with pytest.raises(ValidationError, match="exactly one"):
        AllowedNetworksIpv4Input()
    with pytest.raises(ValidationError, match="exactly one"):
        AllowedNetworksIpv4Input(any=True, ipv4_addresses=["10.0.0.1"])
    with pytest.raises(ValidationError, match="provided together"):
        AllowedNetworksIpv4Input(ipv4_address_start="10.0.0.1")


def test_allowed_networks_validates_ipv4_addresses():
    with pytest.raises(ValidationError, match="valid IPv4"):
        AllowedNetworksIpv4Input(ipv4_addresses=["not-an-address"])


def test_simultaneous_logins_requires_exactly_one_variant():
    assert SimultaneousLoginsInput(use_global_limit=True).use_global_limit is True
    assert SimultaneousLoginsInput(unlimited=True).unlimited is True
    assert SimultaneousLoginsInput(limit=99).limit == 99

    with pytest.raises(ValidationError, match="exactly one"):
        SimultaneousLoginsInput()
    with pytest.raises(ValidationError, match="exactly one"):
        SimultaneousLoginsInput(unlimited=True, limit=3)
    with pytest.raises(ValidationError):
        SimultaneousLoginsInput(limit=100)


@pytest.mark.parametrize(
    "payload",
    [
        {"live_user_id": 0, "message": "bye"},
        {"live_user_id": -1, "message": "bye"},
        {"live_user_id": 1, "message": ""},
        {"live_user_id": 1, "message": "x" * 601},
    ],
)
def test_disconnect_input_enforces_the_contract_bounds(payload: dict[str, Any]):
    with pytest.raises(ValidationError):
        LiveUserDisconnectInput(**payload)


def test_disconnect_input_accepts_the_documented_limits():
    parsed = LiveUserDisconnectInput(live_user_id=1, message="x" * 600)

    assert parsed.live_user_id == 1
    assert len(parsed.message) == 600


def test_live_user_list_input_is_empty_and_closed():
    assert LiveUserListInput.model_fields == {}
    assert LiveUserListInput().model_dump() == {}


# -- Projections -----------------------------------------------------------------------


def test_project_network_user_projects_the_bounded_shape():
    output = project_network_user(NETWORK_USER_PAYLOAD)

    assert output.id == NETWORK_USER_PAYLOAD["id"]
    assert output.name == "user-ops"
    assert output.displayName == "Operations user"
    assert output.group == "users"
    assert output.additionalGroups == ["engineering-users"]
    assert output.policies is not None
    assert output.policies.surfingQuotaPolicy == "default-surfing-quota"
    assert output.policies.allowedNetworksAny is True
    assert output.policies.simultaneousLoginsLimit == 3
    assert output.vpnAccess is not None
    assert output.vpnAccess.l2tp is False


def test_projection_ignores_unknown_fields_and_credential_material():
    payload = {
        **NETWORK_USER_PAYLOAD,
        "password": PASSWORD,
        "passwordHash": "$6$leaked",
        "apiKey": "leaked-key",
        "policies": {**NETWORK_USER_PAYLOAD["policies"], "password": PASSWORD},
    }

    output = project_network_user(payload)
    dumped = json.dumps(output.model_dump(mode="json"))

    assert PASSWORD not in dumped
    assert "leaked" not in dumped
    assert "password" not in output.model_dump()
    assert "passwordHash" not in output.model_dump()


def test_project_network_user_requires_the_contract_identifiers():
    payload = {key: value for key, value in NETWORK_USER_PAYLOAD.items() if key != "id"}

    with pytest.raises(ValidationError):
        project_network_user(payload)


def test_project_user_page_preserves_the_pages_metadata():
    page = project_user_page({"items": [USER_SUMMARY_PAYLOAD], "pages": PAGES})

    assert [item.name for item in page.items] == ["alice"]
    assert page.items[0].administrativeAccess is False
    assert page.pages is not None
    assert page.pages.current == 2
    assert page.pages.size == 10
    assert page.pages.maxSize == 100
    assert page.pages.total == 3
    assert page.pages.items == 1


def test_project_user_page_accepts_an_empty_page():
    page = project_user_page({"items": [], "pages": {"current": 1, "size": 50, "maxSize": 100}})

    assert page.items == []
    assert page.pages is not None
    assert page.pages.current == 1


def test_project_network_user_page_keeps_items_and_pages():
    page = project_network_user_page({"items": [NETWORK_USER_PAYLOAD], "pages": PAGES})

    assert [item.name for item in page.items] == ["user-ops"]
    assert page.pages is not None
    assert page.pages.maxSize == 100


def test_project_live_user_page_projects_every_documented_field():
    page = project_live_user_page({"items": [LIVE_USER_PAYLOAD], "pages": PAGES})

    session = page.items[0]
    assert session.liveUserId == 41
    assert session.userName == "user-ops"
    assert session.clientType == "sslVpnTunnel"
    assert session.ipv4Address == "10.10.10.50"
    assert session.ipv6Address == "2001:db8::50"
    assert session.macAddress == "00:11:22:33:44:55"
    assert session.loggedInTime.year == 2026
    assert (session.uploadData, session.downloadData) == (1024, 2048)
    assert (session.transferRate, session.duration) == (12, 3600)
    assert page.pages is not None
    assert (page.pages.current, page.pages.size, page.pages.maxSize) == (2, 10, 100)


def test_project_live_user_page_accepts_an_empty_collection():
    page = project_live_user_page(
        {"items": [], "pages": {"current": 1, "size": 50, "maxSize": 100}}
    )

    assert page.items == []


def test_project_disconnect_live_user_echoes_the_target_session():
    output = project_disconnect_live_user({"disconnected": True}, 41)

    assert output.disconnected is True
    assert output.liveUserId == 41


# -- M2: output naming -----------------------------------------------------------------

#: The Sophos wire names of every users output object. The projections are renames of the
#: appliance payload, so these are the contract's camelCase names, not snake_case.
USER_SUMMARY_OUTPUT_KEYS = {
    "id",
    "name",
    "displayName",
    "description",
    "active",
    "emailAddresses",
    "group",
    "additionalGroups",
    "administrativeAccess",
    "createdAt",
    "updatedAt",
}
NETWORK_USER_OUTPUT_KEYS = {
    "id",
    "name",
    "displayName",
    "description",
    "active",
    "emailAddresses",
    "group",
    "additionalGroups",
    "policies",
    "vpnAccess",
    "emailQuarantineDigest",
    "createdAt",
    "updatedAt",
}
NETWORK_USER_POLICIES_OUTPUT_KEYS = {
    "surfingQuotaPolicy",
    "accessTimePolicy",
    "networkTrafficQuotaPolicy",
    "trafficShapingPolicy",
    "macBinding",
    "macAddresses",
    "allowedNetworksAny",
    "allowedNetworksIpv4",
    "allowedNetworksIpv4Start",
    "allowedNetworksIpv4End",
    "simultaneousLoginsUseGlobal",
    "simultaneousLoginsUnlimited",
    "simultaneousLoginsLimit",
}
NETWORK_USER_VPN_ACCESS_OUTPUT_KEYS = {
    "sslVpnRemoteAccessPolicy",
    "sslVpnClientlessPolicy",
    "sslVpnStaticIpv4Address",
    "sslVpnStaticIpv6Address",
    "l2tp",
    "l2tpStaticIpv4Address",
    "pptp",
    "pptpStaticIpv4Address",
    "ipsecVpnRemoteAccess",
    "ipsecVpnStaticIpv4Address",
}
LIVE_USER_SESSION_OUTPUT_KEYS = {
    "liveUserId",
    "userName",
    "clientType",
    "ipv4Address",
    "ipv6Address",
    "macAddress",
    "loggedInTime",
    "uploadData",
    "downloadData",
    "transferRate",
    "duration",
}

#: camelCase as the contract writes it: a lowercase first letter, no underscore.
CAMEL_CASE_PATTERN = re.compile(r"^[a-z][a-zA-Z0-9]*$")


def test_projections_dump_the_sophos_wire_names():
    """M2: the users projections publish the appliance's camelCase names.

    Inputs stay snake_case (the model writes them); outputs are projections of the payload
    the model reads, so they keep the wire names like the other 119 tools. A snake_case
    output key is exactly the split M2 removes.
    """
    network_user = project_network_user(NETWORK_USER_PAYLOAD).model_dump(mode="json")
    assert set(network_user) == NETWORK_USER_OUTPUT_KEYS
    assert set(network_user["policies"]) == NETWORK_USER_POLICIES_OUTPUT_KEYS
    assert set(network_user["vpnAccess"]) == NETWORK_USER_VPN_ACCESS_OUTPUT_KEYS

    summary = project_user_page({"items": [USER_SUMMARY_PAYLOAD], "pages": PAGES}).items[0]
    assert set(summary.model_dump(mode="json")) == USER_SUMMARY_OUTPUT_KEYS

    session = project_live_user_page({"items": [LIVE_USER_PAYLOAD], "pages": PAGES}).items[0]
    assert set(session.model_dump(mode="json")) == LIVE_USER_SESSION_OUTPUT_KEYS

    assert set(project_disconnect_live_user({"disconnected": True}, 41).model_dump()) == {
        "disconnected",
        "liveUserId",
    }


async def test_every_published_output_property_is_camel_case_at_every_depth():
    """M2: no users tool publishes a snake_case output property, at any depth.

    The scan walks each tool's published output schema structurally (``$defs``, ``items``,
    ``anyOf``/``oneOf``/``allOf``), so a nested projection such as ``policies.macBinding``
    is covered rather than only the top-level object.
    """
    tools = {tool.name: tool for tool in await make_server().list_tools()}

    scanned: dict[str, set[str]] = {}
    offending: dict[str, list[str]] = {}
    for name, tool in tools.items():
        schema = tool.output_schema
        assert schema is not None, name
        properties = schema_property_names(schema)
        scanned[name] = properties
        bad = sorted(prop for prop in properties if not CAMEL_CASE_PATTERN.match(prop))
        if bad:
            offending[name] = bad

    # The scan must reach the nested projections, not only the top-level object.
    assert {"macBinding", "allowedNetworksIpv4"} <= scanned["network_user_get"]
    assert {"liveUserId", "clientType"} <= scanned["live_user_list"]
    assert {"administrativeAccess", "displayName"} <= scanned["user_list"]

    assert offending == {}


# -- Contract tests: users -------------------------------------------------------------


async def test_user_list_sends_the_documented_query(router: Any):
    route = router.get(f"{BASE}{USERS_PATH}").mock(
        return_value=httpx.Response(200, json={"items": [USER_SUMMARY_PAYLOAD], "pages": PAGES})
    )

    result = await call(
        make_server(),
        "user_list",
        {"page": 2, "page_size": 10, "page_total": True, "name_contains": "ali"},
    )

    request = route.calls.last.request
    assert request.method == "GET"
    assert dict(request.url.params) == {
        "nameContains": "ali",
        "page": "2",
        "pageSize": "10",
        "pageTotal": "true",
    }
    assert "content-type" not in request.headers
    assert result.is_error is False
    assert result.structured_content["items"][0]["name"] == "alice"
    assert result.structured_content["pages"]["current"] == 2


async def test_user_list_omits_optional_query_parameters(router: Any):
    route = router.get(f"{BASE}{USERS_PATH}").mock(
        return_value=httpx.Response(200, json={"items": [], "pages": PAGES})
    )

    await call(make_server(), "user_list", {})

    params = dict(route.calls.last.request.url.params)
    assert params == {"page": "1", "pageSize": "10", "pageTotal": "false"}
    assert not ({"limit", "offset", "cursor", "nameContains", "nameNotEquals"} & set(params))


async def test_user_list_sends_name_not_equals_and_omits_the_other_filter(router: Any):
    route = router.get(f"{BASE}{USERS_PATH}").mock(
        return_value=httpx.Response(200, json={"items": [], "pages": PAGES})
    )

    await call(make_server(), "user_list", {"name_not_equals": "bob"})

    params = dict(route.calls.last.request.url.params)
    assert params["nameNotEquals"] == "bob"
    assert "nameContains" not in params


@pytest.mark.parametrize(
    ("page", "page_size", "page_total"),
    [(1, 50, False), (2, 10, True), (7, 100, False)],
)
async def test_user_list_passes_first_middle_and_last_page_through_unchanged(
    router: Any, page: int, page_size: int, page_total: bool
):
    route = router.get(f"{BASE}{USERS_PATH}").mock(
        return_value=httpx.Response(200, json={"items": [], "pages": PAGES})
    )

    await call(
        make_server(),
        "user_list",
        {"page": page, "page_size": page_size, "page_total": page_total},
    )

    params = dict(route.calls.last.request.url.params)
    assert params["page"] == str(page)
    assert params["pageSize"] == str(page_size)
    assert params["pageTotal"] == str(page_total).lower()


async def test_network_user_list_sends_the_documented_query(router: Any):
    route = router.get(f"{BASE}{NETWORK_USERS_PATH}").mock(
        return_value=httpx.Response(200, json={"items": [NETWORK_USER_PAYLOAD], "pages": PAGES})
    )

    result = await call(
        make_server(),
        "network_user_list",
        {"page": 2, "page_size": 10, "page_total": True, "name_contains": "ops"},
    )

    request = route.calls.last.request
    assert request.method == "GET"
    assert dict(request.url.params) == {
        "nameContains": "ops",
        "page": "2",
        "pageSize": "10",
        "pageTotal": "true",
    }
    assert result.is_error is False
    assert result.structured_content["items"][0]["name"] == "user-ops"
    assert result.structured_content["items"][0]["policies"]["macBinding"] is False


async def test_network_user_get_encodes_the_name_as_one_path_segment(router: Any):
    route = router.get(f"{BASE}{NETWORK_USERS_PATH}/user%20ops").mock(
        return_value=httpx.Response(200, json=NETWORK_USER_PAYLOAD)
    )

    result = await call(make_server(), "network_user_get", {"id_or_name": "user ops"})

    assert str(route.calls.last.request.url) == f"{BASE}{NETWORK_USERS_PATH}/user%20ops"
    assert result.is_error is False
    assert result.structured_content["displayName"] == "Operations user"


async def test_network_user_get_encodes_a_slash_inside_the_name(router: Any):
    route = router.get(f"{BASE}{NETWORK_USERS_PATH}/a%2Fb").mock(
        return_value=httpx.Response(200, json=NETWORK_USER_PAYLOAD)
    )

    await call(make_server(), "network_user_get", {"id_or_name": "a/b"})

    assert str(route.calls.last.request.url) == f"{BASE}{NETWORK_USERS_PATH}/a%2Fb"


async def test_network_user_get_accepts_a_uuid(router: Any):
    route = router.get(f"{BASE}{NETWORK_USERS_PATH}/{UUID}").mock(
        return_value=httpx.Response(200, json=NETWORK_USER_PAYLOAD)
    )

    await call(make_server(), "network_user_get", {"id_or_name": UUID})

    assert str(route.calls.last.request.url) == f"{BASE}{NETWORK_USERS_PATH}/{UUID}"


async def test_network_user_get_maps_not_found(router: Any):
    router.get(f"{BASE}{NETWORK_USERS_PATH}/missing").mock(
        return_value=httpx.Response(
            404, json={"error": "notFound", "message": "Resource not found."}
        )
    )

    result = await call(make_server(), "network_user_get", {"id_or_name": "missing"})

    assert result.is_error is True
    assert "does not exist" in result.content[0].text


async def test_network_user_create_posts_the_documented_body(router: Any):
    route = router.post(f"{BASE}{NETWORK_USERS_PATH}").mock(
        return_value=httpx.Response(201, json=NETWORK_USER_PAYLOAD)
    )

    result = await call(
        make_server(),
        "network_user_create",
        {
            "name": "user-ops",
            "display_name": "Operations user",
            "password": PASSWORD,
            "group": {"name": "users"},
            "description": "Operations network user account.",
            "active": True,
            "email_addresses": ["user-ops@example.com"],
            "policies": {
                "surfing_quota_policy": {"name": "default-surfing-quota"},
                "allowed_networks_ipv4": {"any": True},
                "simultaneous_logins": {"limit": 3},
                "mac_binding": False,
            },
            "vpn_access": {"l2tp": False, "pptp": False, "ipsec_vpn_remote_access": False},
            "email_quarantine_digest": True,
        },
    )

    request = route.calls.last.request
    assert request.method == "POST"
    assert request.headers["content-type"] == "application/json"
    assert body_of(request) == {
        "name": "user-ops",
        "displayName": "Operations user",
        "password": PASSWORD,
        "group": {"name": "users"},
        "description": "Operations network user account.",
        "active": True,
        "emailAddresses": ["user-ops@example.com"],
        "policies": {
            "surfingQuotaPolicy": {"name": "default-surfing-quota"},
            "allowedNetworksIpv4": {"any": True},
            "simultaneousLogins": {"limit": 3},
            "macBinding": False,
        },
        "vpnAccess": {"l2tp": False, "pptp": False, "ipsecVpnRemoteAccess": False},
        "emailQuarantineDigest": True,
    }
    assert result.is_error is False
    assert result.structured_content["name"] == "user-ops"


async def test_network_user_create_sends_only_the_required_fields(router: Any):
    route = router.post(f"{BASE}{NETWORK_USERS_PATH}").mock(
        return_value=httpx.Response(201, json=NETWORK_USER_PAYLOAD)
    )

    await call(make_server(), "network_user_create", MINIMAL_CREATE)

    assert body_of(route.calls.last.request) == {
        "name": "user-ops",
        "displayName": "Operations user",
        "password": PASSWORD,
        "group": {"name": "users"},
    }


def test_network_user_group_must_be_a_name_reference():
    """A bare string is rejected: the appliance answers 400 invalidRequest ("Invalid group.")."""
    with pytest.raises(ValidationError):
        NetworkUserCreateInput(
            name="user-ops",
            display_name="Operations user",
            password=PASSWORD,
            group="users",  # type: ignore[arg-type]
        )

    request = NetworkUserCreateInput(
        name="user-ops",
        display_name="Operations user",
        password=PASSWORD,
        group={"name": "users"},
    )
    assert request.group.name == "users"


def test_network_user_group_matches_the_contract_reference_shape():
    """The published input and the wire body use the documented ``{name}`` reference."""
    spec = load_spec()
    body = spec["paths"][NETWORK_USERS_PATH]["post"]["requestBody"]["content"]["application/json"][
        "schema"
    ]["allOf"][0]
    declared = body["properties"]["group"]
    assert declared["type"] == "object"
    assert declared["required"] == ["name"]

    assert NetworkUserCreateInput.model_fields["group"].annotation is UserGroupRefInput
    assert NetworkUserUpdateInput.model_fields["group"].annotation == (UserGroupRefInput | None)

    schema = NetworkUserCreateInput.model_json_schema()
    reference = schema["properties"]["group"]["$ref"]
    resolved = schema["$defs"][reference.rsplit("/", 1)[-1]]
    assert resolved["type"] == "object"
    assert resolved["required"] == ["name"]
    assert resolved["additionalProperties"] is False


async def test_network_user_create_surfaces_the_appliance_error_code(router: Any):
    """D2: a 400 keeps the sanitized appliance ``error`` code and drops the free-text message."""
    router.post(f"{BASE}{NETWORK_USERS_PATH}").mock(
        return_value=httpx.Response(
            400, json={"error": "invalidInputPassword", "message": "Invalid password."}
        )
    )

    result = await call(make_server(), "network_user_create", MINIMAL_CREATE)

    assert result.is_error is True
    message = result.content[0].text
    assert "[error: invalidInputPassword]" in message
    assert "Invalid password." not in message


async def test_network_user_create_never_returns_the_password(router: Any):
    echoed = {**NETWORK_USER_PAYLOAD, "password": PASSWORD, "passwordHash": "$6$leaked"}
    router.post(f"{BASE}{NETWORK_USERS_PATH}").mock(return_value=httpx.Response(201, json=echoed))

    result = await call(make_server(), "network_user_create", MINIMAL_CREATE)

    assert result.is_error is False
    dumped = json.dumps(result.structured_content)
    assert PASSWORD not in dumped
    assert "password" not in dumped
    assert "leaked" not in dumped


async def test_network_user_update_patches_only_provided_fields(router: Any):
    route = router.patch(f"{BASE}{NETWORK_USERS_PATH}/user-ops").mock(
        return_value=httpx.Response(200, json=NETWORK_USER_PAYLOAD)
    )

    result = await call(
        make_server(), "network_user_update", {"id_or_name": "user-ops", "description": "Updated"}
    )

    request = route.calls.last.request
    assert request.method == "PATCH"
    assert request.headers["content-type"] == "application/json"
    assert request.headers["content-type"] != "application/merge-patch+json"
    assert body_of(request) == {"description": "Updated"}
    assert result.is_error is False


async def test_network_user_update_sends_nested_merge_patch_objects(router: Any):
    route = router.patch(f"{BASE}{NETWORK_USERS_PATH}/user-ops").mock(
        return_value=httpx.Response(200, json=NETWORK_USER_PAYLOAD)
    )

    await call(
        make_server(),
        "network_user_update",
        {"id_or_name": "user-ops", "policies": {"mac_binding": True}},
    )

    assert body_of(route.calls.last.request) == {"policies": {"macBinding": True}}


async def test_network_user_update_sends_a_password_only_when_provided(router: Any):
    route = router.patch(f"{BASE}{NETWORK_USERS_PATH}/user-ops").mock(
        return_value=httpx.Response(200, json=NETWORK_USER_PAYLOAD)
    )

    await call(
        make_server(),
        "network_user_update",
        {"id_or_name": "user-ops", "active": False, "password": PASSWORD},
    )

    assert body_of(route.calls.last.request) == {"active": False, "password": PASSWORD}


async def test_network_user_delete_sends_delete_without_a_body(router: Any):
    route = router.delete(f"{BASE}{NETWORK_USERS_PATH}/user-ops").mock(
        return_value=httpx.Response(200, json={"deleted": True})
    )

    result = await call(make_server(), "network_user_delete", {"id_or_name": "user-ops"})

    request = route.calls.last.request
    assert request.method == "DELETE"
    assert request.content == b""
    assert "content-type" not in request.headers
    assert result.is_error is False
    assert result.structured_content == {"deleted": True, "idOrName": "user-ops"}


# -- Contract tests: live sessions -----------------------------------------------------


async def test_live_user_list_sends_no_query_parameters(router: Any):
    route = router.get(f"{BASE}{LIVE_USERS_PATH}").mock(
        return_value=httpx.Response(200, json={"items": [LIVE_USER_PAYLOAD], "pages": PAGES})
    )

    result = await call(make_server(), "live_user_list", {})

    request = route.calls.last.request
    assert request.method == "GET"
    assert str(request.url) == f"{BASE}{LIVE_USERS_PATH}"
    assert request.content == b""
    assert result.is_error is False
    session = result.structured_content["items"][0]
    assert session["liveUserId"] == 41
    assert session["clientType"] == "sslVpnTunnel"
    assert result.structured_content["pages"]["maxSize"] == 100


async def test_live_user_list_accepts_an_empty_collection(router: Any):
    router.get(f"{BASE}{LIVE_USERS_PATH}").mock(
        return_value=httpx.Response(
            200, json={"items": [], "pages": {"current": 1, "size": 50, "maxSize": 100}}
        )
    )

    result = await call(make_server(), "live_user_list", {})

    assert result.is_error is False
    assert result.structured_content["items"] == []


async def test_live_user_list_description_does_not_name_an_unregistered_tool():
    """L2: in read-only mode `live_user_disconnect` is not registered, so it must not be named."""
    read_only_tools = {tool.name: tool for tool in await make_server(read_only=True).list_tools()}
    assert "live_user_disconnect" not in read_only_tools
    description = read_only_tools["live_user_list"].description
    assert "live_user_disconnect" not in description
    assert "read-only mode" in description

    writable_tools = {tool.name: tool for tool in await make_server().list_tools()}
    assert "live_user_disconnect" in writable_tools
    assert "live_user_disconnect" in writable_tools["live_user_list"].description


async def test_live_user_disconnect_posts_the_documented_body(router: Any):
    route = router.post(f"{BASE}{LIVE_USERS_DISCONNECT_PATH}").mock(
        return_value=httpx.Response(200, json={"disconnected": True})
    )

    result = await call(
        make_server(),
        "live_user_disconnect",
        {"live_user_id": 41, "message": "Session closed by administrator"},
    )

    request = route.calls.last.request
    assert request.method == "POST"
    assert request.headers["content-type"] == "application/json"
    assert body_of(request) == {
        "liveUserId": 41,
        "message": "Session closed by administrator",
    }
    assert result.is_error is False
    assert result.structured_content == {"disconnected": True, "liveUserId": 41}


# -- Error mapping ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("tool", "payload", "method", "path", "status", "fragment"),
    [
        ("user_list", {}, "GET", USERS_PATH, 400, "rejected the request as invalid"),
        ("user_list", {}, "GET", USERS_PATH, 401, "authentication failed"),
        ("user_list", {}, "GET", USERS_PATH, 403, "not allowed"),
        ("user_list", {}, "GET", USERS_PATH, 500, "unexpected error"),
        ("network_user_list", {}, "GET", NETWORK_USERS_PATH, 403, "not allowed"),
        (
            "network_user_get",
            {"id_or_name": "user-ops"},
            "GET",
            f"{NETWORK_USERS_PATH}/user-ops",
            404,
            "does not exist",
        ),
        ("network_user_create", MINIMAL_CREATE, "POST", NETWORK_USERS_PATH, 409, "conflicts"),
        (
            "network_user_update",
            {"id_or_name": "user-ops", "active": False},
            "PATCH",
            f"{NETWORK_USERS_PATH}/user-ops",
            404,
            "does not exist",
        ),
        (
            "network_user_delete",
            {"id_or_name": "user-ops"},
            "DELETE",
            f"{NETWORK_USERS_PATH}/user-ops",
            500,
            "unexpected error",
        ),
        ("live_user_list", {}, "GET", LIVE_USERS_PATH, 500, "unexpected error"),
        (
            "live_user_disconnect",
            {"live_user_id": 41, "message": "bye"},
            "POST",
            LIVE_USERS_DISCONNECT_PATH,
            400,
            "rejected the request as invalid",
        ),
        (
            "live_user_disconnect",
            {"live_user_id": 41, "message": "bye"},
            "POST",
            LIVE_USERS_DISCONNECT_PATH,
            401,
            "authentication failed",
        ),
        (
            "live_user_disconnect",
            {"live_user_id": 41, "message": "bye"},
            "POST",
            LIVE_USERS_DISCONNECT_PATH,
            403,
            "not allowed",
        ),
        (
            "live_user_disconnect",
            {"live_user_id": 41, "message": "bye"},
            "POST",
            LIVE_USERS_DISCONNECT_PATH,
            500,
            "unexpected error",
        ),
    ],
)
async def test_documented_errors_map_to_sanitized_tool_errors(
    router: Any,
    tool: str,
    payload: dict[str, Any],
    method: str,
    path: str,
    status: int,
    fragment: str,
):
    route = getattr(router, method.lower())(f"{BASE}{path}").mock(
        return_value=httpx.Response(
            status, json={"error": "someError", "message": "raw internal detail"}
        )
    )

    result = await call(make_server(), tool, payload)

    assert route.called
    assert result.is_error is True
    text = result.content[0].text
    assert fragment in text
    assert f"HTTP {status}" in text
    assert "raw internal detail" not in text


async def test_permission_denied_and_not_found_are_distinguishable(router: Any):
    router.get(f"{BASE}{NETWORK_USERS_PATH}/denied").mock(
        return_value=httpx.Response(403, json={"error": "forbidden"})
    )
    router.get(f"{BASE}{NETWORK_USERS_PATH}/missing").mock(
        return_value=httpx.Response(404, json={"error": "notFound"})
    )

    denied = await call(make_server(), "network_user_get", {"id_or_name": "denied"})
    missing = await call(make_server(), "network_user_get", {"id_or_name": "missing"})

    assert "not allowed" in denied.content[0].text
    assert "does not exist" in missing.content[0].text
    assert denied.content[0].text != missing.content[0].text


async def test_non_object_bodies_are_rejected_with_a_sanitized_error(router: Any):
    router.get(f"{BASE}{NETWORK_USERS_PATH}/user-ops").mock(
        return_value=httpx.Response(200, json=["not", "an", "object"])
    )

    result = await call(make_server(), "network_user_get", {"id_or_name": "user-ops"})

    assert result.is_error is True
    assert "unexpected error" in result.content[0].text
    assert "non-object body" not in result.content[0].text


async def test_a_malformed_network_user_payload_is_a_sanitized_tool_error(router: Any):
    """A 200 body that does not match the output model becomes a sanitized ToolError."""
    router.get(f"{BASE}{NETWORK_USERS_PATH}/user-ops").mock(
        return_value=httpx.Response(200, json={**NETWORK_USER_PAYLOAD, "active": "not-a-boolean"})
    )

    result = await call(make_server(), "network_user_get", {"id_or_name": "user-ops"})

    assert result.is_error is True
    text = result.content[0].text
    assert "does not match the documented schema" in text
    assert "not-a-boolean" not in text
    assert KEY not in text


# -- Credential redaction --------------------------------------------------------------


async def test_password_never_appears_in_output_errors_or_logs(router: Any, caplog: Any):
    caplog.set_level(logging.DEBUG)
    route = router.post(f"{BASE}{NETWORK_USERS_PATH}").mock(
        return_value=httpx.Response(
            400,
            json={
                "error": "badRequest",
                "message": f"invalid password '{PASSWORD}'",
            },
        )
    )

    result = await call(make_server(), "network_user_create", MINIMAL_CREATE)

    # The password was really sent, so the assertions below are meaningful.
    assert body_of(route.calls.last.request)["password"] == PASSWORD
    assert result.is_error is True
    assert PASSWORD not in result.content[0].text
    assert PASSWORD not in json.dumps(result.structured_content)
    assert PASSWORD not in caplog.text


async def test_password_never_appears_in_a_successful_response(router: Any, caplog: Any):
    caplog.set_level(logging.DEBUG)
    router.post(f"{BASE}{NETWORK_USERS_PATH}").mock(
        return_value=httpx.Response(201, json={**NETWORK_USER_PAYLOAD, "password": PASSWORD})
    )

    result = await call(make_server(), "network_user_create", MINIMAL_CREATE)

    assert result.is_error is False
    assert PASSWORD not in json.dumps(result.structured_content)
    assert PASSWORD not in caplog.text


# -- Discovery and annotations ---------------------------------------------------------


async def test_all_eight_tools_are_registered_with_actionable_descriptions():
    tools = {tool.name: tool for tool in await make_server().list_tools()}

    assert set(tools) == ALL_TOOL_NAMES
    for tool in tools.values():
        assert tool.title
        assert tool.description
    assert "getUsers" in tools["user_list"].description
    assert "getNetworkUsers" in tools["network_user_list"].description
    assert "getNetworkUser" in tools["network_user_get"].description
    assert "createNetworkUser" in tools["network_user_create"].description
    assert "updateNetworkUser" in tools["network_user_update"].description
    assert "deleteNetworkUser" in tools["network_user_delete"].description
    assert "getLiveUsers" in tools["live_user_list"].description
    assert "disconnectLiveUser" in tools["live_user_disconnect"].description


async def test_read_only_mode_registers_only_the_read_tools():
    tools = {tool.name for tool in await make_server(read_only=True).list_tools()}

    assert tools == READ_TOOL_NAMES
    assert tools.isdisjoint(MUTATION_TOOL_NAMES)


async def test_write_mode_registers_every_tool():
    tools = {tool.name for tool in await make_server().list_tools()}

    assert tools == ALL_TOOL_NAMES


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        (
            "user_list",
            {"title": "List authentication users", "readOnlyHint": True, "openWorldHint": True},
        ),
        (
            "network_user_list",
            {"title": "List network users", "readOnlyHint": True, "openWorldHint": True},
        ),
        (
            "network_user_get",
            {"title": "Get network user", "readOnlyHint": True, "openWorldHint": True},
        ),
        (
            "network_user_create",
            {
                "title": "Create network user",
                "readOnlyHint": False,
                "destructiveHint": False,
                "idempotentHint": False,
                "openWorldHint": True,
            },
        ),
        (
            "network_user_update",
            {
                "title": "Update network user",
                "readOnlyHint": False,
                "destructiveHint": False,
                "idempotentHint": True,
                "openWorldHint": True,
            },
        ),
        (
            "network_user_delete",
            {
                "title": "Delete network user",
                "readOnlyHint": False,
                "destructiveHint": True,
                "idempotentHint": True,
                "openWorldHint": True,
            },
        ),
        (
            "live_user_list",
            {"title": "List live user sessions", "readOnlyHint": True, "openWorldHint": True},
        ),
        (
            "live_user_disconnect",
            {
                "title": "Disconnect live user session",
                "readOnlyHint": False,
                "destructiveHint": True,
                "idempotentHint": False,
                "openWorldHint": True,
            },
        ),
    ],
)
async def test_annotations_match_the_tool_kind(name: str, expected: dict[str, Any]):
    tools = {tool.name: tool for tool in await make_server().list_tools()}

    assert tools[name].annotations is not None
    assert tools[name].annotations.model_dump(by_alias=True, exclude_none=True) == expected


async def test_input_schemas_are_closed_and_hide_the_context():
    tools = {tool.name: tool for tool in await make_server().list_tools()}

    for name, tool in tools.items():
        schema = tool.input_schema
        assert schema["type"] == "object", name
        # Arguments are flat: the request model's fields are the root properties, and the
        # root is closed so an unknown argument is rejected rather than silently dropped.
        assert schema["additionalProperties"] is False, name
        assert "ctx" not in schema["properties"], name
        assert request_model_schema(tool)["additionalProperties"] is False, name


async def test_output_schemas_are_object_rooted():
    tools = {tool.name: tool for tool in await make_server().list_tools()}

    for name, tool in tools.items():
        schema = tool.output_schema
        assert schema is not None, name
        assert schema["type"] == "object", name
        assert schema["properties"], name
        assert schema["required"], name


async def test_password_inputs_are_marked_write_only():
    tools = {tool.name: tool for tool in await make_server().list_tools()}

    for name in ("network_user_create", "network_user_update"):
        password = find_password_schema(request_model_schema(tools[name])["properties"]["password"])
        assert password.get("format") == "password", name
        assert password.get("writeOnly") is True, name


async def test_live_user_list_input_exposes_no_page_parameters():
    tools = {tool.name: tool for tool in await make_server().list_tools()}

    schema = request_model_schema(tools["live_user_list"])
    assert schema["properties"] == {}


async def test_login_logout_and_privileged_operations_are_not_registered():
    names = {tool.name for tool in await make_server().list_tools()}

    for forbidden in (
        "network_user_login",
        "network_user_logout",
        "administrator_create",
        "administrator_update",
        "administrator_delete",
        "user_group_create",
    ):
        assert forbidden not in names
    assert not any(
        token in name for name in names for token in ("login", "logout", "admin", "group")
    )


# -- Contract cross-checks -------------------------------------------------------------


def test_path_constants_match_the_contract():
    paths = load_spec()["paths"]

    assert USERS_PATH in paths
    assert NETWORK_USERS_PATH in paths
    assert LIVE_USERS_PATH in paths
    assert LIVE_USERS_DISCONNECT_PATH in paths


def test_every_tool_maps_to_an_audited_operation_id():
    expected = {
        "getUsers",
        "getNetworkUsers",
        "getNetworkUser",
        "createNetworkUser",
        "updateNetworkUser",
        "deleteNetworkUser",
        "getLiveUsers",
        "disconnectLiveUser",
    }
    spec = load_spec()
    operation_ids = {
        operation["operationId"]
        for path_item in spec["paths"].values()
        for operation in path_item.values()
        if isinstance(operation, dict) and "operationId" in operation
    }

    assert expected <= operation_ids


def test_live_user_client_types_match_the_contract():
    spec = load_spec()
    items = spec["paths"][LIVE_USERS_PATH]["get"]["responses"]["200"]["content"][
        "application/json"
    ]["schema"]["properties"]["items"]["items"]
    declared = items["properties"]["clientType"]["enum"]

    assert len(declared) == 20
    assert set(declared) == LIVE_USER_CLIENT_TYPES


def test_network_user_create_contract_requires_the_same_fields():
    spec = load_spec()
    body = spec["paths"][NETWORK_USERS_PATH]["post"]["requestBody"]["content"]["application/json"][
        "schema"
    ]["allOf"][0]

    assert set(body["required"]) == {"name", "displayName", "password", "group"}
    wire_fields = {
        field.serialization_alias or name
        for name, field in NetworkUserCreateInput.model_fields.items()
    }
    assert wire_fields == set(body["properties"])
