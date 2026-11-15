"""Contract, model and discovery tests for the address, group, MAC and country tools (#29).

Every test runs against RESPX: no firewall, no network, no real credentials. The contract
tests prove the exact request each tool builds (method, path, query, headers, body,
content type) and the projection it returns. Model tests prove the families stay distinct
and that closed inputs reject a mixed or malformed payload. Discovery tests prove the
published surface, the annotations and the read-only filter.
"""

from __future__ import annotations

import json
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator

import httpx
import pytest
import respx
from mcp import Client
from mcp.server.mcpserver import MCPServer
from pydantic import TypeAdapter, ValidationError

from sophos_firewall_mcp.config import Settings
from sophos_firewall_mcp.context import AppContext
from sophos_firewall_mcp.models import objects as object_models
from sophos_firewall_mcp.models.objects import (
    CountryGroup,
    DeleteResult,
    FqdnAddress,
    FqdnAddressCreate,
    Ipv4AddressCreate,
    Ipv4AddressCreateIp,
    Ipv4AddressCreateIpList,
    Ipv4AddressCreateIpRange,
    Ipv4AddressCreateNetwork,
    Ipv4AddressGroup,
    Ipv4AddressGroupCreate,
    Ipv4AddressIp,
    Ipv4AddressListInput,
    Ipv4AddressResult,
    Ipv4AddressUpdateInput,
    Ipv6AddressCreate,
    Ipv6AddressCreateIp,
    Ipv6AddressCreateIpList,
    Ipv6AddressCreateIpRange,
    Ipv6AddressCreateNetwork,
    Ipv6AddressIp,
    MacAddressCreate,
    MacAddressCreateList,
    MacAddressCreateSingle,
    MacAddressMacAddress,
    MacAddressUpdateInput,
    MemberRef,
    ObjectIdentifierInput,
)
from sophos_firewall_mcp.server import create_server
from sophos_firewall_mcp.tools.hosts_objects import register_objects_tools

HOST = "fw.example.com"
KEY = "sfos_test_key_0123456789abcdef"
BASE = f"https://{HOST}:4444/api/firewall-config/v1"
UUID = "3f2504e0-4f89-11d3-9a0c-0305e82c3301"
PAGES = {"current": 2, "size": 10, "maxSize": 100, "total": 47, "items": 10}

# -- Published surface -----------------------------------------------------------------

HOSTS_READ_TOOLS = {
    "address_list_ipv4",
    "address_get_ipv4",
    "address_list_ipv6",
    "address_get_ipv6",
    "address_list_fqdn",
    "address_get_fqdn",
    "address_group_list_ipv4",
    "address_group_get_ipv4",
    "address_group_list_ipv6",
    "address_group_get_ipv6",
    "address_group_list_fqdn",
    "address_group_get_fqdn",
    "mac_address_list",
    "mac_address_get",
    "country_group_list",
    "country_group_get",
}

HOSTS_MUTATION_TOOLS = {
    "address_create_ipv4",
    "address_update_ipv4",
    "address_delete_ipv4",
    "address_create_ipv6",
    "address_update_ipv6",
    "address_delete_ipv6",
    "address_create_fqdn",
    "address_update_fqdn",
    "address_delete_fqdn",
    "address_group_create_ipv4",
    "address_group_update_ipv4",
    "address_group_delete_ipv4",
    "address_group_create_ipv6",
    "address_group_update_ipv6",
    "address_group_delete_ipv6",
    "address_group_create_fqdn",
    "address_group_update_fqdn",
    "address_group_delete_fqdn",
    "mac_address_create",
    "mac_address_update",
    "mac_address_delete",
}

SERVICE_READ_TOOLS = {
    "service_list",
    "service_get",
    "service_group_list",
    "service_group_get",
}

SERVICE_MUTATION_TOOLS = {
    "service_create",
    "service_update",
    "service_delete",
    "service_group_create",
    "service_group_update",
    "service_group_delete",
}

# -- Fixtures and helpers --------------------------------------------------------------


def make_settings(read_only: bool = False) -> Settings:
    return Settings(
        host=HOST,
        port=4444,
        api_key=KEY,
        verify_ssl=False,
        timeout=5.0,
        read_only_mode=read_only,
    )


def make_server(read_only: bool = False) -> MCPServer[AppContext]:
    return create_server(make_settings(read_only), domains=[register_objects_tools])


@asynccontextmanager
async def open_client(read_only: bool = False) -> AsyncIterator[Client]:
    async with Client(make_server(read_only)) as client:
        yield client


async def tools_by_name(server: MCPServer[AppContext]) -> dict[str, Any]:
    return {tool.name: tool for tool in await server.list_tools()}


@pytest.fixture
def router() -> Any:
    with respx.mock(assert_all_called=False) as mocked:
        yield mocked


def dig(payload: Any, path: tuple[Any, ...]) -> Any:
    for key in path:
        payload = payload[key]
    return payload


def assert_authenticated(request: httpx.Request) -> None:
    assert request.headers["authorization"] == f"Bearer {KEY}"
    assert request.headers["accept"] == "application/json"


def property_names(schema: dict[str, Any]) -> set[str]:
    """Collect every property name reachable from a published JSON schema."""
    names = set(schema.get("properties", {}))
    for definition in schema.get("$defs", {}).values():
        names |= property_names(definition)
    for key in ("anyOf", "oneOf"):
        for sub_schema in schema.get(key, []):
            names |= property_names(sub_schema)
    return names


# -- Wire payloads ---------------------------------------------------------------------

IPV4_ITEM = {
    "id": UUID,
    "name": "web",
    "type": "ipv4Address",
    "ipv4Address": "203.0.113.10",
}
IPV6_ITEM = {
    "id": UUID,
    "name": "v6-web",
    "type": "ipv6Address",
    "ipv6Address": "2001:db8::10",
}
FQDN_ITEM = {"id": UUID, "name": "example", "fqdn": "example.com"}
IPV4_GROUP_ITEM = {"id": UUID, "name": "grp4", "ipv4Addresses": [{"name": "web"}]}
IPV6_GROUP_ITEM = {"id": UUID, "name": "grp6", "ipv6Addresses": [{"name": "v6-web"}]}
FQDN_GROUP_ITEM = {"id": UUID, "name": "grpf", "fqdns": [{"name": "example"}]}
MAC_ITEM = {
    "id": UUID,
    "name": "printer",
    "type": "macAddress",
    "macAddress": "00:11:22:33:44:55",
}
COUNTRY_ITEM = {
    "id": UUID,
    "name": "Europe",
    "countries": [{"name": "Germany"}, {"name": "France"}],
}

# -- Contract cases --------------------------------------------------------------------

LIST_CASES = [
    ("address_list_ipv4", "/network/addresses/ipv4", IPV4_ITEM),
    ("address_list_ipv6", "/network/addresses/ipv6", IPV6_ITEM),
    ("address_list_fqdn", "/network/addresses/fqdn", FQDN_ITEM),
    ("address_group_list_ipv4", "/network/address-groups/ipv4", IPV4_GROUP_ITEM),
    ("address_group_list_ipv6", "/network/address-groups/ipv6", IPV6_GROUP_ITEM),
    ("address_group_list_fqdn", "/network/address-groups/fqdn", FQDN_GROUP_ITEM),
    ("mac_address_list", "/network/addresses/mac", MAC_ITEM),
    ("country_group_list", "/network/address-groups/country", COUNTRY_ITEM),
]

GET_CASES = [
    (
        "address_get_ipv4",
        "/network/addresses/ipv4",
        IPV4_ITEM,
        ("address", "type"),
        "ipv4Address",
    ),
    (
        "address_get_ipv6",
        "/network/addresses/ipv6",
        IPV6_ITEM,
        ("address", "type"),
        "ipv6Address",
    ),
    ("address_get_fqdn", "/network/addresses/fqdn", FQDN_ITEM, ("fqdn",), "example.com"),
    (
        "address_group_get_ipv4",
        "/network/address-groups/ipv4",
        IPV4_GROUP_ITEM,
        ("ipv4Addresses", 0, "name"),
        "web",
    ),
    (
        "address_group_get_ipv6",
        "/network/address-groups/ipv6",
        IPV6_GROUP_ITEM,
        ("ipv6Addresses", 0, "name"),
        "v6-web",
    ),
    (
        "address_group_get_fqdn",
        "/network/address-groups/fqdn",
        FQDN_GROUP_ITEM,
        ("fqdns", 0, "name"),
        "example",
    ),
    ("mac_address_get", "/network/addresses/mac", MAC_ITEM, ("address", "type"), "macAddress"),
    (
        "country_group_get",
        "/network/address-groups/country",
        COUNTRY_ITEM,
        ("countries", 0, "name"),
        "Germany",
    ),
]

CREATE_CASES = [
    (
        "address_create_ipv4",
        "/network/addresses/ipv4",
        {"name": "web", "type": "ipv4Address", "ipv4Address": "203.0.113.10"},
        IPV4_ITEM,
        ("address", "type"),
        "ipv4Address",
    ),
    (
        "address_create_ipv6",
        "/network/addresses/ipv6",
        {
            "name": "v6-net",
            "type": "ipv6Network",
            "ipv6NetworkAddress": "2001:db8::",
            "prefixLength": 64,
        },
        {
            "id": UUID,
            "name": "v6-net",
            "type": "ipv6Network",
            "ipv6NetworkAddress": "2001:db8::",
            "prefixLength": 64,
        },
        ("address", "type"),
        "ipv6Network",
    ),
    (
        "address_create_fqdn",
        "/network/addresses/fqdn",
        {"name": "example", "fqdn": "example.com"},
        FQDN_ITEM,
        ("fqdn",),
        "example.com",
    ),
    (
        "address_group_create_ipv4",
        "/network/address-groups/ipv4",
        {"name": "grp4", "ipv4Addresses": [{"name": "web"}]},
        IPV4_GROUP_ITEM,
        ("ipv4Addresses", 0, "name"),
        "web",
    ),
    (
        "address_group_create_ipv6",
        "/network/address-groups/ipv6",
        {"name": "grp6", "ipv6Addresses": [{"name": "v6-web"}]},
        IPV6_GROUP_ITEM,
        ("ipv6Addresses", 0, "name"),
        "v6-web",
    ),
    (
        "address_group_create_fqdn",
        "/network/address-groups/fqdn",
        {"name": "grpf", "fqdns": [{"name": "example"}]},
        FQDN_GROUP_ITEM,
        ("fqdns", 0, "name"),
        "example",
    ),
    (
        "mac_address_create",
        "/network/addresses/mac",
        {"name": "printer", "macAddress": "00:11:22:33:44:55"},
        MAC_ITEM,
        ("address", "type"),
        "macAddress",
    ),
    (
        "mac_address_create",
        "/network/addresses/mac",
        {"name": "printers", "macAddresses": ["00:11:22:33:44:55"]},
        {
            "id": UUID,
            "name": "printers",
            "type": "macList",
            "macAddresses": ["00:11:22:33:44:55"],
        },
        ("address", "type"),
        "macList",
    ),
]

UPDATE_CASES = [
    (
        "address_update_ipv4",
        "/network/addresses/ipv4",
        {
            "id_or_name": "web",
            "description": None,
            "ipv4Addresses": ["203.0.113.10", "203.0.113.11"],
        },
        {"description": None, "ipv4Addresses": ["203.0.113.10", "203.0.113.11"]},
        {
            "id": UUID,
            "name": "web",
            "type": "ipv4List",
            "ipv4Addresses": ["203.0.113.10", "203.0.113.11"],
        },
        ("address", "type"),
        "ipv4List",
    ),
    (
        "address_update_ipv6",
        "/network/addresses/ipv6",
        {"id_or_name": "web", "prefixLength": 56},
        {"prefixLength": 56},
        {
            "id": UUID,
            "name": "v6-net",
            "type": "ipv6Network",
            "ipv6NetworkAddress": "2001:db8::",
            "prefixLength": 56,
        },
        ("address", "prefixLength"),
        56,
    ),
    (
        "address_update_fqdn",
        "/network/addresses/fqdn",
        {"id_or_name": "web", "fqdn": "new.example.com"},
        {"fqdn": "new.example.com"},
        {"id": UUID, "name": "example", "fqdn": "new.example.com"},
        ("fqdn",),
        "new.example.com",
    ),
    (
        "address_group_update_ipv4",
        "/network/address-groups/ipv4",
        {"id_or_name": "web", "ipv4Addresses": [{"name": "web"}]},
        {"ipv4Addresses": [{"name": "web"}]},
        IPV4_GROUP_ITEM,
        ("ipv4Addresses", 0, "name"),
        "web",
    ),
    (
        "address_group_update_ipv6",
        "/network/address-groups/ipv6",
        {"id_or_name": "web", "ipv6Addresses": [{"name": "v6-web"}]},
        {"ipv6Addresses": [{"name": "v6-web"}]},
        IPV6_GROUP_ITEM,
        ("ipv6Addresses", 0, "name"),
        "v6-web",
    ),
    (
        "address_group_update_fqdn",
        "/network/address-groups/fqdn",
        {"id_or_name": "web", "fqdns": [{"name": "example"}]},
        {"fqdns": [{"name": "example"}]},
        FQDN_GROUP_ITEM,
        ("fqdns", 0, "name"),
        "example",
    ),
    (
        "mac_address_update",
        "/network/addresses/mac",
        {"id_or_name": "web", "macAddresses": ["00:11:22:33:44:55"]},
        {"macAddresses": ["00:11:22:33:44:55"]},
        {
            "id": UUID,
            "name": "printers",
            "type": "macList",
            "macAddresses": ["00:11:22:33:44:55"],
        },
        ("address", "type"),
        "macList",
    ),
]

DELETE_CASES = [
    ("address_delete_ipv4", "/network/addresses/ipv4"),
    ("address_delete_ipv6", "/network/addresses/ipv6"),
    ("address_delete_fqdn", "/network/addresses/fqdn"),
    ("address_group_delete_ipv4", "/network/address-groups/ipv4"),
    ("address_group_delete_ipv6", "/network/address-groups/ipv6"),
    ("address_group_delete_fqdn", "/network/address-groups/fqdn"),
    ("mac_address_delete", "/network/addresses/mac"),
]


# -- Discovery and annotations ---------------------------------------------------------


async def test_write_mode_publishes_the_full_objects_surface():
    names = set(await tools_by_name(make_server()))

    assert names == (
        HOSTS_READ_TOOLS | HOSTS_MUTATION_TOOLS | SERVICE_READ_TOOLS | SERVICE_MUTATION_TOOLS
    )
    assert len(names) == 47


async def test_read_only_mode_publishes_only_read_tools():
    names = set(await tools_by_name(make_server(read_only=True)))

    assert names == HOSTS_READ_TOOLS | SERVICE_READ_TOOLS
    assert len(names) == 20


async def test_country_groups_have_no_mutation_tools():
    names = set(await tools_by_name(make_server()))

    assert not any(
        name.startswith("country_group_")
        and name
        not in {
            "country_group_list",
            "country_group_get",
        }
        for name in names
    )


async def test_every_tool_has_a_title_and_a_description():
    tools = await tools_by_name(make_server())

    for tool in tools.values():
        assert tool.title
        assert len(tool.description) >= 40


async def test_read_tools_declare_only_read_annotations():
    tools = await tools_by_name(make_server())

    for name in HOSTS_READ_TOOLS | SERVICE_READ_TOOLS:
        annotations = tools[name].annotations
        assert annotations.read_only_hint is True
        assert annotations.destructive_hint is None
        assert annotations.idempotent_hint is None


async def test_mutation_tools_declare_write_hints():
    tools = await tools_by_name(make_server())

    for name in HOSTS_MUTATION_TOOLS | SERVICE_MUTATION_TOOLS:
        annotations = tools[name].annotations
        assert annotations.read_only_hint is False
        assert annotations.destructive_hint is not None
        assert annotations.idempotent_hint is not None


async def test_input_schemas_are_closed_and_hide_the_context():
    tools = await tools_by_name(make_server())

    for tool in tools.values():
        schema = tool.input_schema
        assert schema["type"] == "object"
        assert schema["required"] == ["request"]
        assert "ctx" not in schema["properties"]
        for definition in schema.get("$defs", {}).values():
            assert definition.get("additionalProperties") is False


async def test_output_schemas_are_object_rooted():
    tools = await tools_by_name(make_server())

    for tool in tools.values():
        schema = tool.output_schema
        assert schema is not None
        assert schema["type"] == "object"


async def test_no_tool_accepts_a_path_url_or_header_argument():
    tools = await tools_by_name(make_server())

    for tool in tools.values():
        names = property_names(tool.input_schema)
        assert not names & {"path", "url", "headers", "method", "body"}


# -- List contract ---------------------------------------------------------------------


@pytest.mark.parametrize(("tool", "path", "item"), LIST_CASES, ids=[case[0] for case in LIST_CASES])
async def test_list_operations_build_the_documented_request(
    router: Any, tool: str, path: str, item: dict[str, Any]
):
    body = {"items": [item], "pages": PAGES}
    route = router.get(f"{BASE}{path}").mock(return_value=httpx.Response(200, json=body))

    async with open_client() as client:
        result = await client.call_tool(
            tool,
            {
                "request": {
                    "page": 2,
                    "page_size": 10,
                    "page_total": True,
                    "name_contains": "web",
                }
            },
        )

    assert result.is_error is False
    request = route.calls.last.request
    assert request.method == "GET"
    assert request.url.path == f"/api/firewall-config/v1{path}"
    assert dict(request.url.params) == {
        "page": "2",
        "pageSize": "10",
        "pageTotal": "true",
        "nameContains": "web",
    }
    assert_authenticated(request)
    assert "content-type" not in request.headers
    assert result.structured_content["pages"] == PAGES
    assert result.structured_content["items"][0]["name"] == item["name"]


async def test_list_supports_name_not_equals_and_defaults(router: Any):
    route = router.get(f"{BASE}/network/addresses/ipv4").mock(
        return_value=httpx.Response(200, json={"items": [], "pages": PAGES})
    )

    async with open_client() as client:
        result = await client.call_tool(
            "address_list_ipv4", {"request": {"name_not_equals": "web"}}
        )

    assert result.is_error is False
    assert dict(route.calls.last.request.url.params) == {
        "page": "1",
        "pageSize": "50",
        "pageTotal": "false",
        "nameNotEquals": "web",
    }


# -- Get contract ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("tool", "path", "item", "key_path", "expected"),
    GET_CASES,
    ids=[case[0] for case in GET_CASES],
)
async def test_get_operations_build_the_documented_request(
    router: Any,
    tool: str,
    path: str,
    item: dict[str, Any],
    key_path: tuple[Any, ...],
    expected: Any,
):
    route = router.get(f"{BASE}{path}/web").mock(return_value=httpx.Response(200, json=item))

    async with open_client() as client:
        result = await client.call_tool(tool, {"request": {"id_or_name": "web"}})

    assert result.is_error is False
    request = route.calls.last.request
    assert request.method == "GET"
    assert request.url.path == f"/api/firewall-config/v1{path}/web"
    assert_authenticated(request)
    assert dig(result.structured_content, key_path) == expected


async def test_get_percent_encodes_the_identifier(router: Any):
    route = router.get(f"{BASE}/network/addresses/ipv4/web%20server").mock(
        return_value=httpx.Response(200, json={**IPV4_ITEM, "name": "web server"})
    )

    async with open_client() as client:
        result = await client.call_tool(
            "address_get_ipv4", {"request": {"id_or_name": "web server"}}
        )

    assert result.is_error is False
    assert (
        route.calls.last.request.url.raw_path
        == b"/api/firewall-config/v1/network/addresses/ipv4/web%20server"
    )


# -- Create contract -------------------------------------------------------------------


@pytest.mark.parametrize(
    ("tool", "path", "request_body", "response_body", "key_path", "expected"),
    CREATE_CASES,
    ids=[f"{case[0]}-{index}" for index, case in enumerate(CREATE_CASES)],
)
async def test_create_operations_build_the_documented_request(
    router: Any,
    tool: str,
    path: str,
    request_body: dict[str, Any],
    response_body: dict[str, Any],
    key_path: tuple[Any, ...],
    expected: Any,
):
    route = router.post(f"{BASE}{path}").mock(return_value=httpx.Response(201, json=response_body))

    async with open_client() as client:
        result = await client.call_tool(tool, {"request": request_body})

    assert result.is_error is False
    request = route.calls.last.request
    assert request.method == "POST"
    assert request.url.path == f"/api/firewall-config/v1{path}"
    assert_authenticated(request)
    assert request.headers["content-type"] == "application/json"
    assert json.loads(request.content) == request_body
    assert dig(result.structured_content, key_path) == expected


# -- Update contract -------------------------------------------------------------------


@pytest.mark.parametrize(
    ("tool", "path", "request_body", "expected_body", "response_body", "key_path", "expected"),
    UPDATE_CASES,
    ids=[case[0] for case in UPDATE_CASES],
)
async def test_update_operations_build_the_documented_request(
    router: Any,
    tool: str,
    path: str,
    request_body: dict[str, Any],
    expected_body: dict[str, Any],
    response_body: dict[str, Any],
    key_path: tuple[Any, ...],
    expected: Any,
):
    route = router.patch(f"{BASE}{path}/web").mock(
        return_value=httpx.Response(200, json=response_body)
    )

    async with open_client() as client:
        result = await client.call_tool(tool, {"request": request_body})

    assert result.is_error is False
    request = route.calls.last.request
    assert request.method == "PATCH"
    assert request.url.path == f"/api/firewall-config/v1{path}/web"
    assert_authenticated(request)
    assert request.headers["content-type"] == "application/json"
    assert json.loads(request.content) == expected_body
    assert dig(result.structured_content, key_path) == expected


# -- Delete contract -------------------------------------------------------------------


@pytest.mark.parametrize(("tool", "path"), DELETE_CASES, ids=[case[0] for case in DELETE_CASES])
async def test_delete_operations_build_the_documented_request(router: Any, tool: str, path: str):
    route = router.delete(f"{BASE}{path}/web").mock(
        return_value=httpx.Response(200, json={"deleted": True})
    )

    async with open_client() as client:
        result = await client.call_tool(tool, {"request": {"id_or_name": "web"}})

    assert result.is_error is False
    request = route.calls.last.request
    assert request.method == "DELETE"
    assert request.url.path == f"/api/firewall-config/v1{path}/web"
    assert_authenticated(request)
    assert "content-type" not in request.headers
    assert request.content == b""
    assert result.structured_content == {"deleted": True}


# -- Error mapping ---------------------------------------------------------------------


async def test_get_not_found_maps_to_a_clear_tool_error(router: Any):
    router.get(f"{BASE}/network/addresses/ipv4/missing").mock(
        return_value=httpx.Response(404, json={"error": "notFound"})
    )

    async with open_client() as client:
        result = await client.call_tool("address_get_ipv4", {"request": {"id_or_name": "missing"}})

    assert result.is_error is True
    assert "does not exist" in result.content[0].text


async def test_delete_in_use_conflict_maps_to_a_clear_tool_error(router: Any):
    router.delete(f"{BASE}/network/addresses/ipv4/in-use").mock(
        return_value=httpx.Response(409, json={"error": "resourceConflict"})
    )

    async with open_client() as client:
        result = await client.call_tool(
            "address_delete_ipv4", {"request": {"id_or_name": "in-use"}}
        )

    assert result.is_error is True
    assert "conflicts with the current firewall state" in result.content[0].text


async def test_create_duplicate_name_conflict_maps_to_a_clear_tool_error(router: Any):
    router.post(f"{BASE}/network/addresses/fqdn").mock(
        return_value=httpx.Response(409, json={"error": "resourceConflict"})
    )

    async with open_client() as client:
        result = await client.call_tool(
            "address_create_fqdn",
            {"request": {"name": "example", "fqdn": "example.com"}},
        )

    assert result.is_error is True
    assert "conflicts with the current firewall state" in result.content[0].text


async def test_validation_error_never_echoes_the_raw_body(router: Any):
    router.post(f"{BASE}/network/addresses/fqdn").mock(
        return_value=httpx.Response(
            400, json={"error": "badRequest", "message": "raw appliance detail"}
        )
    )

    async with open_client() as client:
        result = await client.call_tool(
            "address_create_fqdn",
            {"request": {"name": "example", "fqdn": "example.com"}},
        )

    assert result.is_error is True
    assert "rejected the request as invalid" in result.content[0].text
    assert "raw appliance detail" not in result.content[0].text


async def test_a_malformed_address_payload_is_a_sanitized_tool_error(router: Any):
    """A 200 body that does not match the output model becomes a sanitized ToolError."""
    router.get(f"{BASE}/network/addresses/ipv4/web").mock(
        return_value=httpx.Response(200, json={**IPV4_ITEM, "ipv4Address": "not-an-ip"})
    )

    async with open_client() as client:
        result = await client.call_tool("address_get_ipv4", {"request": {"id_or_name": "web"}})

    assert result.is_error is True
    text = result.content[0].text
    assert "does not match the documented schema" in text
    assert "not-an-ip" not in text
    assert KEY not in text


# -- Model tests: families stay distinct -----------------------------------------------


def test_ipv4_create_variants_are_distinct():
    adapter = TypeAdapter(Ipv4AddressCreate)

    single = adapter.validate_python(
        {"name": "web", "type": "ipv4Address", "ipv4Address": "203.0.113.10"}
    )
    network = adapter.validate_python(
        {
            "name": "net",
            "type": "ipv4Network",
            "ipv4NetworkAddress": "192.0.2.0",
            "cidr": 24,
        }
    )
    address_range = adapter.validate_python(
        {
            "name": "range",
            "type": "ipv4Range",
            "ipv4AddressStart": "192.0.2.1",
            "ipv4AddressEnd": "192.0.2.10",
        }
    )
    listed = adapter.validate_python(
        {"name": "list", "type": "ipv4List", "ipv4Addresses": ["192.0.2.1"]}
    )

    assert isinstance(single, Ipv4AddressCreateIp)
    assert isinstance(network, Ipv4AddressCreateNetwork)
    assert isinstance(address_range, Ipv4AddressCreateIpRange)
    assert isinstance(listed, Ipv4AddressCreateIpList)


def test_ipv6_create_variants_are_distinct():
    adapter = TypeAdapter(Ipv6AddressCreate)

    single = adapter.validate_python(
        {"name": "web", "type": "ipv6Address", "ipv6Address": "2001:db8::1"}
    )
    network = adapter.validate_python(
        {
            "name": "net",
            "type": "ipv6Network",
            "ipv6NetworkAddress": "2001:db8::",
            "prefixLength": 64,
        }
    )
    address_range = adapter.validate_python(
        {
            "name": "range",
            "type": "ipv6Range",
            "ipv6AddressStart": "2001:db8::1",
            "ipv6AddressEnd": "2001:db8::10",
        }
    )
    listed = adapter.validate_python(
        {"name": "list", "type": "ipv6List", "ipv6Addresses": ["2001:db8::1"]}
    )

    assert isinstance(single, Ipv6AddressCreateIp)
    assert isinstance(network, Ipv6AddressCreateNetwork)
    assert isinstance(address_range, Ipv6AddressCreateIpRange)
    assert isinstance(listed, Ipv6AddressCreateIpList)


def test_ipv4_create_rejects_an_ipv6_member():
    with pytest.raises(ValidationError):
        TypeAdapter(Ipv4AddressCreate).validate_python(
            {
                "name": "web",
                "type": "ipv4Address",
                "ipv4Address": "203.0.113.10",
                "ipv6Address": "2001:db8::1",
            }
        )


def test_ipv6_create_rejects_an_ipv4_member():
    with pytest.raises(ValidationError):
        TypeAdapter(Ipv6AddressCreate).validate_python(
            {
                "name": "web",
                "type": "ipv6Address",
                "ipv6Address": "2001:db8::1",
                "ipv4Address": "203.0.113.10",
            }
        )


def wire_fields(model: type[Any]) -> set[str]:
    """The property names a model publishes on the wire (aliases, not Python names)."""
    return set(model.model_json_schema(by_alias=True)["properties"])


def test_family_models_do_not_share_fields():
    assert "ipv4Address" in wire_fields(Ipv4AddressIp)
    assert "ipv6Address" not in wire_fields(Ipv4AddressIp)
    assert "ipv6Address" in wire_fields(Ipv6AddressIp)
    assert "ipv4Address" not in wire_fields(Ipv6AddressIp)
    assert "fqdn" in wire_fields(FqdnAddress)
    assert "ipv4Address" not in wire_fields(FqdnAddress)
    assert "macAddress" in wire_fields(MacAddressMacAddress)
    assert "ipv4Address" not in wire_fields(MacAddressMacAddress)
    assert "countries" in wire_fields(CountryGroup)


def test_ipv4_result_rejects_an_ipv6_payload():
    with pytest.raises(ValidationError):
        Ipv4AddressResult.model_validate(
            {
                "address": {
                    "name": "v6",
                    "type": "ipv6Address",
                    "ipv6Address": "2001:db8::1",
                }
            }
        )


# -- Model tests: address validation ---------------------------------------------------


@pytest.mark.parametrize("cidr", [0, 32])
def test_ipv4_network_rejects_an_out_of_range_cidr(cidr: int):
    with pytest.raises(ValidationError):
        TypeAdapter(Ipv4AddressCreate).validate_python(
            {
                "name": "net",
                "type": "ipv4Network",
                "ipv4NetworkAddress": "192.0.2.0",
                "cidr": cidr,
            }
        )


def test_ipv4_network_accepts_cidr_24():
    created = TypeAdapter(Ipv4AddressCreate).validate_python(
        {
            "name": "net",
            "type": "ipv4Network",
            "ipv4NetworkAddress": "192.0.2.0",
            "cidr": 24,
        }
    )

    assert created.cidr == 24


@pytest.mark.parametrize("prefix_length", [0, 128])
def test_ipv6_network_rejects_an_out_of_range_prefix(prefix_length: int):
    with pytest.raises(ValidationError):
        TypeAdapter(Ipv6AddressCreate).validate_python(
            {
                "name": "net",
                "type": "ipv6Network",
                "ipv6NetworkAddress": "2001:db8::",
                "prefixLength": prefix_length,
            }
        )


def test_ipv6_network_accepts_prefix_64():
    created = TypeAdapter(Ipv6AddressCreate).validate_python(
        {
            "name": "net",
            "type": "ipv6Network",
            "ipv6NetworkAddress": "2001:db8::",
            "prefixLength": 64,
        }
    )

    assert created.prefix_length == 64


def test_address_create_rejects_an_invalid_ip():
    with pytest.raises(ValidationError):
        TypeAdapter(Ipv4AddressCreate).validate_python(
            {"name": "web", "type": "ipv4Address", "ipv4Address": "not-an-ip"}
        )


def test_fqdn_create_requires_an_fqdn():
    with pytest.raises(ValidationError):
        FqdnAddressCreate(name="example")


# -- Model tests: groups ---------------------------------------------------------------


def test_group_membership_is_a_name_reference():
    member = MemberRef(name="web")

    assert member.name == "web"
    with pytest.raises(ValidationError):
        MemberRef(name="web", id=UUID)
    with pytest.raises(ValidationError):
        MemberRef(name="bad,name")


def test_ipv4_group_rejects_ipv6_membership():
    with pytest.raises(ValidationError):
        Ipv4AddressGroupCreate(
            name="grp",
            ipv4Addresses=[{"name": "web"}],
            ipv6Addresses=[{"name": "v6-web"}],
        )


def test_group_create_rejects_a_member_with_extra_fields():
    with pytest.raises(ValidationError):
        Ipv4AddressGroupCreate(
            name="grp",
            ipv4Addresses=[{"name": "web", "ipv4Address": "203.0.113.10"}],
        )


def test_group_output_keeps_member_references():
    group = Ipv4AddressGroup.model_validate(IPV4_GROUP_ITEM)

    assert [member.name for member in group.ipv4_addresses] == ["web"]


# -- Model tests: MAC objects ----------------------------------------------------------


def test_mac_create_single_and_list_are_distinct():
    adapter = TypeAdapter(MacAddressCreate)

    single = adapter.validate_python({"name": "printer", "macAddress": "00:11:22:33:44:55"})
    listed = adapter.validate_python({"name": "printers", "macAddresses": ["00:11:22:33:44:55"]})

    assert isinstance(single, MacAddressCreateSingle)
    assert isinstance(listed, MacAddressCreateList)


@pytest.mark.parametrize(
    "payload",
    [
        {"name": "printer"},
        {
            "name": "printer",
            "macAddress": "00:11:22:33:44:55",
            "macAddresses": ["00:11:22:33:44:55"],
        },
    ],
)
def test_mac_create_requires_exactly_one_shape(payload: dict[str, Any]):
    with pytest.raises(ValidationError):
        TypeAdapter(MacAddressCreate).validate_python(payload)


@pytest.mark.parametrize(
    "value",
    ["00:11:22:33:44", "00:11:22:33:44:55:66", "zz:11:22:33:44:55", "00:11:22:33:44:5"],
)
def test_mac_create_rejects_an_invalid_address(value: str):
    with pytest.raises(ValidationError):
        TypeAdapter(MacAddressCreate).validate_python({"name": "printer", "macAddress": value})


def test_mac_update_rejects_both_shapes():
    with pytest.raises(ValidationError):
        MacAddressUpdateInput(
            id_or_name="printer",
            macAddress="00:11:22:33:44:55",
            macAddresses=["00:11:22:33:44:55"],
        )


# -- Model tests: identifiers, pagination and PATCH semantics --------------------------


def test_object_id_or_name_accepts_a_uuid_and_a_name():
    assert ObjectIdentifierInput(id_or_name=UUID).id_or_name == UUID
    assert ObjectIdentifierInput(id_or_name="web server").id_or_name == "web server"


@pytest.mark.parametrize("value", ["", "bad,name", "bad;name", " leading", "trailing "])
def test_object_id_or_name_rejects_an_invalid_value(value: str):
    with pytest.raises(ValidationError):
        ObjectIdentifierInput(id_or_name=value)


def test_list_query_rejects_both_name_filters():
    with pytest.raises(ValidationError):
        Ipv4AddressListInput(name_contains="web", name_not_equals="mail")


@pytest.mark.parametrize("page", [0, -1])
def test_list_query_rejects_a_page_below_one(page: int):
    with pytest.raises(ValidationError):
        Ipv4AddressListInput(page=page)


@pytest.mark.parametrize("page_size", [0, 101])
def test_list_query_rejects_a_page_size_out_of_range(page_size: int):
    with pytest.raises(ValidationError):
        Ipv4AddressListInput(page_size=page_size)


def test_update_body_omits_unset_fields_and_keeps_an_explicit_null():
    omitted = Ipv4AddressUpdateInput(id_or_name="web", name="renamed")
    cleared = Ipv4AddressUpdateInput(id_or_name="web", description=None)

    omitted_body = omitted.model_dump(
        mode="json", by_alias=True, exclude_unset=True, exclude={"id_or_name"}
    )
    cleared_body = cleared.model_dump(
        mode="json", by_alias=True, exclude_unset=True, exclude={"id_or_name"}
    )

    assert omitted_body == {"name": "renamed"}
    assert cleared_body == {"description": None}


def test_delete_result_tolerates_a_missing_body():
    assert DeleteResult().deleted is None
    assert DeleteResult.model_validate({"deleted": True}).deleted is True


# -- Model tests: country groups stay read-only ----------------------------------------


def test_country_group_has_no_mutation_models():
    assert not hasattr(object_models, "CountryGroupCreate")
    assert not hasattr(object_models, "CountryGroupUpdateInput")
    assert not hasattr(object_models, "CountryGroupDeleteInput")


def test_country_group_output_keeps_country_references():
    group = CountryGroup.model_validate(COUNTRY_ITEM)

    assert [country.name for country in group.countries] == ["Germany", "France"]
