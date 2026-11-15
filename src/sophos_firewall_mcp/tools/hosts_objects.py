"""MCP tools for Sophos network addresses, address groups, MAC objects and country groups.

Thirty-seven operations from the audited v1 scope (#29), one tool each:

* IPv4, IPv6 and FQDN addresses: list/get/create/update/delete (15 tools);
* IPv4, IPv6 and FQDN address groups: list/get/create/update/delete (15 tools);
* MAC address objects: list/get/create/update/delete (5 tools);
* country groups: list/get only (2 tools). Country groups are built-in and read-only in
  v1; no mutation tool exists for them.

Bulk delete is excluded from v1 and is not registered. Every family keeps its own models:
an IPv4 object is not an IPv6 object, an FQDN object is not a MAC object, and a group only
references members of its own family. Deletion never cascades: an in-use object returns a
conflict from the appliance and nothing is deleted.

:func:`register_objects_tools` is the single entry point the server factory wires into
``DEFAULT_DOMAINS``; it registers these 37 tools and delegates the ten service tools to
:func:`~sophos_firewall_mcp.tools.services_objects.register_service_objects_tools`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, TypeVar
from urllib.parse import quote

from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import BaseModel, ValidationError

from sophos_firewall_mcp.context import AppContext
from sophos_firewall_mcp.errors import SophosAPIError
from sophos_firewall_mcp.models.common import ListPage
from sophos_firewall_mcp.models.objects import (
    CountryGroup,
    CountryGroupListInput,
    DeleteResult,
    FqdnAddress,
    FqdnAddressCreate,
    FqdnAddressGroup,
    FqdnAddressGroupCreate,
    FqdnAddressGroupListInput,
    FqdnAddressGroupUpdateInput,
    FqdnAddressListInput,
    FqdnAddressUpdateInput,
    Ipv4Address,
    Ipv4AddressCreate,
    Ipv4AddressGroup,
    Ipv4AddressGroupCreate,
    Ipv4AddressGroupListInput,
    Ipv4AddressGroupUpdateInput,
    Ipv4AddressListInput,
    Ipv4AddressResult,
    Ipv4AddressUpdateInput,
    Ipv6Address,
    Ipv6AddressCreate,
    Ipv6AddressGroup,
    Ipv6AddressGroupCreate,
    Ipv6AddressGroupListInput,
    Ipv6AddressGroupUpdateInput,
    Ipv6AddressListInput,
    Ipv6AddressResult,
    Ipv6AddressUpdateInput,
    ListQuery,
    MacAddress,
    MacAddressCreate,
    MacAddressListInput,
    MacAddressResult,
    MacAddressUpdateInput,
    ObjectIdentifierInput,
)
from sophos_firewall_mcp.tools import DomainAdapter, ToolKind, register_tool, tool_error
from sophos_firewall_mcp.tools.services_objects import register_service_objects_tools

__all__ = [
    "COUNTRY_GROUPS_PATH",
    "FQDN_ADDRESSES_PATH",
    "FQDN_GROUPS_PATH",
    "IPV4_ADDRESSES_PATH",
    "IPV4_GROUPS_PATH",
    "IPV6_ADDRESSES_PATH",
    "IPV6_GROUPS_PATH",
    "MAC_ADDRESSES_PATH",
    "ObjectsAdapter",
    "register_objects_tools",
]

#: ``getAllIpAddresses`` / ``createIpAddress`` collection path.
IPV4_ADDRESSES_PATH = "/network/addresses/ipv4"

#: ``getAllIpv6Addresses`` / ``createIpv6Address`` collection path.
IPV6_ADDRESSES_PATH = "/network/addresses/ipv6"

#: ``getAllFqdns`` / ``createFqdn`` collection path.
FQDN_ADDRESSES_PATH = "/network/addresses/fqdn"

#: ``getAllMacAddresses`` / ``createMacAddress`` collection path.
MAC_ADDRESSES_PATH = "/network/addresses/mac"

#: ``getAllIpv4AddressGroups`` / ``createIpv4AddressGroup`` collection path.
IPV4_GROUPS_PATH = "/network/address-groups/ipv4"

#: ``getAllIpv6AddressGroups`` / ``createIpv6AddressGroup`` collection path.
IPV6_GROUPS_PATH = "/network/address-groups/ipv6"

#: ``getAllFqdnGroups`` / ``createFqdnGroup`` collection path.
FQDN_GROUPS_PATH = "/network/address-groups/fqdn"

#: ``getAllCountryGroups`` collection path (read-only in v1).
COUNTRY_GROUPS_PATH = "/network/address-groups/country"

OutputT = TypeVar("OutputT", bound=BaseModel)


def _object_path(collection: str, id_or_name: str) -> str:
    """Build the ``{idOrName}`` path, percent-encoding the identifier segment.

    Names may contain spaces and dots; encoding is required for a valid request and keeps
    a name from being interpreted as a path separator or query delimiter.
    """
    return f"{collection}/{quote(id_or_name, safe='')}"


def _schema_error(exc: ValidationError, path: str) -> ToolError:
    """Build the sanitized error for a response that does not match its output model.

    Only the field location is echoed: the rejected input may contain appliance data, and
    the raw payload must never reach the model.
    """
    first = exc.errors()[0]
    location = ".".join(str(part) for part in first.get("loc", ())) or "body"
    return ToolError(
        f"the appliance returned a response for {path} that does not match the documented "
        f"schema ({location})"
    )


def _project(payload: Any, model: type[OutputT], path: str) -> OutputT:
    """Validate one appliance payload into its bounded model, with a sanitized error."""
    try:
        return model.model_validate(payload)
    except ValidationError as exc:
        raise _schema_error(exc, path) from exc


class ObjectsAdapter(DomainAdapter):
    """Project the address, group, MAC and country operations onto typed MCP DTOs."""

    async def _list(self, path: str, request: ListQuery, output: type[OutputT]) -> OutputT:
        try:
            payload = await self.client.get_page(
                path,
                page=request.page,
                page_size=request.page_size,
                page_total=request.page_total,
                params=request.filters(),
            )
        except SophosAPIError as exc:
            raise tool_error(exc) from exc
        return _project(payload, output, path)

    async def _get(self, path: str, id_or_name: str) -> Any:
        try:
            return await self.client.get(_object_path(path, id_or_name))
        except SophosAPIError as exc:
            raise tool_error(exc) from exc

    async def _create(self, path: str, body: dict[str, Any]) -> Any:
        try:
            return await self.client.post(path, json=body)
        except SophosAPIError as exc:
            raise tool_error(exc) from exc

    async def _update(self, path: str, id_or_name: str, body: dict[str, Any]) -> Any:
        try:
            return await self.client.patch(_object_path(path, id_or_name), json=body)
        except SophosAPIError as exc:
            raise tool_error(exc) from exc

    async def _delete(self, path: str, id_or_name: str) -> DeleteResult:
        try:
            await self.client.delete(_object_path(path, id_or_name))
        except SophosAPIError as exc:
            raise tool_error(exc) from exc
        # The shared client discards the DELETE response body; a successful call means the
        # appliance accepted the deletion, so the projection reports it as applied.
        return DeleteResult(deleted=True)

    # -- IPv4 addresses -----------------------------------------------------------

    async def list_ipv4_addresses(self, request: Ipv4AddressListInput) -> ListPage[Ipv4Address]:
        return await self._list(IPV4_ADDRESSES_PATH, request, ListPage[Ipv4Address])

    async def get_ipv4_address(self, request: ObjectIdentifierInput) -> Ipv4AddressResult:
        payload = await self._get(IPV4_ADDRESSES_PATH, request.id_or_name)
        return _project({"address": payload}, Ipv4AddressResult, IPV4_ADDRESSES_PATH)

    async def create_ipv4_address(self, request: Ipv4AddressCreate) -> Ipv4AddressResult:
        body = request.model_dump(mode="json", by_alias=True, exclude_unset=True)
        payload = await self._create(IPV4_ADDRESSES_PATH, body)
        return _project({"address": payload}, Ipv4AddressResult, IPV4_ADDRESSES_PATH)

    async def update_ipv4_address(self, request: Ipv4AddressUpdateInput) -> Ipv4AddressResult:
        body = request.model_dump(
            mode="json", by_alias=True, exclude_unset=True, exclude={"id_or_name"}
        )
        payload = await self._update(IPV4_ADDRESSES_PATH, request.id_or_name, body)
        return _project({"address": payload}, Ipv4AddressResult, IPV4_ADDRESSES_PATH)

    async def delete_ipv4_address(self, request: ObjectIdentifierInput) -> DeleteResult:
        return await self._delete(IPV4_ADDRESSES_PATH, request.id_or_name)

    # -- IPv6 addresses -----------------------------------------------------------

    async def list_ipv6_addresses(self, request: Ipv6AddressListInput) -> ListPage[Ipv6Address]:
        return await self._list(IPV6_ADDRESSES_PATH, request, ListPage[Ipv6Address])

    async def get_ipv6_address(self, request: ObjectIdentifierInput) -> Ipv6AddressResult:
        payload = await self._get(IPV6_ADDRESSES_PATH, request.id_or_name)
        return _project({"address": payload}, Ipv6AddressResult, IPV6_ADDRESSES_PATH)

    async def create_ipv6_address(self, request: Ipv6AddressCreate) -> Ipv6AddressResult:
        body = request.model_dump(mode="json", by_alias=True, exclude_unset=True)
        payload = await self._create(IPV6_ADDRESSES_PATH, body)
        return _project({"address": payload}, Ipv6AddressResult, IPV6_ADDRESSES_PATH)

    async def update_ipv6_address(self, request: Ipv6AddressUpdateInput) -> Ipv6AddressResult:
        body = request.model_dump(
            mode="json", by_alias=True, exclude_unset=True, exclude={"id_or_name"}
        )
        payload = await self._update(IPV6_ADDRESSES_PATH, request.id_or_name, body)
        return _project({"address": payload}, Ipv6AddressResult, IPV6_ADDRESSES_PATH)

    async def delete_ipv6_address(self, request: ObjectIdentifierInput) -> DeleteResult:
        return await self._delete(IPV6_ADDRESSES_PATH, request.id_or_name)

    # -- FQDN addresses -----------------------------------------------------------

    async def list_fqdn_addresses(self, request: FqdnAddressListInput) -> ListPage[FqdnAddress]:
        return await self._list(FQDN_ADDRESSES_PATH, request, ListPage[FqdnAddress])

    async def get_fqdn_address(self, request: ObjectIdentifierInput) -> FqdnAddress:
        payload = await self._get(FQDN_ADDRESSES_PATH, request.id_or_name)
        return _project(payload, FqdnAddress, FQDN_ADDRESSES_PATH)

    async def create_fqdn_address(self, request: FqdnAddressCreate) -> FqdnAddress:
        body = request.model_dump(mode="json", by_alias=True, exclude_unset=True)
        payload = await self._create(FQDN_ADDRESSES_PATH, body)
        return _project(payload, FqdnAddress, FQDN_ADDRESSES_PATH)

    async def update_fqdn_address(self, request: FqdnAddressUpdateInput) -> FqdnAddress:
        body = request.model_dump(
            mode="json", by_alias=True, exclude_unset=True, exclude={"id_or_name"}
        )
        payload = await self._update(FQDN_ADDRESSES_PATH, request.id_or_name, body)
        return _project(payload, FqdnAddress, FQDN_ADDRESSES_PATH)

    async def delete_fqdn_address(self, request: ObjectIdentifierInput) -> DeleteResult:
        return await self._delete(FQDN_ADDRESSES_PATH, request.id_or_name)

    # -- IPv4 address groups ------------------------------------------------------

    async def list_ipv4_address_groups(
        self, request: Ipv4AddressGroupListInput
    ) -> ListPage[Ipv4AddressGroup]:
        return await self._list(IPV4_GROUPS_PATH, request, ListPage[Ipv4AddressGroup])

    async def get_ipv4_address_group(self, request: ObjectIdentifierInput) -> Ipv4AddressGroup:
        payload = await self._get(IPV4_GROUPS_PATH, request.id_or_name)
        return _project(payload, Ipv4AddressGroup, IPV4_GROUPS_PATH)

    async def create_ipv4_address_group(self, request: Ipv4AddressGroupCreate) -> Ipv4AddressGroup:
        body = request.model_dump(mode="json", by_alias=True, exclude_unset=True)
        payload = await self._create(IPV4_GROUPS_PATH, body)
        return _project(payload, Ipv4AddressGroup, IPV4_GROUPS_PATH)

    async def update_ipv4_address_group(
        self, request: Ipv4AddressGroupUpdateInput
    ) -> Ipv4AddressGroup:
        body = request.model_dump(
            mode="json", by_alias=True, exclude_unset=True, exclude={"id_or_name"}
        )
        payload = await self._update(IPV4_GROUPS_PATH, request.id_or_name, body)
        return _project(payload, Ipv4AddressGroup, IPV4_GROUPS_PATH)

    async def delete_ipv4_address_group(self, request: ObjectIdentifierInput) -> DeleteResult:
        return await self._delete(IPV4_GROUPS_PATH, request.id_or_name)

    # -- IPv6 address groups ------------------------------------------------------

    async def list_ipv6_address_groups(
        self, request: Ipv6AddressGroupListInput
    ) -> ListPage[Ipv6AddressGroup]:
        return await self._list(IPV6_GROUPS_PATH, request, ListPage[Ipv6AddressGroup])

    async def get_ipv6_address_group(self, request: ObjectIdentifierInput) -> Ipv6AddressGroup:
        payload = await self._get(IPV6_GROUPS_PATH, request.id_or_name)
        return _project(payload, Ipv6AddressGroup, IPV6_GROUPS_PATH)

    async def create_ipv6_address_group(self, request: Ipv6AddressGroupCreate) -> Ipv6AddressGroup:
        body = request.model_dump(mode="json", by_alias=True, exclude_unset=True)
        payload = await self._create(IPV6_GROUPS_PATH, body)
        return _project(payload, Ipv6AddressGroup, IPV6_GROUPS_PATH)

    async def update_ipv6_address_group(
        self, request: Ipv6AddressGroupUpdateInput
    ) -> Ipv6AddressGroup:
        body = request.model_dump(
            mode="json", by_alias=True, exclude_unset=True, exclude={"id_or_name"}
        )
        payload = await self._update(IPV6_GROUPS_PATH, request.id_or_name, body)
        return _project(payload, Ipv6AddressGroup, IPV6_GROUPS_PATH)

    async def delete_ipv6_address_group(self, request: ObjectIdentifierInput) -> DeleteResult:
        return await self._delete(IPV6_GROUPS_PATH, request.id_or_name)

    # -- FQDN address groups ------------------------------------------------------

    async def list_fqdn_address_groups(
        self, request: FqdnAddressGroupListInput
    ) -> ListPage[FqdnAddressGroup]:
        return await self._list(FQDN_GROUPS_PATH, request, ListPage[FqdnAddressGroup])

    async def get_fqdn_address_group(self, request: ObjectIdentifierInput) -> FqdnAddressGroup:
        payload = await self._get(FQDN_GROUPS_PATH, request.id_or_name)
        return _project(payload, FqdnAddressGroup, FQDN_GROUPS_PATH)

    async def create_fqdn_address_group(self, request: FqdnAddressGroupCreate) -> FqdnAddressGroup:
        body = request.model_dump(mode="json", by_alias=True, exclude_unset=True)
        payload = await self._create(FQDN_GROUPS_PATH, body)
        return _project(payload, FqdnAddressGroup, FQDN_GROUPS_PATH)

    async def update_fqdn_address_group(
        self, request: FqdnAddressGroupUpdateInput
    ) -> FqdnAddressGroup:
        body = request.model_dump(
            mode="json", by_alias=True, exclude_unset=True, exclude={"id_or_name"}
        )
        payload = await self._update(FQDN_GROUPS_PATH, request.id_or_name, body)
        return _project(payload, FqdnAddressGroup, FQDN_GROUPS_PATH)

    async def delete_fqdn_address_group(self, request: ObjectIdentifierInput) -> DeleteResult:
        return await self._delete(FQDN_GROUPS_PATH, request.id_or_name)

    # -- MAC address objects ------------------------------------------------------

    async def list_mac_addresses(self, request: MacAddressListInput) -> ListPage[MacAddress]:
        return await self._list(MAC_ADDRESSES_PATH, request, ListPage[MacAddress])

    async def get_mac_address(self, request: ObjectIdentifierInput) -> MacAddressResult:
        payload = await self._get(MAC_ADDRESSES_PATH, request.id_or_name)
        return _project({"address": payload}, MacAddressResult, MAC_ADDRESSES_PATH)

    async def create_mac_address(self, request: MacAddressCreate) -> MacAddressResult:
        body = request.model_dump(mode="json", by_alias=True, exclude_unset=True)
        payload = await self._create(MAC_ADDRESSES_PATH, body)
        return _project({"address": payload}, MacAddressResult, MAC_ADDRESSES_PATH)

    async def update_mac_address(self, request: MacAddressUpdateInput) -> MacAddressResult:
        body = request.model_dump(
            mode="json", by_alias=True, exclude_unset=True, exclude={"id_or_name"}
        )
        payload = await self._update(MAC_ADDRESSES_PATH, request.id_or_name, body)
        return _project({"address": payload}, MacAddressResult, MAC_ADDRESSES_PATH)

    async def delete_mac_address(self, request: ObjectIdentifierInput) -> DeleteResult:
        return await self._delete(MAC_ADDRESSES_PATH, request.id_or_name)

    # -- Country groups (read-only) -----------------------------------------------

    async def list_country_groups(self, request: CountryGroupListInput) -> ListPage[CountryGroup]:
        return await self._list(COUNTRY_GROUPS_PATH, request, ListPage[CountryGroup])

    async def get_country_group(self, request: ObjectIdentifierInput) -> CountryGroup:
        payload = await self._get(COUNTRY_GROUPS_PATH, request.id_or_name)
        return _project(payload, CountryGroup, COUNTRY_GROUPS_PATH)


# -- Handlers --------------------------------------------------------------------------


async def address_list_ipv4(
    request: Ipv4AddressListInput, ctx: Context[AppContext]
) -> ListPage[Ipv4Address]:
    return await ObjectsAdapter.from_context(ctx).list_ipv4_addresses(request)


async def address_get_ipv4(
    request: ObjectIdentifierInput, ctx: Context[AppContext]
) -> Ipv4AddressResult:
    return await ObjectsAdapter.from_context(ctx).get_ipv4_address(request)


async def address_create_ipv4(
    request: Ipv4AddressCreate, ctx: Context[AppContext]
) -> Ipv4AddressResult:
    return await ObjectsAdapter.from_context(ctx).create_ipv4_address(request)


async def address_update_ipv4(
    request: Ipv4AddressUpdateInput, ctx: Context[AppContext]
) -> Ipv4AddressResult:
    return await ObjectsAdapter.from_context(ctx).update_ipv4_address(request)


async def address_delete_ipv4(
    request: ObjectIdentifierInput, ctx: Context[AppContext]
) -> DeleteResult:
    return await ObjectsAdapter.from_context(ctx).delete_ipv4_address(request)


async def address_list_ipv6(
    request: Ipv6AddressListInput, ctx: Context[AppContext]
) -> ListPage[Ipv6Address]:
    return await ObjectsAdapter.from_context(ctx).list_ipv6_addresses(request)


async def address_get_ipv6(
    request: ObjectIdentifierInput, ctx: Context[AppContext]
) -> Ipv6AddressResult:
    return await ObjectsAdapter.from_context(ctx).get_ipv6_address(request)


async def address_create_ipv6(
    request: Ipv6AddressCreate, ctx: Context[AppContext]
) -> Ipv6AddressResult:
    return await ObjectsAdapter.from_context(ctx).create_ipv6_address(request)


async def address_update_ipv6(
    request: Ipv6AddressUpdateInput, ctx: Context[AppContext]
) -> Ipv6AddressResult:
    return await ObjectsAdapter.from_context(ctx).update_ipv6_address(request)


async def address_delete_ipv6(
    request: ObjectIdentifierInput, ctx: Context[AppContext]
) -> DeleteResult:
    return await ObjectsAdapter.from_context(ctx).delete_ipv6_address(request)


async def address_list_fqdn(
    request: FqdnAddressListInput, ctx: Context[AppContext]
) -> ListPage[FqdnAddress]:
    return await ObjectsAdapter.from_context(ctx).list_fqdn_addresses(request)


async def address_get_fqdn(request: ObjectIdentifierInput, ctx: Context[AppContext]) -> FqdnAddress:
    return await ObjectsAdapter.from_context(ctx).get_fqdn_address(request)


async def address_create_fqdn(request: FqdnAddressCreate, ctx: Context[AppContext]) -> FqdnAddress:
    return await ObjectsAdapter.from_context(ctx).create_fqdn_address(request)


async def address_update_fqdn(
    request: FqdnAddressUpdateInput, ctx: Context[AppContext]
) -> FqdnAddress:
    return await ObjectsAdapter.from_context(ctx).update_fqdn_address(request)


async def address_delete_fqdn(
    request: ObjectIdentifierInput, ctx: Context[AppContext]
) -> DeleteResult:
    return await ObjectsAdapter.from_context(ctx).delete_fqdn_address(request)


async def address_group_list_ipv4(
    request: Ipv4AddressGroupListInput, ctx: Context[AppContext]
) -> ListPage[Ipv4AddressGroup]:
    return await ObjectsAdapter.from_context(ctx).list_ipv4_address_groups(request)


async def address_group_get_ipv4(
    request: ObjectIdentifierInput, ctx: Context[AppContext]
) -> Ipv4AddressGroup:
    return await ObjectsAdapter.from_context(ctx).get_ipv4_address_group(request)


async def address_group_create_ipv4(
    request: Ipv4AddressGroupCreate, ctx: Context[AppContext]
) -> Ipv4AddressGroup:
    return await ObjectsAdapter.from_context(ctx).create_ipv4_address_group(request)


async def address_group_update_ipv4(
    request: Ipv4AddressGroupUpdateInput, ctx: Context[AppContext]
) -> Ipv4AddressGroup:
    return await ObjectsAdapter.from_context(ctx).update_ipv4_address_group(request)


async def address_group_delete_ipv4(
    request: ObjectIdentifierInput, ctx: Context[AppContext]
) -> DeleteResult:
    return await ObjectsAdapter.from_context(ctx).delete_ipv4_address_group(request)


async def address_group_list_ipv6(
    request: Ipv6AddressGroupListInput, ctx: Context[AppContext]
) -> ListPage[Ipv6AddressGroup]:
    return await ObjectsAdapter.from_context(ctx).list_ipv6_address_groups(request)


async def address_group_get_ipv6(
    request: ObjectIdentifierInput, ctx: Context[AppContext]
) -> Ipv6AddressGroup:
    return await ObjectsAdapter.from_context(ctx).get_ipv6_address_group(request)


async def address_group_create_ipv6(
    request: Ipv6AddressGroupCreate, ctx: Context[AppContext]
) -> Ipv6AddressGroup:
    return await ObjectsAdapter.from_context(ctx).create_ipv6_address_group(request)


async def address_group_update_ipv6(
    request: Ipv6AddressGroupUpdateInput, ctx: Context[AppContext]
) -> Ipv6AddressGroup:
    return await ObjectsAdapter.from_context(ctx).update_ipv6_address_group(request)


async def address_group_delete_ipv6(
    request: ObjectIdentifierInput, ctx: Context[AppContext]
) -> DeleteResult:
    return await ObjectsAdapter.from_context(ctx).delete_ipv6_address_group(request)


async def address_group_list_fqdn(
    request: FqdnAddressGroupListInput, ctx: Context[AppContext]
) -> ListPage[FqdnAddressGroup]:
    return await ObjectsAdapter.from_context(ctx).list_fqdn_address_groups(request)


async def address_group_get_fqdn(
    request: ObjectIdentifierInput, ctx: Context[AppContext]
) -> FqdnAddressGroup:
    return await ObjectsAdapter.from_context(ctx).get_fqdn_address_group(request)


async def address_group_create_fqdn(
    request: FqdnAddressGroupCreate, ctx: Context[AppContext]
) -> FqdnAddressGroup:
    return await ObjectsAdapter.from_context(ctx).create_fqdn_address_group(request)


async def address_group_update_fqdn(
    request: FqdnAddressGroupUpdateInput, ctx: Context[AppContext]
) -> FqdnAddressGroup:
    return await ObjectsAdapter.from_context(ctx).update_fqdn_address_group(request)


async def address_group_delete_fqdn(
    request: ObjectIdentifierInput, ctx: Context[AppContext]
) -> DeleteResult:
    return await ObjectsAdapter.from_context(ctx).delete_fqdn_address_group(request)


async def mac_address_list(
    request: MacAddressListInput, ctx: Context[AppContext]
) -> ListPage[MacAddress]:
    return await ObjectsAdapter.from_context(ctx).list_mac_addresses(request)


async def mac_address_get(
    request: ObjectIdentifierInput, ctx: Context[AppContext]
) -> MacAddressResult:
    return await ObjectsAdapter.from_context(ctx).get_mac_address(request)


async def mac_address_create(
    request: MacAddressCreate, ctx: Context[AppContext]
) -> MacAddressResult:
    return await ObjectsAdapter.from_context(ctx).create_mac_address(request)


async def mac_address_update(
    request: MacAddressUpdateInput, ctx: Context[AppContext]
) -> MacAddressResult:
    return await ObjectsAdapter.from_context(ctx).update_mac_address(request)


async def mac_address_delete(
    request: ObjectIdentifierInput, ctx: Context[AppContext]
) -> DeleteResult:
    return await ObjectsAdapter.from_context(ctx).delete_mac_address(request)


async def country_group_list(
    request: CountryGroupListInput, ctx: Context[AppContext]
) -> ListPage[CountryGroup]:
    return await ObjectsAdapter.from_context(ctx).list_country_groups(request)


async def country_group_get(
    request: ObjectIdentifierInput, ctx: Context[AppContext]
) -> CountryGroup:
    return await ObjectsAdapter.from_context(ctx).get_country_group(request)


# -- Registration ----------------------------------------------------------------------


@dataclass(frozen=True)
class _ToolSpec:
    """One tool's registration metadata and its module-level handler."""

    name: str
    title: str
    description: str
    kind: ToolKind
    handler: Callable[..., Any]
    annotations: ToolAnnotations | None = None


_CREATE = ToolAnnotations(destructive_hint=False, idempotent_hint=False)
_UPDATE = ToolAnnotations(destructive_hint=False, idempotent_hint=True)
_DELETE = ToolAnnotations(destructive_hint=True, idempotent_hint=True)

_TOOL_SPECS: tuple[_ToolSpec, ...] = (
    _ToolSpec(
        name="address_list_ipv4",
        title="List IPv4 addresses",
        description=(
            "List one page of IPv4 address objects (single address, network, range or IP "
            "list). Read-only. `page` is 1-based, `page_size` is 1-100 and `page_total` "
            "requests total metadata; `name_contains` and `name_not_equals` are mutually "
            "exclusive. Returns the page items and the appliance `pages` metadata; it "
            "never auto-paginates."
        ),
        kind=ToolKind.READ,
        handler=address_list_ipv4,
    ),
    _ToolSpec(
        name="address_get_ipv4",
        title="Get an IPv4 address",
        description=(
            "Read one IPv4 address object by UUID or name (`id_or_name`). Read-only. The "
            "response is discriminated by `type` (ipv4Address, ipv4Network, ipv4Range, "
            "ipv4List); use it before updating or deleting to confirm the shape."
        ),
        kind=ToolKind.READ,
        handler=address_get_ipv4,
    ),
    _ToolSpec(
        name="address_create_ipv4",
        title="Create an IPv4 address",
        description=(
            "Create an IPv4 address object. `type` selects the shape: ipv4Address "
            "(`ipv4Address`), ipv4Network (`ipv4NetworkAddress` + `cidr` 1-31), ipv4Range "
            "(`ipv4AddressStart` + `ipv4AddressEnd`) or ipv4List (`ipv4Addresses`). `name` "
            "is required and must be a valid Sophos object name. A duplicate name returns "
            "a conflict and nothing is created."
        ),
        kind=ToolKind.MUTATION,
        handler=address_create_ipv4,
        annotations=_CREATE,
    ),
    _ToolSpec(
        name="address_update_ipv4",
        title="Update an IPv4 address",
        description=(
            "Partially update an IPv4 address object by UUID or name. PATCH uses JSON "
            "Merge Patch: omitted fields keep their stored value and `description: null` "
            "clears the description. The object `type` cannot be changed and is not "
            "accepted. Mutating."
        ),
        kind=ToolKind.MUTATION,
        handler=address_update_ipv4,
        annotations=_UPDATE,
    ),
    _ToolSpec(
        name="address_delete_ipv4",
        title="Delete an IPv4 address",
        description=(
            "Delete an IPv4 address object by UUID or name. Destructive and not "
            "cascading: if the object is still referenced by a rule, group or NAT entry "
            "the appliance returns a conflict and nothing is deleted."
        ),
        kind=ToolKind.MUTATION,
        handler=address_delete_ipv4,
        annotations=_DELETE,
    ),
    _ToolSpec(
        name="address_list_ipv6",
        title="List IPv6 addresses",
        description=(
            "List one page of IPv6 address objects (single address, network, range or IP "
            "list). Read-only. `page` is 1-based, `page_size` is 1-100 and `page_total` "
            "requests total metadata; `name_contains` and `name_not_equals` are mutually "
            "exclusive. Returns the page items and the appliance `pages` metadata."
        ),
        kind=ToolKind.READ,
        handler=address_list_ipv6,
    ),
    _ToolSpec(
        name="address_get_ipv6",
        title="Get an IPv6 address",
        description=(
            "Read one IPv6 address object by UUID or name (`id_or_name`). Read-only. The "
            "response is discriminated by `type` (ipv6Address, ipv6Network, ipv6Range, "
            "ipv6List); use it before updating or deleting to confirm the shape."
        ),
        kind=ToolKind.READ,
        handler=address_get_ipv6,
    ),
    _ToolSpec(
        name="address_create_ipv6",
        title="Create an IPv6 address",
        description=(
            "Create an IPv6 address object. `type` selects the shape: ipv6Address "
            "(`ipv6Address`), ipv6Network (`ipv6NetworkAddress` + `prefixLength` 1-127), "
            "ipv6Range (`ipv6AddressStart` + `ipv6AddressEnd`) or ipv6List "
            "(`ipv6Addresses`). `name` is required. A duplicate name returns a conflict."
        ),
        kind=ToolKind.MUTATION,
        handler=address_create_ipv6,
        annotations=_CREATE,
    ),
    _ToolSpec(
        name="address_update_ipv6",
        title="Update an IPv6 address",
        description=(
            "Partially update an IPv6 address object by UUID or name. PATCH uses JSON "
            "Merge Patch: omitted fields keep their stored value and `description: null` "
            "clears the description. The object `type` cannot be changed. Mutating."
        ),
        kind=ToolKind.MUTATION,
        handler=address_update_ipv6,
        annotations=_UPDATE,
    ),
    _ToolSpec(
        name="address_delete_ipv6",
        title="Delete an IPv6 address",
        description=(
            "Delete an IPv6 address object by UUID or name. Destructive and not "
            "cascading: if the object is still referenced the appliance returns a "
            "conflict and nothing is deleted."
        ),
        kind=ToolKind.MUTATION,
        handler=address_delete_ipv6,
        annotations=_DELETE,
    ),
    _ToolSpec(
        name="address_list_fqdn",
        title="List FQDN addresses",
        description=(
            "List one page of FQDN address objects. Read-only. `page` is 1-based, "
            "`page_size` is 1-100 and `page_total` requests total metadata; "
            "`name_contains` and `name_not_equals` are mutually exclusive. Returns the "
            "page items and the appliance `pages` metadata."
        ),
        kind=ToolKind.READ,
        handler=address_list_fqdn,
    ),
    _ToolSpec(
        name="address_get_fqdn",
        title="Get an FQDN address",
        description=(
            "Read one FQDN address object by UUID or name (`id_or_name`). Read-only. "
            "Returns the object's `name`, `description` and `fqdn`."
        ),
        kind=ToolKind.READ,
        handler=address_get_fqdn,
    ),
    _ToolSpec(
        name="address_create_fqdn",
        title="Create an FQDN address",
        description=(
            "Create an FQDN address object. `name` and `fqdn` (1-253 characters) are "
            "required. A duplicate name returns a conflict and nothing is created."
        ),
        kind=ToolKind.MUTATION,
        handler=address_create_fqdn,
        annotations=_CREATE,
    ),
    _ToolSpec(
        name="address_update_fqdn",
        title="Update an FQDN address",
        description=(
            "Partially update an FQDN address object by UUID or name. PATCH uses JSON "
            "Merge Patch: omitted fields keep their stored value and `description: null` "
            "clears the description. Mutating."
        ),
        kind=ToolKind.MUTATION,
        handler=address_update_fqdn,
        annotations=_UPDATE,
    ),
    _ToolSpec(
        name="address_delete_fqdn",
        title="Delete an FQDN address",
        description=(
            "Delete an FQDN address object by UUID or name. Destructive and not "
            "cascading: if the object is still referenced the appliance returns a "
            "conflict and nothing is deleted."
        ),
        kind=ToolKind.MUTATION,
        handler=address_delete_fqdn,
        annotations=_DELETE,
    ),
    _ToolSpec(
        name="address_group_list_ipv4",
        title="List IPv4 address groups",
        description=(
            "List one page of IPv4 address groups. Read-only. `page` is 1-based, "
            "`page_size` is 1-100 and `page_total` requests total metadata; "
            "`name_contains` and `name_not_equals` are mutually exclusive. Members are "
            "returned as name references."
        ),
        kind=ToolKind.READ,
        handler=address_group_list_ipv4,
    ),
    _ToolSpec(
        name="address_group_get_ipv4",
        title="Get an IPv4 address group",
        description=(
            "Read one IPv4 address group by UUID or name (`id_or_name`). Read-only. "
            "Members are IPv4 address objects referenced by name; a group never mixes "
            "address families."
        ),
        kind=ToolKind.READ,
        handler=address_group_get_ipv4,
    ),
    _ToolSpec(
        name="address_group_create_ipv4",
        title="Create an IPv4 address group",
        description=(
            "Create an IPv4 address group from existing IPv4 address objects. `name` and "
            '`ipv4Addresses` (a list of `{"name": ...}` references, possibly empty) are '
            "required. Members must already exist and must be IPv4 address objects; the "
            "appliance rejects an unknown or wrong-family name."
        ),
        kind=ToolKind.MUTATION,
        handler=address_group_create_ipv4,
        annotations=_CREATE,
    ),
    _ToolSpec(
        name="address_group_update_ipv4",
        title="Update an IPv4 address group",
        description=(
            "Partially update an IPv4 address group by UUID or name. PATCH uses JSON "
            "Merge Patch: omitted fields keep their stored value and `ipv4Addresses` "
            "replaces the whole member list. Mutating."
        ),
        kind=ToolKind.MUTATION,
        handler=address_group_update_ipv4,
        annotations=_UPDATE,
    ),
    _ToolSpec(
        name="address_group_delete_ipv4",
        title="Delete an IPv4 address group",
        description=(
            "Delete an IPv4 address group by UUID or name. Destructive and not "
            "cascading: if the group is still referenced by a rule or another group the "
            "appliance returns a conflict and nothing is deleted."
        ),
        kind=ToolKind.MUTATION,
        handler=address_group_delete_ipv4,
        annotations=_DELETE,
    ),
    _ToolSpec(
        name="address_group_list_ipv6",
        title="List IPv6 address groups",
        description=(
            "List one page of IPv6 address groups. Read-only. `page` is 1-based, "
            "`page_size` is 1-100 and `page_total` requests total metadata; "
            "`name_contains` and `name_not_equals` are mutually exclusive. Members are "
            "returned as name references."
        ),
        kind=ToolKind.READ,
        handler=address_group_list_ipv6,
    ),
    _ToolSpec(
        name="address_group_get_ipv6",
        title="Get an IPv6 address group",
        description=(
            "Read one IPv6 address group by UUID or name (`id_or_name`). Read-only. "
            "Members are IPv6 address objects referenced by name; a group never mixes "
            "address families."
        ),
        kind=ToolKind.READ,
        handler=address_group_get_ipv6,
    ),
    _ToolSpec(
        name="address_group_create_ipv6",
        title="Create an IPv6 address group",
        description=(
            "Create an IPv6 address group from existing IPv6 address objects. `name` and "
            '`ipv6Addresses` (a list of `{"name": ...}` references, possibly empty) are '
            "required. Members must already exist and must be IPv6 address objects."
        ),
        kind=ToolKind.MUTATION,
        handler=address_group_create_ipv6,
        annotations=_CREATE,
    ),
    _ToolSpec(
        name="address_group_update_ipv6",
        title="Update an IPv6 address group",
        description=(
            "Partially update an IPv6 address group by UUID or name. PATCH uses JSON "
            "Merge Patch: omitted fields keep their stored value and `ipv6Addresses` "
            "replaces the whole member list. Mutating."
        ),
        kind=ToolKind.MUTATION,
        handler=address_group_update_ipv6,
        annotations=_UPDATE,
    ),
    _ToolSpec(
        name="address_group_delete_ipv6",
        title="Delete an IPv6 address group",
        description=(
            "Delete an IPv6 address group by UUID or name. Destructive and not "
            "cascading: if the group is still referenced the appliance returns a "
            "conflict and nothing is deleted."
        ),
        kind=ToolKind.MUTATION,
        handler=address_group_delete_ipv6,
        annotations=_DELETE,
    ),
    _ToolSpec(
        name="address_group_list_fqdn",
        title="List FQDN address groups",
        description=(
            "List one page of FQDN address groups. Read-only. `page` is 1-based, "
            "`page_size` is 1-100 and `page_total` requests total metadata; "
            "`name_contains` and `name_not_equals` are mutually exclusive. Members are "
            "returned as name references."
        ),
        kind=ToolKind.READ,
        handler=address_group_list_fqdn,
    ),
    _ToolSpec(
        name="address_group_get_fqdn",
        title="Get an FQDN address group",
        description=(
            "Read one FQDN address group by UUID or name (`id_or_name`). Read-only. "
            "Members are FQDN address objects referenced by name."
        ),
        kind=ToolKind.READ,
        handler=address_group_get_fqdn,
    ),
    _ToolSpec(
        name="address_group_create_fqdn",
        title="Create an FQDN address group",
        description=(
            "Create an FQDN address group from existing FQDN address objects. `name` is "
            'required; `fqdns` is a list of `{"name": ...}` references and is nullable '
            "in the contract. Members must already exist and must be FQDN address objects."
        ),
        kind=ToolKind.MUTATION,
        handler=address_group_create_fqdn,
        annotations=_CREATE,
    ),
    _ToolSpec(
        name="address_group_update_fqdn",
        title="Update an FQDN address group",
        description=(
            "Partially update an FQDN address group by UUID or name. PATCH uses JSON "
            "Merge Patch: omitted fields keep their stored value and `fqdns` replaces the "
            "whole member list; `fqdns: null` clears it. Mutating."
        ),
        kind=ToolKind.MUTATION,
        handler=address_group_update_fqdn,
        annotations=_UPDATE,
    ),
    _ToolSpec(
        name="address_group_delete_fqdn",
        title="Delete an FQDN address group",
        description=(
            "Delete an FQDN address group by UUID or name. Destructive and not "
            "cascading: if the group is still referenced the appliance returns a "
            "conflict and nothing is deleted."
        ),
        kind=ToolKind.MUTATION,
        handler=address_group_delete_fqdn,
        annotations=_DELETE,
    ),
    _ToolSpec(
        name="mac_address_list",
        title="List MAC address objects",
        description=(
            "List one page of MAC address objects (a single address or a MAC list). "
            "Read-only. `page` is 1-based, `page_size` is 1-100 and `page_total` requests "
            "total metadata; `name_contains` and `name_not_equals` are mutually exclusive. "
            "Returns the page items and the appliance `pages` metadata."
        ),
        kind=ToolKind.READ,
        handler=mac_address_list,
    ),
    _ToolSpec(
        name="mac_address_get",
        title="Get a MAC address object",
        description=(
            "Read one MAC address object by UUID or name (`id_or_name`). Read-only. The "
            "response is discriminated by `type` (macAddress or macList)."
        ),
        kind=ToolKind.READ,
        handler=mac_address_get,
    ),
    _ToolSpec(
        name="mac_address_create",
        title="Create a MAC address object",
        description=(
            "Create a MAC address object. Provide exactly one of `macAddress` (a single "
            "address) or `macAddresses` (1-1000 addresses); the create payload has no "
            "`type` member. `name` is required. A duplicate name returns a conflict and "
            "nothing is created."
        ),
        kind=ToolKind.MUTATION,
        handler=mac_address_create,
        annotations=_CREATE,
    ),
    _ToolSpec(
        name="mac_address_update",
        title="Update a MAC address object",
        description=(
            "Partially update a MAC address object by UUID or name. PATCH uses JSON Merge "
            "Patch: omitted fields keep their stored value. Provide at most one of "
            "`macAddress` and `macAddresses`. Mutating."
        ),
        kind=ToolKind.MUTATION,
        handler=mac_address_update,
        annotations=_UPDATE,
    ),
    _ToolSpec(
        name="mac_address_delete",
        title="Delete a MAC address object",
        description=(
            "Delete a MAC address object by UUID or name. Destructive and not cascading: "
            "if the object is still referenced the appliance returns a conflict and "
            "nothing is deleted."
        ),
        kind=ToolKind.MUTATION,
        handler=mac_address_delete,
        annotations=_DELETE,
    ),
    _ToolSpec(
        name="country_group_list",
        title="List country groups",
        description=(
            "List one page of built-in country groups. Read-only. `page` is 1-based, "
            "`page_size` is 1-100 and `page_total` requests total metadata; "
            "`name_contains` and `name_not_equals` are mutually exclusive. Country groups "
            "are read-only in v1: no create, update or delete tool exists."
        ),
        kind=ToolKind.READ,
        handler=country_group_list,
    ),
    _ToolSpec(
        name="country_group_get",
        title="Get a country group",
        description=(
            "Read one built-in country group by UUID or name (`id_or_name`). Read-only. "
            "Returns the group's country references; no mutation is available."
        ),
        kind=ToolKind.READ,
        handler=country_group_get,
    ),
)


def register_objects_tools(server: MCPServer[AppContext], *, read_only: bool) -> None:
    """Register the address, group, MAC, country and service tools.

    This is the domain entry point the server factory wires into ``DEFAULT_DOMAINS``. It
    registers the 37 tools of this module and delegates the ten service tools to
    :func:`~sophos_firewall_mcp.tools.services_objects.register_service_objects_tools`.

    Args:
        server: The server built by :func:`sophos_firewall_mcp.server.create_server`.
        read_only: When true, mutation tools are not registered at all.
    """
    for spec in _TOOL_SPECS:
        register_tool(
            server,
            read_only=read_only,
            kind=spec.kind,
            name=spec.name,
            title=spec.title,
            description=spec.description,
            annotations=spec.annotations,
        )(spec.handler)
    register_service_objects_tools(server, read_only=read_only)
