"""MCP tools for Sophos network addresses, address groups, MAC objects and country groups.

Twenty-seven tools from the audited v1 scope (#29):

* IPv4/IPv6 addresses: list/get/create/update/delete (5 merged tools, ``ip_family``
  selects the collection) plus the five FQDN address tools (10 tools);
* IPv4/IPv6 address groups: list/get/create/update/delete (5 merged tools) plus the five
  FQDN group tools (10 tools);
* MAC address objects: list/get/create/update/delete (5 tools);
* country groups: list/get only (2 tools). Country groups are built-in and read-only in
  v1; no mutation tool exists for them.

Bulk delete is excluded from v1 and is not registered. The IPv4 and IPv6 families keep
their own wire models: an IPv4 object is not an IPv6 object, an FQDN object is not a MAC
object, and a group only references members of its own family. The merged tools take a
required ``ip_family`` and the adapter selects the collection; the wire body is unchanged
for each family. Deletion never cascades: an in-use object returns a conflict from the
appliance and nothing is deleted.

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
    Address,
    AddressCreateInput,
    AddressGroupCreateInput,
    AddressGroupListInput,
    AddressGroupOutput,
    AddressGroupUpdateInput,
    AddressListInput,
    AddressResult,
    AddressUpdateInput,
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
    IpFamilyObjectIdentifierInput,
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

    # -- Addresses (IPv4 and IPv6; ``ip_family`` selects the collection) ----------

    async def list_addresses(self, request: AddressListInput) -> ListPage[Address]:
        path = IPV6_ADDRESSES_PATH if request.ip_family == "ipv6" else IPV4_ADDRESSES_PATH
        return await self._list(path, request, ListPage[Address])

    async def get_address(self, request: IpFamilyObjectIdentifierInput) -> AddressResult:
        path = IPV6_ADDRESSES_PATH if request.ip_family == "ipv6" else IPV4_ADDRESSES_PATH
        payload = await self._get(path, request.id_or_name)
        return _project({"address": payload}, AddressResult, path)

    async def create_address(self, request: AddressCreateInput) -> AddressResult:
        path = IPV6_ADDRESSES_PATH if request.ip_family == "ipv6" else IPV4_ADDRESSES_PATH
        body = request.model_dump(
            mode="json", by_alias=True, exclude_unset=True, exclude={"ip_family"}
        )
        payload = await self._create(path, body)
        return _project({"address": payload}, AddressResult, path)

    async def update_address(self, request: AddressUpdateInput) -> AddressResult:
        path = IPV6_ADDRESSES_PATH if request.ip_family == "ipv6" else IPV4_ADDRESSES_PATH
        body = request.model_dump(
            mode="json",
            by_alias=True,
            exclude_unset=True,
            exclude={"id_or_name", "ip_family"},
        )
        payload = await self._update(path, request.id_or_name, body)
        return _project({"address": payload}, AddressResult, path)

    async def delete_address(self, request: IpFamilyObjectIdentifierInput) -> DeleteResult:
        path = IPV6_ADDRESSES_PATH if request.ip_family == "ipv6" else IPV4_ADDRESSES_PATH
        return await self._delete(path, request.id_or_name)

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

    # -- Address groups (IPv4 and IPv6; ``ip_family`` selects the collection) -----

    async def list_address_groups(
        self, request: AddressGroupListInput
    ) -> ListPage[AddressGroupOutput]:
        path = IPV6_GROUPS_PATH if request.ip_family == "ipv6" else IPV4_GROUPS_PATH
        return await self._list(path, request, ListPage[AddressGroupOutput])

    async def get_address_group(self, request: IpFamilyObjectIdentifierInput) -> AddressGroupOutput:
        path = IPV6_GROUPS_PATH if request.ip_family == "ipv6" else IPV4_GROUPS_PATH
        payload = await self._get(path, request.id_or_name)
        return _project(payload, AddressGroupOutput, path)

    async def create_address_group(self, request: AddressGroupCreateInput) -> AddressGroupOutput:
        path = IPV6_GROUPS_PATH if request.ip_family == "ipv6" else IPV4_GROUPS_PATH
        body = request.model_dump(
            mode="json", by_alias=True, exclude_unset=True, exclude={"ip_family"}
        )
        payload = await self._create(path, body)
        return _project(payload, AddressGroupOutput, path)

    async def update_address_group(self, request: AddressGroupUpdateInput) -> AddressGroupOutput:
        path = IPV6_GROUPS_PATH if request.ip_family == "ipv6" else IPV4_GROUPS_PATH
        body = request.model_dump(
            mode="json",
            by_alias=True,
            exclude_unset=True,
            exclude={"id_or_name", "ip_family"},
        )
        payload = await self._update(path, request.id_or_name, body)
        return _project(payload, AddressGroupOutput, path)

    async def delete_address_group(self, request: IpFamilyObjectIdentifierInput) -> DeleteResult:
        path = IPV6_GROUPS_PATH if request.ip_family == "ipv6" else IPV4_GROUPS_PATH
        return await self._delete(path, request.id_or_name)

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


async def address_list(request: AddressListInput, ctx: Context[AppContext]) -> ListPage[Address]:
    return await ObjectsAdapter.from_context(ctx).list_addresses(request)


async def address_get(
    request: IpFamilyObjectIdentifierInput, ctx: Context[AppContext]
) -> AddressResult:
    return await ObjectsAdapter.from_context(ctx).get_address(request)


async def address_create(request: AddressCreateInput, ctx: Context[AppContext]) -> AddressResult:
    return await ObjectsAdapter.from_context(ctx).create_address(request)


async def address_update(request: AddressUpdateInput, ctx: Context[AppContext]) -> AddressResult:
    return await ObjectsAdapter.from_context(ctx).update_address(request)


async def address_delete(
    request: IpFamilyObjectIdentifierInput, ctx: Context[AppContext]
) -> DeleteResult:
    return await ObjectsAdapter.from_context(ctx).delete_address(request)


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


async def address_group_list(
    request: AddressGroupListInput, ctx: Context[AppContext]
) -> ListPage[AddressGroupOutput]:
    return await ObjectsAdapter.from_context(ctx).list_address_groups(request)


async def address_group_get(
    request: IpFamilyObjectIdentifierInput, ctx: Context[AppContext]
) -> AddressGroupOutput:
    return await ObjectsAdapter.from_context(ctx).get_address_group(request)


async def address_group_create(
    request: AddressGroupCreateInput, ctx: Context[AppContext]
) -> AddressGroupOutput:
    return await ObjectsAdapter.from_context(ctx).create_address_group(request)


async def address_group_update(
    request: AddressGroupUpdateInput, ctx: Context[AppContext]
) -> AddressGroupOutput:
    return await ObjectsAdapter.from_context(ctx).update_address_group(request)


async def address_group_delete(
    request: IpFamilyObjectIdentifierInput, ctx: Context[AppContext]
) -> DeleteResult:
    return await ObjectsAdapter.from_context(ctx).delete_address_group(request)


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
        name="address_list",
        title="List addresses",
        description=(
            "List one page of IPv4 or IPv6 address objects (single address, network, range "
            "or IP list), selected by the required `ip_family`. Read-only. `page` is 1-based, "
            "`page_size` is 1-100 (default 10) and `page_total` requests total metadata; "
            "`name_contains` and `name_not_equals` are mutually exclusive. Returns the page "
            "items and the appliance `pages` metadata; it never auto-paginates."
        ),
        kind=ToolKind.READ,
        handler=address_list,
    ),
    _ToolSpec(
        name="address_get",
        title="Get an address",
        description=(
            "Read one IPv4 or IPv6 address object by UUID or name (`id_or_name`), selected "
            "by the required `ip_family`. Read-only. The response is discriminated by `type` "
            "(ipv4Address/ipv4Network/ipv4Range/ipv4List or the IPv6 equivalents); use it "
            "before updating or deleting to confirm the shape."
        ),
        kind=ToolKind.READ,
        handler=address_get,
    ),
    _ToolSpec(
        name="address_create",
        title="Create an address",
        description=(
            "Create an IPv4 or IPv6 address object, selected by the required `ip_family`. "
            "`type` selects the shape: a single address, a network (address + `cidr` or "
            "`prefix_length`), a range (start + end) or a list. `name` is required and must "
            "be a valid Sophos object name. A duplicate name returns a conflict and nothing "
            "is created."
        ),
        kind=ToolKind.MUTATION,
        handler=address_create,
        annotations=_CREATE,
    ),
    _ToolSpec(
        name="address_update",
        title="Update an address",
        description=(
            "Partially update an IPv4 or IPv6 address object by UUID or name, selected by "
            "the required `ip_family`. PATCH uses JSON Merge Patch: omitted fields keep "
            "their stored value and `description: null` clears the description. The object "
            "`type` cannot be changed and is not accepted. Mutating."
        ),
        kind=ToolKind.MUTATION,
        handler=address_update,
        annotations=_UPDATE,
    ),
    _ToolSpec(
        name="address_delete",
        title="Delete an address",
        description=(
            "Delete an IPv4 or IPv6 address object by UUID or name, selected by the "
            "required `ip_family`. Destructive and not cascading: if the object is still "
            "referenced by a rule, group or NAT entry the appliance returns a conflict and "
            "nothing is deleted."
        ),
        kind=ToolKind.MUTATION,
        handler=address_delete,
        annotations=_DELETE,
    ),
    _ToolSpec(
        name="address_list_fqdn",
        title="List FQDN addresses",
        description=(
            "List one page of FQDN address objects. Read-only. `page` is 1-based, "
            "`page_size` is 1-100 (default 10) and `page_total` requests total metadata; "
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
        name="address_group_list",
        title="List address groups",
        description=(
            "List one page of IPv4 or IPv6 address groups, selected by the required "
            "`ip_family`. Read-only. `page` is 1-based, `page_size` is 1-100 (default 10) "
            "and `page_total` requests total metadata; `name_contains` and `name_not_equals` "
            "are mutually exclusive. Members are returned as name references."
        ),
        kind=ToolKind.READ,
        handler=address_group_list,
    ),
    _ToolSpec(
        name="address_group_get",
        title="Get an address group",
        description=(
            "Read one IPv4 or IPv6 address group by UUID or name (`id_or_name`), selected by "
            "the required `ip_family`. Read-only. Members are address objects of the same "
            "family referenced by name; a group never mixes address families."
        ),
        kind=ToolKind.READ,
        handler=address_group_get,
    ),
    _ToolSpec(
        name="address_group_create",
        title="Create an address group",
        description=(
            "Create an IPv4 or IPv6 address group from existing address objects of the same "
            "family, selected by the required `ip_family`. `name` and the family's member "
            'list (`ipv4Addresses` or `ipv6Addresses`, a list of `{"name": ...}` references, '
            "possibly empty) are required. Members must already exist and must belong to "
            "the same family; the appliance rejects an unknown or wrong-family name."
        ),
        kind=ToolKind.MUTATION,
        handler=address_group_create,
        annotations=_CREATE,
    ),
    _ToolSpec(
        name="address_group_update",
        title="Update an address group",
        description=(
            "Partially update an IPv4 or IPv6 address group by UUID or name, selected by the "
            "required `ip_family`. PATCH uses JSON Merge Patch: omitted fields keep their "
            "stored value and the family's member list replaces the whole member list. "
            "Mutating."
        ),
        kind=ToolKind.MUTATION,
        handler=address_group_update,
        annotations=_UPDATE,
    ),
    _ToolSpec(
        name="address_group_delete",
        title="Delete an address group",
        description=(
            "Delete an IPv4 or IPv6 address group by UUID or name, selected by the required "
            "`ip_family`. Destructive and not cascading: if the group is still referenced by "
            "a rule or another group the appliance returns a conflict and nothing is "
            "deleted."
        ),
        kind=ToolKind.MUTATION,
        handler=address_group_delete,
        annotations=_DELETE,
    ),
    _ToolSpec(
        name="address_group_list_fqdn",
        title="List FQDN address groups",
        description=(
            "List one page of FQDN address groups. Read-only. `page` is 1-based, "
            "`page_size` is 1-100 (default 10) and `page_total` requests total metadata; "
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
            "in the API. Members must already exist and must be FQDN address objects."
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
            "Read-only. `page` is 1-based, `page_size` is 1-100 (default 10) and "
            "`page_total` requests total metadata; `name_contains` and `name_not_equals` are "
            "mutually exclusive. Returns the page items and the appliance `pages` metadata."
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
            "`page_size` is 1-100 (default 10) and `page_total` requests total metadata; "
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
