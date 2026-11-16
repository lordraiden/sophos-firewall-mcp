"""MCP tools for Sophos network services and service groups (#29).

Ten operations from the audited v1 scope, one tool each:

* ``getAllServices``, ``getServiceByIdOrName``, ``createService``,
  ``updateServiceByIdOrName``, ``deleteServiceByIdOrName``;
* ``getAllServiceGroups``, ``getServiceGroupByIdOrName``, ``createServiceGroup``,
  ``updateServiceGroupByIdOrName``, ``deleteServiceGroupByIdOrName``.

Bulk delete is excluded from v1 and is not registered. Services and service groups keep
separate models because their payloads differ; a service group member is a name reference
to an existing service.

The module never builds an HTTP client or a URL: paths are module constants, the shared
client comes from :class:`~sophos_firewall_mcp.context.AppContext`, and typed transport
failures are mapped through :func:`~sophos_firewall_mcp.tools.tool_error`.
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
    DeleteResult,
    ListQuery,
    ObjectIdentifierInput,
    Service,
    ServiceCreate,
    ServiceGroup,
    ServiceGroupCreate,
    ServiceGroupListInput,
    ServiceGroupUpdateInput,
    ServiceListInput,
    ServiceUpdateInput,
)
from sophos_firewall_mcp.tools import (
    ADDITIVE_ANNOTATIONS,
    DESTRUCTIVE_ANNOTATIONS,
    DomainAdapter,
    ToolKind,
    register_tool,
    tool_error,
)

__all__ = [
    "SERVICES_PATH",
    "SERVICE_GROUPS_PATH",
    "ServicesAdapter",
    "register_service_objects_tools",
]

#: ``getAllServices`` / ``createService`` collection path.
SERVICES_PATH = "/network/services"

#: ``getAllServiceGroups`` / ``createServiceGroup`` collection path.
SERVICE_GROUPS_PATH = "/network/service-groups"

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


class ServicesAdapter(DomainAdapter):
    """Project the service and service-group operations onto typed MCP DTOs."""

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

    # -- Services -----------------------------------------------------------------

    async def list_services(self, request: ServiceListInput) -> ListPage[Service]:
        page = await self._list(SERVICES_PATH, request, ListPage[Service])
        if request.type is None:
            return page
        # The appliance ignores the API's ``type`` query parameter (observed on the appliance,
        # 2026-11-15), so the filter is applied to the projected page here. ``pages`` is the
        # appliance metadata for the unfiltered collection and is preserved unchanged.
        return ListPage[Service](
            items=[item for item in page.items if item.type == request.type],
            pages=page.pages,
        )

    async def get_service(self, request: ObjectIdentifierInput) -> Service:
        payload = await self._get(SERVICES_PATH, request.id_or_name)
        return _project(payload, Service, SERVICES_PATH)

    async def create_service(self, request: ServiceCreate) -> Service:
        body = request.model_dump(mode="json", by_alias=True, exclude_unset=True)
        payload = await self._create(SERVICES_PATH, body)
        return _project(payload, Service, SERVICES_PATH)

    async def update_service(self, request: ServiceUpdateInput) -> Service:
        body = request.model_dump(
            mode="json", by_alias=True, exclude_unset=True, exclude={"id_or_name"}
        )
        payload = await self._update(SERVICES_PATH, request.id_or_name, body)
        return _project(payload, Service, SERVICES_PATH)

    async def delete_service(self, request: ObjectIdentifierInput) -> DeleteResult:
        return await self._delete(SERVICES_PATH, request.id_or_name)

    # -- Service groups -----------------------------------------------------------

    async def list_service_groups(self, request: ServiceGroupListInput) -> ListPage[ServiceGroup]:
        return await self._list(SERVICE_GROUPS_PATH, request, ListPage[ServiceGroup])

    async def get_service_group(self, request: ObjectIdentifierInput) -> ServiceGroup:
        payload = await self._get(SERVICE_GROUPS_PATH, request.id_or_name)
        return _project(payload, ServiceGroup, SERVICE_GROUPS_PATH)

    async def create_service_group(self, request: ServiceGroupCreate) -> ServiceGroup:
        body = request.model_dump(mode="json", by_alias=True, exclude_unset=True)
        payload = await self._create(SERVICE_GROUPS_PATH, body)
        return _project(payload, ServiceGroup, SERVICE_GROUPS_PATH)

    async def update_service_group(self, request: ServiceGroupUpdateInput) -> ServiceGroup:
        body = request.model_dump(
            mode="json", by_alias=True, exclude_unset=True, exclude={"id_or_name"}
        )
        payload = await self._update(SERVICE_GROUPS_PATH, request.id_or_name, body)
        return _project(payload, ServiceGroup, SERVICE_GROUPS_PATH)

    async def delete_service_group(self, request: ObjectIdentifierInput) -> DeleteResult:
        return await self._delete(SERVICE_GROUPS_PATH, request.id_or_name)


# -- Handlers --------------------------------------------------------------------------


async def service_list(request: ServiceListInput, ctx: Context[AppContext]) -> ListPage[Service]:
    return await ServicesAdapter.from_context(ctx).list_services(request)


async def service_get(request: ObjectIdentifierInput, ctx: Context[AppContext]) -> Service:
    return await ServicesAdapter.from_context(ctx).get_service(request)


async def service_create(request: ServiceCreate, ctx: Context[AppContext]) -> Service:
    return await ServicesAdapter.from_context(ctx).create_service(request)


async def service_update(request: ServiceUpdateInput, ctx: Context[AppContext]) -> Service:
    return await ServicesAdapter.from_context(ctx).update_service(request)


async def service_delete(request: ObjectIdentifierInput, ctx: Context[AppContext]) -> DeleteResult:
    return await ServicesAdapter.from_context(ctx).delete_service(request)


async def service_group_list(
    request: ServiceGroupListInput, ctx: Context[AppContext]
) -> ListPage[ServiceGroup]:
    return await ServicesAdapter.from_context(ctx).list_service_groups(request)


async def service_group_get(
    request: ObjectIdentifierInput, ctx: Context[AppContext]
) -> ServiceGroup:
    return await ServicesAdapter.from_context(ctx).get_service_group(request)


async def service_group_create(
    request: ServiceGroupCreate, ctx: Context[AppContext]
) -> ServiceGroup:
    return await ServicesAdapter.from_context(ctx).create_service_group(request)


async def service_group_update(
    request: ServiceGroupUpdateInput, ctx: Context[AppContext]
) -> ServiceGroup:
    return await ServicesAdapter.from_context(ctx).update_service_group(request)


async def service_group_delete(
    request: ObjectIdentifierInput, ctx: Context[AppContext]
) -> DeleteResult:
    return await ServicesAdapter.from_context(ctx).delete_service_group(request)


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


_TOOL_SPECS: tuple[_ToolSpec, ...] = (
    _ToolSpec(
        name="service_list",
        title="List services",
        description=(
            "List one page of network services. Read-only. `type` filters by the API "
            "enum (tcpOrUdp, ip, icmp, icmpv6); the appliance currently ignores the `type` "
            "query parameter, so the filter is also applied client-side to the returned "
            "page: `items` may be shorter than `page_size` and `pages` still describes the "
            "unfiltered collection. `name_contains` and `name_not_equals` are mutually "
            "exclusive. `page` is 1-based and `page_size` is 1-100 (default 10). Returns "
            "the page items and the appliance `pages` metadata; it never auto-paginates. "
            "Size: the tested appliance's 94 services are ~28 KB of JSON at pageSize=50, so "
            "keep page_size small and page through the collection. The MCP SDK returns the "
            "payload both as a text block and as structuredContent; read one of them, not "
            "both."
        ),
        kind=ToolKind.READ,
        handler=service_list,
    ),
    _ToolSpec(
        name="service_get",
        title="Get a service",
        description=(
            "Read one network service by UUID or name (`id_or_name`). Read-only. Use it "
            "before updating or deleting to inspect the service `type` and its protocol "
            "detail entries."
        ),
        kind=ToolKind.READ,
        handler=service_get,
    ),
    _ToolSpec(
        name="service_create",
        title="Create a service",
        description=(
            "Create a network service. `name`, `type` and at least one `services` detail "
            "entry are required. Each detail entry is one of: TCP/UDP (`protocol` plus "
            "optional `sourcePort`/`destinationPort`), IP protocol (`ipProtocol`), ICMPv4 "
            "(`icmpType`+`icmpCode`) or ICMPv6 (`icmpv6Type`+`icmpv6Code`). A duplicate "
            "name returns a conflict and nothing is created."
        ),
        kind=ToolKind.MUTATION,
        handler=service_create,
        annotations=ADDITIVE_ANNOTATIONS,
    ),
    _ToolSpec(
        name="service_update",
        title="Update a service",
        description=(
            "Partially update a network service by UUID or name. PATCH uses JSON Merge "
            "Patch: omitted fields keep their stored value and `description: null` clears "
            "the description. The service `type` cannot be changed and is not accepted. "
            "Mutating."
        ),
        kind=ToolKind.MUTATION,
        handler=service_update,
        annotations=DESTRUCTIVE_ANNOTATIONS,
    ),
    _ToolSpec(
        name="service_delete",
        title="Delete a service",
        description=(
            "Delete a network service by UUID or name. Destructive and not cascading: if "
            "the service is still referenced by a rule or a service group the appliance "
            "returns a conflict and nothing is deleted."
        ),
        kind=ToolKind.MUTATION,
        handler=service_delete,
        annotations=DESTRUCTIVE_ANNOTATIONS,
    ),
    _ToolSpec(
        name="service_group_list",
        title="List service groups",
        description=(
            "List one page of service groups. Read-only. `name_contains` and "
            "`name_not_equals` are mutually exclusive; `page` is 1-based and `page_size` "
            "is 1-100 (default 10). Returns the page items and the appliance `pages` "
            "metadata."
        ),
        kind=ToolKind.READ,
        handler=service_group_list,
    ),
    _ToolSpec(
        name="service_group_get",
        title="Get a service group",
        description=(
            "Read one service group by UUID or name (`id_or_name`). Read-only. Returns the "
            "group's member services as name references."
        ),
        kind=ToolKind.READ,
        handler=service_group_get,
    ),
    _ToolSpec(
        name="service_group_create",
        title="Create a service group",
        description=(
            "Create a service group from existing network services. `name` and at least "
            'one `services` member reference of the form `{"name": "<service>"}` are '
            "required. Members must already exist; the appliance rejects an unknown name "
            "with a validation error."
        ),
        kind=ToolKind.MUTATION,
        handler=service_group_create,
        annotations=ADDITIVE_ANNOTATIONS,
    ),
    _ToolSpec(
        name="service_group_update",
        title="Update a service group",
        description=(
            "Partially update a service group by UUID or name. PATCH uses JSON Merge Patch: "
            "omitted fields keep their stored value and `description: null` clears the "
            "description. `services` replaces the whole member list. Mutating."
        ),
        kind=ToolKind.MUTATION,
        handler=service_group_update,
        annotations=DESTRUCTIVE_ANNOTATIONS,
    ),
    _ToolSpec(
        name="service_group_delete",
        title="Delete a service group",
        description=(
            "Delete a service group by UUID or name. Destructive and not cascading: if the "
            "group is still referenced by a rule the appliance returns a conflict and "
            "nothing is deleted."
        ),
        kind=ToolKind.MUTATION,
        handler=service_group_delete,
        annotations=DESTRUCTIVE_ANNOTATIONS,
    ),
)


def register_service_objects_tools(server: MCPServer[AppContext], *, read_only: bool) -> None:
    """Register the ten service and service-group tools through the shared contract.

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
