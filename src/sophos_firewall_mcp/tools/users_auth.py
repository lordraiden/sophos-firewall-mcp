"""MCP tools for Sophos Firewall authentication users and live sessions (#30).

Eight tools over eight audited operations, in two families that the API keeps apart:

* users -- ``user_list`` (``getUsers``, the paginated general authentication-user summary),
  ``network_user_list``/``network_user_get``/``network_user_create``/
  ``network_user_update``/``network_user_delete`` (network-user CRUD);
* live sessions -- ``live_user_list`` (``getLiveUsers``) and ``live_user_disconnect``
  (``disconnectLiveUser``).

Administrators, user groups, administrator password changes, bulk deletes and network-user
login/logout are classified in ``docs/API-COVERAGE.md`` and deliberately **not** registered
here. The login/logout operations have operational side effects and are out of the v1 tool
surface.

Layer rules (see :mod:`sophos_firewall_mcp.tools`): handlers are typed, receive the SDK
``Context`` and delegate to :class:`UsersAdapter`; the adapter owns the path constants, uses
the shared REST client from :class:`~sophos_firewall_mcp.context.AppContext` and maps
:class:`~sophos_firewall_mcp.errors.SophosAPIError` to a sanitized ``ToolError``. No handler
builds a URL, a header or an HTTP client, and no tool argument ever reaches a path except as
an encoded ``idOrName`` segment validated by the input model.

Credentials: ``password`` is a ``SecretStr`` in the create/update inputs. It is placed in the
request body only, is never logged, and no output model has a credential field.
"""

from __future__ import annotations

from typing import Annotated, Any, Callable, TypeVar
from urllib.parse import quote

from mcp.server.elicitation import ElicitationResult
from mcp.server.mcpserver import Context, MCPServer, Resolve
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import ValidationError

from sophos_firewall_mcp.context import AppContext
from sophos_firewall_mcp.errors import SophosAPIError
from sophos_firewall_mcp.models.common import ListPage
from sophos_firewall_mcp.models.users import (
    LiveUserDisconnectInput,
    LiveUserDisconnectOutput,
    LiveUserListInput,
    LiveUserSessionOutput,
    NetworkUserCreateInput,
    NetworkUserDeleteInput,
    NetworkUserDeleteOutput,
    NetworkUserGetInput,
    NetworkUserListInput,
    NetworkUserOutput,
    NetworkUserUpdateInput,
    UserListInput,
    UserSummaryOutput,
    project_disconnect_live_user,
    project_live_user_page,
    project_network_user,
    project_network_user_page,
    project_user_page,
)
from sophos_firewall_mcp.tools import (
    CONFIRMATION_NOTE,
    DestructiveConfirmation,
    DomainAdapter,
    ToolKind,
    destructive_confirmation,
    register_tool,
    require_confirmation,
    tool_error,
)

__all__ = ["register_users_tools"]


def _network_user_delete_target(request: NetworkUserDeleteInput) -> str:
    """The object the delete confirmation names."""
    return f"{request.id_or_name!r}"


#: The resolver that asks the client to confirm ``network_user_delete``.
_CONFIRM_NETWORK_USER_DELETE = destructive_confirmation(
    "delete the network user", _network_user_delete_target
)

OutputT = TypeVar("OutputT")

#: ``getUsers`` -- the paginated general authentication-user list.
USERS_PATH = "/authentication/users"

#: ``getNetworkUsers``/``createNetworkUser`` -- the network-user collection.
NETWORK_USERS_PATH = "/authentication/users/network-users"

#: ``getLiveUsers`` -- the live-session collection (no request pagination in the API).
LIVE_USERS_PATH = "/authentication/live-users"

#: ``disconnectLiveUser`` -- disconnect exactly one live session.
LIVE_USERS_DISCONNECT_PATH = "/authentication/live-users/disconnect"


def _network_user_path(id_or_name: str) -> str:
    """Build the ``/authentication/users/network-users/{idOrName}`` path.

    The identifier was validated by the input model (UUID or ``sfos-object-name``); it is
    percent-encoded so it can only ever be one path segment.
    """
    return f"{NETWORK_USERS_PATH}/{quote(id_or_name, safe='')}"


def _name_filter_params(
    request: UserListInput | NetworkUserListInput,
) -> dict[str, Any] | None:
    """Return the single documented name filter, or ``None`` when none was requested."""
    if request.name_contains is not None:
        return {"nameContains": request.name_contains}
    if request.name_not_equals is not None:
        return {"nameNotEquals": request.name_not_equals}
    return None


def _require_object(payload: Any, *, method: str, path: str) -> dict[str, Any]:
    """Reject a non-object body before projecting it, with a sanitized transport error."""
    if not isinstance(payload, dict):
        raise SophosAPIError(
            f"{method} {path} returned a non-object body",
            method=method,
            path=path,
        )
    return payload


def _schema_error(exc: ValidationError, path: str) -> ToolError:
    """Build the sanitized error for a response that does not match its output model.

    Only the field location is echoed: the rejected input may contain appliance data
    (including a network-user record), and the raw payload must never reach the model.
    """
    first = exc.errors()[0]
    location = ".".join(str(part) for part in first.get("loc", ())) or "body"
    return ToolError(
        f"the appliance returned a response for {path} that does not match the documented "
        f"schema ({location})"
    )


def _project(payload: Any, project: Callable[[Any], OutputT], path: str) -> OutputT:
    """Project one appliance payload, with a sanitized error when it does not match."""
    try:
        return project(payload)
    except ValidationError as exc:
        raise _schema_error(exc, path) from exc


def _create_body(request: NetworkUserCreateInput) -> dict[str, Any]:
    """Serialize the create body, extracting the secret only at the transport boundary."""
    body = request.model_dump(
        by_alias=True,
        exclude_unset=True,
        exclude={"password"},
        mode="json",
    )
    body["password"] = request.password.get_secret_value()
    return body


def _update_body(request: NetworkUserUpdateInput) -> dict[str, Any]:
    """Serialize a JSON Merge Patch body: only the fields the caller set are sent.

    Omitted fields keep their stored value; an explicit ``null`` is sent as a removal
    (RFC 7396). The password is extracted only here, never through a model dump.
    """
    body = request.model_dump(
        by_alias=True,
        exclude_unset=True,
        exclude={"id_or_name", "password"},
        mode="json",
    )
    if "password" in request.model_fields_set:
        # The input model rejects an explicit null password, so this is always a secret.
        password = request.password
        if password is not None:
            body["password"] = password.get_secret_value()
    return body


class UsersAdapter(DomainAdapter):
    """Domain adapter for the user and live-session operations.

    It owns the path constants, calls the shared REST client and projects payloads into the
    bounded DTOs from :mod:`sophos_firewall_mcp.models.users`. Every transport failure is
    mapped to a sanitized ``ToolError``; unexpected exceptions (including cancellation) are
    deliberately not caught.
    """

    async def list_users(self, request: UserListInput) -> ListPage[UserSummaryOutput]:
        """``getUsers``: one page of the general authentication-user list."""
        try:
            payload = await self.client.get_page(
                USERS_PATH,
                page=request.page,
                page_size=request.page_size,
                page_total=request.page_total,
                params=_name_filter_params(request),
            )
            return _project(payload, project_user_page, USERS_PATH)
        except SophosAPIError as exc:
            raise tool_error(exc) from exc

    async def list_network_users(
        self, request: NetworkUserListInput
    ) -> ListPage[NetworkUserOutput]:
        """``getNetworkUsers``: one page of the network-user collection."""
        try:
            payload = await self.client.get_page(
                NETWORK_USERS_PATH,
                page=request.page,
                page_size=request.page_size,
                page_total=request.page_total,
                params=_name_filter_params(request),
            )
            return _project(payload, project_network_user_page, NETWORK_USERS_PATH)
        except SophosAPIError as exc:
            raise tool_error(exc) from exc

    async def get_network_user(self, request: NetworkUserGetInput) -> NetworkUserOutput:
        """``getNetworkUser``: one network user by name or UUID."""
        path = _network_user_path(request.id_or_name)
        try:
            payload = await self.client.get(path)
            return _project(
                _require_object(payload, method="GET", path=path),
                project_network_user,
                NETWORK_USERS_PATH,
            )
        except SophosAPIError as exc:
            raise tool_error(exc) from exc

    async def create_network_user(self, request: NetworkUserCreateInput) -> NetworkUserOutput:
        """``createNetworkUser``: create one network user."""
        try:
            payload = await self.client.post(NETWORK_USERS_PATH, json=_create_body(request))
            return _project(
                _require_object(payload, method="POST", path=NETWORK_USERS_PATH),
                project_network_user,
                NETWORK_USERS_PATH,
            )
        except SophosAPIError as exc:
            raise tool_error(exc) from exc

    async def update_network_user(self, request: NetworkUserUpdateInput) -> NetworkUserOutput:
        """``updateNetworkUser``: PATCH one network user with JSON Merge Patch semantics."""
        path = _network_user_path(request.id_or_name)
        try:
            payload = await self.client.patch(path, json=_update_body(request))
            return _project(
                _require_object(payload, method="PATCH", path=path),
                project_network_user,
                NETWORK_USERS_PATH,
            )
        except SophosAPIError as exc:
            raise tool_error(exc) from exc

    async def delete_network_user(self, request: NetworkUserDeleteInput) -> NetworkUserDeleteOutput:
        """``deleteNetworkUser``: delete one network user by name or UUID."""
        path = _network_user_path(request.id_or_name)
        try:
            await self.client.delete(path)
        except SophosAPIError as exc:
            raise tool_error(exc) from exc
        return NetworkUserDeleteOutput(deleted=True, idOrName=request.id_or_name)

    async def list_live_users(self, request: LiveUserListInput) -> ListPage[LiveUserSessionOutput]:
        """``getLiveUsers``: the ``{items, pages}`` live-session body, no request pagination."""
        try:
            payload = await self.client.get(LIVE_USERS_PATH)
            return _project(
                _require_object(payload, method="GET", path=LIVE_USERS_PATH),
                project_live_user_page,
                LIVE_USERS_PATH,
            )
        except SophosAPIError as exc:
            raise tool_error(exc) from exc

    async def disconnect_live_user(
        self, request: LiveUserDisconnectInput
    ) -> LiveUserDisconnectOutput:
        """``disconnectLiveUser``: disconnect exactly one live session."""
        body = request.model_dump(by_alias=True, exclude_unset=True, mode="json")
        try:
            payload = await self.client.post(LIVE_USERS_DISCONNECT_PATH, json=body)
            return _project(
                _require_object(payload, method="POST", path=LIVE_USERS_DISCONNECT_PATH),
                lambda wire: project_disconnect_live_user(wire, request.live_user_id),
                LIVE_USERS_DISCONNECT_PATH,
            )
        except SophosAPIError as exc:
            raise tool_error(exc) from exc


def register_users_tools(server: MCPServer[AppContext], *, read_only: bool) -> None:
    """Register the user and live-session tools on ``server``.

    Args:
        server: The server built by :func:`sophos_firewall_mcp.server.create_server`.
        read_only: When true, the four mutation tools are not registered at all; only
            ``user_list``, ``network_user_list``, ``network_user_get`` and
            ``live_user_list`` remain.
    """

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.READ,
        name="user_list",
        title="List authentication users",
        description=(
            "List authentication users (`getUsers`) as a paginated basic summary: id, name, "
            "display name, description, active state, email addresses, group memberships and "
            "`administrativeAccess`. This is the general user list, not the network-user "
            "collection: use `network_user_list` for network-user accounts with policies and "
            "VPN access, and `network_user_get` for one account. Pagination is "
            "`page`/`page_size` (max 100, default 10)/`page_total`; the optional "
            "`name_contains` and `name_not_equals` filters are mutually exclusive. Returns one "
            "page per call; "
            "there is no cursor or limit parameter."
        ),
    )
    async def user_list(
        request: UserListInput, ctx: Context[AppContext]
    ) -> ListPage[UserSummaryOutput]:
        return await UsersAdapter.from_context(ctx).list_users(request)

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.READ,
        name="network_user_list",
        title="List network users",
        description=(
            "List network-user accounts (`getNetworkUsers`) as a paginated collection with "
            "their policies and VPN access. Returns one page per call; pagination is "
            "`page`/`page_size` (max 100, default 10)/`page_total`, and the optional "
            "`name_contains` and `name_not_equals` filters are mutually exclusive. This is the "
            "network-user "
            "collection, not the general authentication-user list: use `user_list` for the "
            "basic summary of all authentication users."
        ),
    )
    async def network_user_list(
        request: NetworkUserListInput, ctx: Context[AppContext]
    ) -> ListPage[NetworkUserOutput]:
        return await UsersAdapter.from_context(ctx).list_network_users(request)

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.READ,
        name="network_user_get",
        title="Get network user",
        description=(
            "Read one network-user account (`getNetworkUser`) by name or UUID. Returns the "
            "account with its group memberships, policies and VPN access; never returns "
            "credentials. A missing account is reported as not found, which is distinct from "
            "a permission denial."
        ),
    )
    async def network_user_get(
        request: NetworkUserGetInput, ctx: Context[AppContext]
    ) -> NetworkUserOutput:
        return await UsersAdapter.from_context(ctx).get_network_user(request)

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.MUTATION,
        name="network_user_create",
        title="Create network user",
        description=(
            "Create a network-user account (`createNetworkUser`). `name`, `display_name`, "
            "`password` and `group` are required; `group` is a `{name}` reference such as "
            '`{"name": "Open Group"}`, not a bare string. Description, active state, email '
            "addresses, policies and VPN access are optional. The password is write-only: it "
            "is sent once, is never returned, logged or included in errors. Returns the "
            "created account. Not idempotent: repeating the call creates nothing new but "
            "fails with a conflict because the name already exists."
        ),
        annotations=ToolAnnotations(destructive_hint=False, idempotent_hint=False),
    )
    async def network_user_create(
        request: NetworkUserCreateInput, ctx: Context[AppContext]
    ) -> NetworkUserOutput:
        return await UsersAdapter.from_context(ctx).create_network_user(request)

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.MUTATION,
        name="network_user_update",
        title="Update network user",
        description=(
            "Update a network-user account (`updateNetworkUser`) by name or UUID. This is a "
            "PATCH with JSON Merge Patch semantics: only the fields you provide are sent, so "
            "omitted fields keep their stored values and an explicit null removes a property. "
            "At least one field is required. `group`, when provided, is a `{name}` reference "
            'such as `{"name": "Open Group"}`, not a bare string. `password` is write-only and '
            "never returned. Returns the updated account. Idempotent: sending the same body "
            "twice leaves the same state."
        ),
        annotations=ToolAnnotations(destructive_hint=True, idempotent_hint=True),
    )
    async def network_user_update(
        request: NetworkUserUpdateInput, ctx: Context[AppContext]
    ) -> NetworkUserOutput:
        return await UsersAdapter.from_context(ctx).update_network_user(request)

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.MUTATION,
        name="network_user_delete",
        title="Delete network user",
        description=(
            "Delete a network-user account (`deleteNetworkUser`) by name or UUID. Destructive: "
            "the account is removed from the appliance. "
            f"{CONFIRMATION_NOTE} Idempotent: "
            "repeating the delete has no further effect and a second call reports not found. "
            "If the name has been reused in the meantime, re-read before retrying: the retry "
            "would target the new account. Returns `deleted` and the identifier the delete was "
            "issued for."
        ),
        annotations=ToolAnnotations(destructive_hint=True, idempotent_hint=True),
    )
    async def network_user_delete(
        request: NetworkUserDeleteInput,
        confirmation: Annotated[
            ElicitationResult[DestructiveConfirmation],
            Resolve(_CONFIRM_NETWORK_USER_DELETE),
        ],
        ctx: Context[AppContext],
    ) -> NetworkUserDeleteOutput:
        require_confirmation(confirmation, action="delete the network user")
        return await UsersAdapter.from_context(ctx).delete_network_user(request)

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.READ,
        name="live_user_list",
        title="List live user sessions",
        description=(
            "List active user sessions (`getLiveUsers`) as `items` plus `pages` metadata "
            "(`current`, `size`, `maxSize`, and `total`/`items` when returned). The API "
            "declares no request pagination for this operation, so this tool exposes no page "
            "parameters and reports the metadata exactly as returned; it does not loop over "
            "pages."
            + (
                " Use `live_user_disconnect` to terminate one session."
                if not read_only
                else " Terminating a session is not available in read-only mode."
            )
        ),
    )
    async def live_user_list(
        request: LiveUserListInput, ctx: Context[AppContext]
    ) -> ListPage[LiveUserSessionOutput]:
        return await UsersAdapter.from_context(ctx).list_live_users(request)

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.MUTATION,
        name="live_user_disconnect",
        title="Disconnect live user session",
        description=(
            "Disconnect one active user session (`disconnectLiveUser`). Both `live_user_id` "
            "(integer >= 1) and `message` (1-600 characters, shown to the user) are required. "
            "Destructive: the session is terminated immediately and the user must "
            "re-authenticate. Not idempotent: session identifiers are not stable, so do not "
            "retry blindly; list the sessions again first. Returns `disconnected` and the "
            "targeted session id."
        ),
        annotations=ToolAnnotations(destructive_hint=True, idempotent_hint=False),
    )
    async def live_user_disconnect(
        request: LiveUserDisconnectInput, ctx: Context[AppContext]
    ) -> LiveUserDisconnectOutput:
        return await UsersAdapter.from_context(ctx).disconnect_live_user(request)
