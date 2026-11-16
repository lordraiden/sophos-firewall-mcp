"""Read-only IPsec and SSL VPN tools.

VPN is **read-only in v1**: this module registers 20 GET tools and no mutation. The 11 IPsec
operations cover profiles, failover groups, policy-based and route-based IPv4 site-to-site
connections, live site-to-site connections and remote-access settings; the 9 SSL VPN
operations cover remote-access policies, clientless policies, bookmark groups, bookmarks and
global settings. Every VPN mutation (create/update/delete/bulk delete) is excluded from the
first release and is deliberately absent here -- there is no hidden write path.

Two distinctions the tools keep explicit:

* **Configured vs live.** ``ipsec_connection_list_ipv4`` and the policy/route-based tools
  return configuration; ``ipsec_live_connection_list_ipv4`` returns the live IKE/IPsec
  security associations and their traffic counters. Neither is derived from the other.
* **SSL VPN remote access vs site-to-site.** Only remote-access resources exist in this
  contract: SSL VPN site-to-site is not supported by SFOS 23 and is absent from the
  contract, so no placeholder tool is advertised.

The adapter repeats three small read helpers from the network adapter instead of importing
it, because the network module registers this module and a shared import would be circular;
``tools/__init__.py`` (owned by the foundation) has no read-helper base to extend.
"""

from __future__ import annotations

from typing import Any, TypeVar
from urllib.parse import quote

from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from pydantic import BaseModel, ValidationError

from sophos_firewall_mcp.context import AppContext
from sophos_firewall_mcp.errors import SophosAPIError
from sophos_firewall_mcp.models import vpn as models
from sophos_firewall_mcp.models.common import ListPage
from sophos_firewall_mcp.tools import DomainAdapter, ToolKind, register_tool, tool_error

__all__ = ["register_vpn_tools"]

ModelT = TypeVar("ModelT", bound=BaseModel)

# -- API paths (module constants: no tool argument ever reaches a path) -----------------

_PROFILES = "/ipsec-vpn/profiles"
_REMOTE_ACCESS_SETTINGS = "/ipsec-vpn/remote-access/settings"
_CONNECTIONS_IPV4 = "/ipsec-vpn/site-to-site/connections/ipv4"
_POLICY_BASED_IPV4 = "/ipsec-vpn/site-to-site/connections/policy-based/ipv4"
_ROUTE_BASED_IPV4 = "/ipsec-vpn/site-to-site/connections/route-based/ipv4"
_LIVE_CONNECTIONS_IPV4 = "/ipsec-vpn/site-to-site/live-connections/ipv4"
_FAILOVER_GROUPS = "/ipsec-vpn/site-to-site/failover-groups"
_SSL_REMOTE_ACCESS_POLICIES = "/ssl-vpn/remote-access/policies"
_BOOKMARK_GROUPS = "/ssl-vpn/clientless/bookmark-groups"
_BOOKMARKS = "/ssl-vpn/clientless/bookmarks"
_CLIENTLESS_POLICIES = "/ssl-vpn/clientless/policies"
_SSL_GLOBAL_SETTINGS = "/ssl-vpn/global-settings"


def _segment(value: str) -> str:
    """Percent-encode one path segment (names may contain spaces, dots and slashes)."""
    return quote(value, safe="")


def _require_object(payload: Any, path: str) -> dict[str, Any]:
    """Reject a non-object body from an operation that documents an object response."""
    if not isinstance(payload, dict):
        raise ToolError(f"the appliance returned a non-object body for GET {path}")
    return payload


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


def _project(payload: Any, model: type[ModelT], path: str) -> ModelT:
    """Validate one appliance payload into its bounded model, with a sanitized error."""
    try:
        return model.model_validate(payload)
    except ValidationError as exc:
        raise _schema_error(exc, path) from exc


class VpnAdapter(DomainAdapter):
    """Domain adapter for the read-only VPN operations.

    It owns the path constants, calls the shared REST client and maps transport failures to
    sanitized ``ToolError`` messages. It never creates an HTTP client and never accepts a
    path from a tool argument.
    """

    async def page(
        self, path: str, request: models.VpnPageInput | models.VpnFilteredPageInput
    ) -> dict[str, Any]:
        """Read one page of a paginated collection, with the declared name filters."""
        filters = request.name_filters() if isinstance(request, models.VpnFilteredPageInput) else {}
        try:
            return await self.client.get_page(
                path,
                page=request.page,
                page_size=request.page_size,
                page_total=request.page_total,
                params=filters,
            )
        except SophosAPIError as exc:
            raise tool_error(exc) from exc

    async def failover_group_page(
        self, path: str, request: models.FailoverGroupListInput
    ) -> dict[str, Any]:
        """Read one page of failover groups, including the declared filter/sort parameters."""
        filters = request.name_filters()
        filters.update(request.extra_filters())
        try:
            return await self.client.get_page(
                path,
                page=request.page,
                page_size=request.page_size,
                page_total=request.page_total,
                params=filters,
            )
        except SophosAPIError as exc:
            raise tool_error(exc) from exc

    async def unpaginated(self, path: str) -> dict[str, Any]:
        """Read a collection whose operation declares no pagination parameters."""
        try:
            payload = await self.client.get(path)
        except SophosAPIError as exc:
            raise tool_error(exc) from exc
        return _require_object(payload, path)

    async def object(self, path: str, id_or_name: str) -> dict[str, Any]:
        """Read one object by name or UUID."""
        full_path = f"{path}/{_segment(id_or_name)}"
        try:
            payload = await self.client.get(full_path)
        except SophosAPIError as exc:
            raise tool_error(exc) from exc
        return _require_object(payload, full_path)

    async def single(self, path: str) -> dict[str, Any]:
        """Read a singleton settings object."""
        try:
            payload = await self.client.get(path)
        except SophosAPIError as exc:
            raise tool_error(exc) from exc
        return _require_object(payload, path)


def register_vpn_tools(server: MCPServer[AppContext], *, read_only: bool) -> None:
    """Register the 20 read-only IPsec and SSL VPN tools.

    Called by :func:`sophos_firewall_mcp.tools.network.register_network_tools`; it can also be
    called directly in a test. Every tool is a read, so ``read_only`` has no effect on the
    registered set -- the VPN surface is read-only in both modes.

    Args:
        server: The server built by :func:`sophos_firewall_mcp.server.create_server`.
        read_only: The resolved read-only mode; the VPN tools are reads either way.
    """

    # -- IPsec profiles ----------------------------------------------------------------

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.READ,
        name="ipsec_profile_list",
        title="List IPsec profiles",
        description=(
            "List the IPsec profiles one page at a time, with optional name filters. Each "
            "profile carries its key exchange (IKEv1/IKEv2), authentication mode, phase-1 and "
            "phase-2 proposals and dead-peer-detection settings. Pagination: `page` is 1-based "
            "and `page_size` is 1-100 (default 10). Read-only: VPN mutations are "
            "excluded from this server."
        ),
    )
    async def ipsec_profile_list(
        request: models.VpnFilteredPageInput, ctx: Context[AppContext]
    ) -> ListPage[models.IpsecProfile]:
        payload = await VpnAdapter.from_context(ctx).page(_PROFILES, request)
        return _project(payload, ListPage[models.IpsecProfile], _PROFILES)

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.READ,
        name="ipsec_profile_get",
        title="Get an IPsec profile",
        description="Read one IPsec profile by name or UUID. Read-only.",
    )
    async def ipsec_profile_get(
        request: models.VpnProfileRefInput, ctx: Context[AppContext]
    ) -> models.IpsecProfile:
        payload = await VpnAdapter.from_context(ctx).object(_PROFILES, request.id_or_name)
        return _project(payload, models.IpsecProfile, _PROFILES)

    # -- IPsec failover groups ---------------------------------------------------------

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.READ,
        name="ipsec_failover_group_list",
        title="List IPsec failover groups",
        description=(
            "List the IPsec site-to-site failover groups one page at a time, with optional name "
            "filters and the operation's opaque filter/sort parameters. Each group carries its "
            "member connections, liveness checks and failback settings. Pagination: `page` is "
            "1-based and `page_size` is 1-100 (default 10). Read-only."
        ),
    )
    async def ipsec_failover_group_list(
        request: models.FailoverGroupListInput, ctx: Context[AppContext]
    ) -> ListPage[models.IpsecFailoverGroup]:
        payload = await VpnAdapter.from_context(ctx).failover_group_page(_FAILOVER_GROUPS, request)
        return _project(payload, ListPage[models.IpsecFailoverGroup], _FAILOVER_GROUPS)

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.READ,
        name="ipsec_failover_group_get",
        title="Get an IPsec failover group",
        description="Read one IPsec failover group by name or UUID. Read-only.",
    )
    async def ipsec_failover_group_get(
        request: models.VpnFailoverGroupRefInput, ctx: Context[AppContext]
    ) -> models.IpsecFailoverGroup:
        payload = await VpnAdapter.from_context(ctx).object(_FAILOVER_GROUPS, request.id_or_name)
        return _project(payload, models.IpsecFailoverGroup, _FAILOVER_GROUPS)

    # -- IPsec site-to-site connections ------------------------------------------------

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.READ,
        name="ipsec_connection_list_ipv4",
        title="List IPv4 IPsec site-to-site connections",
        description=(
            "List the configured IPv4 IPsec site-to-site connections one page at a time, with "
            "optional name filters. Each item carries its type (policyBased or routeBased), "
            "gateway mode, profile, gateway settings and protected networks. This is "
            "configuration: use ipsec_live_connection_list_ipv4 for live security "
            "associations. The API has no IPv6 counterpart. Read-only."
        ),
    )
    async def ipsec_connection_list_ipv4(
        request: models.VpnFilteredPageInput, ctx: Context[AppContext]
    ) -> ListPage[models.IpsecConnection]:
        payload = await VpnAdapter.from_context(ctx).page(_CONNECTIONS_IPV4, request)
        return _project(payload, ListPage[models.IpsecConnection], _CONNECTIONS_IPV4)

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.READ,
        name="ipsec_policy_based_connection_list_ipv4",
        title="List policy-based IPv4 IPsec connections",
        description=(
            "List the configured policy-based IPv4 site-to-site connections one page at a time, "
            "with optional name filters. The API has no IPv6 counterpart. Read-only."
        ),
    )
    async def ipsec_policy_based_connection_list_ipv4(
        request: models.VpnFilteredPageInput, ctx: Context[AppContext]
    ) -> ListPage[models.IpsecConnection]:
        payload = await VpnAdapter.from_context(ctx).page(_POLICY_BASED_IPV4, request)
        return _project(payload, ListPage[models.IpsecConnection], _POLICY_BASED_IPV4)

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.READ,
        name="ipsec_policy_based_connection_get_ipv4",
        title="Get a policy-based IPv4 IPsec connection",
        description=(
            "Read one policy-based IPv4 site-to-site connection by name or UUID. The API has "
            "no IPv6 counterpart. Read-only."
        ),
    )
    async def ipsec_policy_based_connection_get_ipv4(
        request: models.VpnPolicyBasedConnectionRefInput, ctx: Context[AppContext]
    ) -> models.IpsecConnection:
        payload = await VpnAdapter.from_context(ctx).object(_POLICY_BASED_IPV4, request.id_or_name)
        return _project(payload, models.IpsecConnection, _POLICY_BASED_IPV4)

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.READ,
        name="ipsec_route_based_connection_list_ipv4",
        title="List route-based IPv4 IPsec connections",
        description=(
            "List the configured route-based IPv4 site-to-site connections one page at a time, "
            "with optional name filters. Each item also carries its tunnel interface. The API "
            "has no IPv6 counterpart. Read-only."
        ),
    )
    async def ipsec_route_based_connection_list_ipv4(
        request: models.VpnFilteredPageInput, ctx: Context[AppContext]
    ) -> ListPage[models.IpsecRouteBasedConnection]:
        payload = await VpnAdapter.from_context(ctx).page(_ROUTE_BASED_IPV4, request)
        return _project(payload, ListPage[models.IpsecRouteBasedConnection], _ROUTE_BASED_IPV4)

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.READ,
        name="ipsec_route_based_connection_get_ipv4",
        title="Get a route-based IPv4 IPsec connection",
        description=(
            "Read one route-based IPv4 site-to-site connection by name or UUID. The API has no "
            "IPv6 counterpart. Read-only."
        ),
    )
    async def ipsec_route_based_connection_get_ipv4(
        request: models.VpnRouteBasedConnectionRefInput, ctx: Context[AppContext]
    ) -> models.IpsecRouteBasedConnection:
        payload = await VpnAdapter.from_context(ctx).object(_ROUTE_BASED_IPV4, request.id_or_name)
        return _project(payload, models.IpsecRouteBasedConnection, _ROUTE_BASED_IPV4)

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.READ,
        name="ipsec_live_connection_list_ipv4",
        title="List live IPv4 IPsec site-to-site connections",
        description=(
            "List the live IPv4 site-to-site connections with their established IKE and IPsec "
            "security associations, traffic selectors and packet/byte counters. This is "
            "operational state, not configuration: an empty list means no tunnel is currently "
            "established, not that none is configured. The operation declares no pagination "
            "parameters and the appliance caps the response at 1000 items (pages.size and "
            "pages.maxSize are both 1000), so a list of exactly 1000 items may be truncated "
            "and there is no way to page past it. The API has no IPv6 counterpart. Read-only."
        ),
    )
    async def ipsec_live_connection_list_ipv4(
        ctx: Context[AppContext],
    ) -> ListPage[models.IpsecLiveConnection]:
        payload = await VpnAdapter.from_context(ctx).unpaginated(_LIVE_CONNECTIONS_IPV4)
        return _project(payload, ListPage[models.IpsecLiveConnection], _LIVE_CONNECTIONS_IPV4)

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.READ,
        name="ipsec_remote_access_settings_get",
        title="Get IPsec remote-access settings",
        description=(
            "Read the remote-access IPsec configuration: connection state, profile, gateway "
            "authentication, authorized users and groups, the IPv4 lease range, DNS settings "
            "and Sophos Connect client settings. configured is derived, not returned by the "
            "appliance: it is false when connectionState is unset (remote-access IPsec is not "
            "configured at all) and true when connectionState is enabled or disabled, so an "
            "agent does not have to know the unset sentinel. Read-only: the settings cannot be "
            "changed through this server."
        ),
    )
    async def ipsec_remote_access_settings_get(
        ctx: Context[AppContext],
    ) -> models.IpsecRemoteAccessSettings:
        payload = await VpnAdapter.from_context(ctx).single(_REMOTE_ACCESS_SETTINGS)
        return _project(payload, models.IpsecRemoteAccessSettings, _REMOTE_ACCESS_SETTINGS)

    # -- SSL VPN remote-access policies ------------------------------------------------

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.READ,
        name="sslvpn_remote_access_policy_list",
        title="List SSL VPN remote-access policies",
        description=(
            "List the SSL VPN remote-access policies one page at a time, with optional name "
            "filters. Each policy carries its members, full-tunnel flag, permitted IPv4/IPv6 "
            "networks and idle-peer-detection settings. Pagination: `page` is 1-based and "
            "`page_size` is 1-100 (default 10). Read-only."
        ),
    )
    async def sslvpn_remote_access_policy_list(
        request: models.VpnFilteredPageInput, ctx: Context[AppContext]
    ) -> ListPage[models.SslVpnRemoteAccessPolicy]:
        payload = await VpnAdapter.from_context(ctx).page(_SSL_REMOTE_ACCESS_POLICIES, request)
        return _project(
            payload, ListPage[models.SslVpnRemoteAccessPolicy], _SSL_REMOTE_ACCESS_POLICIES
        )

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.READ,
        name="sslvpn_remote_access_policy_get",
        title="Get an SSL VPN remote-access policy",
        description="Read one SSL VPN remote-access policy by name or UUID. Read-only.",
    )
    async def sslvpn_remote_access_policy_get(
        request: models.VpnRemoteAccessPolicyRefInput, ctx: Context[AppContext]
    ) -> models.SslVpnRemoteAccessPolicy:
        payload = await VpnAdapter.from_context(ctx).object(
            _SSL_REMOTE_ACCESS_POLICIES, request.id_or_name
        )
        return _project(payload, models.SslVpnRemoteAccessPolicy, _SSL_REMOTE_ACCESS_POLICIES)

    # -- SSL VPN clientless bookmarks --------------------------------------------------

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.READ,
        name="sslvpn_bookmark_group_list",
        title="List SSL VPN bookmark groups",
        description=(
            "List the clientless SSL VPN bookmark groups one page at a time, with optional name "
            "filters. Bookmark groups and bookmarks are separate resources. Pagination: `page` "
            "is 1-based and `page_size` is 1-100 (default 10). Read-only."
        ),
    )
    async def sslvpn_bookmark_group_list(
        request: models.VpnFilteredPageInput, ctx: Context[AppContext]
    ) -> ListPage[models.SslVpnBookmarkGroup]:
        payload = await VpnAdapter.from_context(ctx).page(_BOOKMARK_GROUPS, request)
        return _project(payload, ListPage[models.SslVpnBookmarkGroup], _BOOKMARK_GROUPS)

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.READ,
        name="sslvpn_bookmark_group_get",
        title="Get an SSL VPN bookmark group",
        description="Read one clientless SSL VPN bookmark group by name or UUID. Read-only.",
    )
    async def sslvpn_bookmark_group_get(
        request: models.VpnBookmarkGroupRefInput, ctx: Context[AppContext]
    ) -> models.SslVpnBookmarkGroup:
        payload = await VpnAdapter.from_context(ctx).object(_BOOKMARK_GROUPS, request.id_or_name)
        return _project(payload, models.SslVpnBookmarkGroup, _BOOKMARK_GROUPS)

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.READ,
        name="sslvpn_bookmark_list",
        title="List SSL VPN bookmarks",
        description=(
            "List the clientless SSL VPN bookmarks one page at a time, with optional name "
            "filters. The API models eight protocol variants (rdp, telnet, ssh, ftp, ftps, "
            "sftp, smb, vnc); each item is projected with its protocol and the variant's target "
            "fields. Credentials are never returned. Pagination: `page` is 1-based and "
            "`page_size` is 1-100 (default 10). Read-only."
        ),
    )
    async def sslvpn_bookmark_list(
        request: models.VpnFilteredPageInput, ctx: Context[AppContext]
    ) -> ListPage[models.SslVpnBookmark]:
        payload = await VpnAdapter.from_context(ctx).page(_BOOKMARKS, request)
        return _project(payload, ListPage[models.SslVpnBookmark], _BOOKMARKS)

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.READ,
        name="sslvpn_bookmark_get",
        title="Get an SSL VPN bookmark",
        description=(
            "Read one clientless SSL VPN bookmark by name or UUID. The eight protocol variants "
            "are flattened into one projection with a 'protocol' field. Read-only."
        ),
    )
    async def sslvpn_bookmark_get(
        request: models.VpnBookmarkRefInput, ctx: Context[AppContext]
    ) -> models.SslVpnBookmark:
        payload = await VpnAdapter.from_context(ctx).object(_BOOKMARKS, request.id_or_name)
        return _project(payload, models.SslVpnBookmark, _BOOKMARKS)

    # -- SSL VPN clientless policies and global settings -------------------------------

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.READ,
        name="sslvpn_clientless_policy_list",
        title="List SSL VPN clientless policies",
        description=(
            "List the SSL VPN Web Access (clientless) policies one page at a time, with optional "
            "name filters. Each policy carries its member users/groups and the bookmarks and "
            "bookmark groups it publishes. Pagination: `page` is 1-based and `page_size` "
            "is 1-100 (default 10). Read-only."
        ),
    )
    async def sslvpn_clientless_policy_list(
        request: models.VpnFilteredPageInput, ctx: Context[AppContext]
    ) -> ListPage[models.SslVpnClientlessPolicy]:
        payload = await VpnAdapter.from_context(ctx).page(_CLIENTLESS_POLICIES, request)
        return _project(payload, ListPage[models.SslVpnClientlessPolicy], _CLIENTLESS_POLICIES)

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.READ,
        name="sslvpn_clientless_policy_get",
        title="Get an SSL VPN clientless policy",
        description="Read one SSL VPN clientless policy by name or UUID. Read-only.",
    )
    async def sslvpn_clientless_policy_get(
        request: models.VpnClientlessPolicyRefInput, ctx: Context[AppContext]
    ) -> models.SslVpnClientlessPolicy:
        payload = await VpnAdapter.from_context(ctx).object(
            _CLIENTLESS_POLICIES, request.id_or_name
        )
        return _project(payload, models.SslVpnClientlessPolicy, _CLIENTLESS_POLICIES)

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.READ,
        name="sslvpn_global_settings_get",
        title="Get SSL VPN global settings",
        description=(
            "Read the SSL VPN global settings: protocol and port, server certificate, override "
            "host, client lease pools, DNS/WINS settings, peer-detection timeouts, cryptographic "
            "settings and Sophos Connect client settings. Read-only: the settings cannot be "
            "changed through this server."
        ),
    )
    async def sslvpn_global_settings_get(ctx: Context[AppContext]) -> models.SslVpnGlobalSettings:
        payload = await VpnAdapter.from_context(ctx).single(_SSL_GLOBAL_SETTINGS)
        return _project(payload, models.SslVpnGlobalSettings, _SSL_GLOBAL_SETTINGS)
