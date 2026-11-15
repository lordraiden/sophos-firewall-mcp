"""MCP resources: the passive context a client reads instead of calling a tool.

The MCP specification splits a server's surface into three primitives: tools are
model-controlled actions, resources are application-controlled passive context, and
prompts are user-controlled templates. This server's tools are narrow and typed, so the
context a model needs *before* it calls them -- the REST API surface, the coverage matrix,
the read-only policy and the calling conventions -- is published here once instead of
being repeated in 112 tool descriptions.

Every resource is a constant for the process lifetime. The read-only mode is resolved
before registration and nothing else in the content depends on request state, which is why
:mod:`sophos_firewall_mcp.server` gives ``resources/list`` and ``resources/read`` the same
long cache hint as ``tools/list``.

The coverage matrix is a summary of ``docs/API-COVERAGE.md``, which is generated from the
checked-in OpenAPI document. That document is not shipped in the wheel, so the summary is
embedded here and ``tests/test_server.py`` compares it against the document: a
regeneration that changes a count fails the test instead of leaving a stale resource.

Nothing here touches the network, the appliance or the tool registry: a resource is a
string built from module-level constants.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, NamedTuple

from sophos_firewall_mcp.config import API_PATH_PREFIX

if TYPE_CHECKING:  # pragma: no cover - typing only, keeps the mcp import out of this module
    from mcp.server.mcpserver import MCPServer

    from sophos_firewall_mcp.context import AppContext

__all__ = [
    "API_COMPONENT_SCHEMAS",
    "API_OPERATIONS",
    "API_OPERATIONS_BY_METHOD",
    "API_PAGINATED_GET_OPERATIONS",
    "API_PATHS",
    "ARGUMENT_TOOL_COUNT",
    "COMPOSITE_TOOL_COUNT",
    "COMPOSITE_TOOLS",
    "COVERAGE_DOMAINS",
    "MUTATION_TOOL_COUNT",
    "NO_ARGUMENT_TOOLS",
    "READ_ONLY_TOOL_COUNT",
    "TOOL_MAP_COUNT",
    "TOTAL_TOOL_COUNT",
    "CoverageDomain",
    "register_resources",
]

#: Paths in the checked-in OpenAPI document.
API_PATHS = 384

#: Operations in the checked-in OpenAPI document, and their split by HTTP method.
API_OPERATIONS = 700
API_OPERATIONS_BY_METHOD: tuple[tuple[str, int], ...] = (
    ("GET", 263),
    ("POST", 210),
    ("PATCH", 134),
    ("DELETE", 93),
)

#: Component schemas the document defines.
API_COMPONENT_SCHEMAS = 32

#: GET operations that declare ``page``/``pageSize``/``pageTotal``.
API_PAGINATED_GET_OPERATIONS = 83

#: Audited operations exposed as tools (the curated ``tool_map``).
TOOL_MAP_COUNT = 145

#: Tools that map one-to-one to an audited operation.
#:
#: Lower than :data:`TOOL_MAP_COUNT` because the IPv4/IPv6 pairs are one tool each: 38
#: one-to-one pairs cover 76 operations with 38 tools.
ONE_TO_ONE_TOOL_COUNT = 107

#: Tools that compose audited operations and add no endpoint.
COMPOSITE_TOOL_COUNT = 5

#: Tools published with every domain registered.
TOTAL_TOOL_COUNT = ONE_TO_ONE_TOOL_COUNT + COMPOSITE_TOOL_COUNT

#: Tools whose annotation is ``readOnlyHint=true``.
READ_ONLY_TOOL_COUNT = 74

#: Tools that mutate the appliance; absent when read-only mode is on.
MUTATION_TOOL_COUNT = TOTAL_TOOL_COUNT - READ_ONLY_TOOL_COUNT

#: The five composite tools, named so the surface resource can list them.
COMPOSITE_TOOLS: tuple[str, ...] = (
    "firewall_rule_set_enabled",
    "firewall_rule_clone",
    "audit_firewall_rules",
    "explain_connectivity",
    "find_object_usage",
)

#: Tools that take no arguments and publish an empty ``arguments`` object.
#:
#: ``live_user_list`` belongs here because its request model is deliberately empty: the
#: API declares no parameters for ``/authentication/live-users``. Before 0.7 it published a
#: ``request`` wrapper around that empty model, so it looked like an argument-taking tool;
#: with flat arguments it publishes no properties at all, like the other six.
NO_ARGUMENT_TOOLS: tuple[str, ...] = (
    "dns_settings_get",
    "ipsec_live_connection_list_ipv4",
    "ipsec_remote_access_settings_get",
    "live_user_list",
    "network_status_cellular_wan",
    "network_status_dns_protection",
    "sslvpn_global_settings_get",
)

#: Tools that take arguments: every tool except the no-argument ones.
ARGUMENT_TOOL_COUNT = TOTAL_TOOL_COUNT - len(NO_ARGUMENT_TOOLS)


def _method_count(method: str) -> int:
    """Operations the document declares for one HTTP method."""
    return dict(API_OPERATIONS_BY_METHOD)[method]


class CoverageDomain(NamedTuple):
    """One row of the coverage matrix.

    Attributes:
        title: The domain title used by ``docs/API-COVERAGE.md`` section 5, verbatim, so
            the drift test can match a row to its generated section by title.
        api_operations: Operations the document assigns to the domain.
        tools: Tools this server publishes for the domain.
        access: The access the domain exposes, as published in the README table.
        tool_prefixes: Name prefixes that identify the domain's tools. The prefixes
            partition the published surface: every tool matches exactly one domain.
    """

    title: str
    api_operations: int
    tools: int
    access: str
    tool_prefixes: tuple[str, ...]


#: The coverage matrix, in the canonical domain order of the generated document.
#:
#: ``api_operations`` sums to :data:`API_OPERATIONS` and ``tools`` to
#: :data:`TOTAL_TOOL_COUNT`; both are asserted in ``tests/test_server.py``.
COVERAGE_DOMAINS: tuple[CoverageDomain, ...] = (
    CoverageDomain("Firewall rules", 14, 8, "read + write", ("firewall_rule_",)),
    CoverageDomain("NAT rules", 14, 6, "read + write", ("nat_rule_",)),
    CoverageDomain(
        "Addresses and address groups",
        48,
        27,
        "read + write",
        ("address_", "mac_address_", "country_group_"),
    ),
    CoverageDomain("Services and service groups", 12, 10, "read + write", ("service_",)),
    CoverageDomain(
        "Authentication users, administrators and groups",
        23,
        6,
        "read + write",
        ("network_user_", "user_"),
    ),
    CoverageDomain("Live users", 2, 2, "read + write", ("live_user_",)),
    CoverageDomain("IPsec VPN", 30, 11, "read-only", ("ipsec_",)),
    CoverageDomain("SSL VPN", 26, 9, "read-only", ("sslvpn_",)),
    CoverageDomain(
        "Network",
        113,
        28,
        "read + VLAN-only write",
        (
            "network_interface_",
            "zone_",
            "gateway_",
            "wan_gateway_",
            "custom_gateway_",
            "unicast_route_",
            "sdwan_",
            "dhcp_",
            "dns_",
            "static_neighbor_",
        ),
    ),
    CoverageDomain("Network status", 2, 2, "read-only", ("network_status_",)),
    CoverageDomain("Audit (composite)", 0, 3, "read-only", ("audit_", "explain_", "find_")),
    CoverageDomain("Administration and system", 31, 0, "excluded", ()),
    CoverageDomain("Other catalog", 385, 0, "excluded", ()),
)


def _surface_document() -> str:
    """The REST API surface and the tool mapping, as Markdown."""
    methods = ", ".join(f"{method} {count}" for method, count in API_OPERATIONS_BY_METHOD)
    composites = "\n".join(f"- `{name}`" for name in COMPOSITE_TOOLS)
    return f"""# Sophos Firewall Configuration REST API

This server administers one Sophos Firewall (SFOS 23) appliance through its Configuration
REST API. Every tool wraps one or more audited operations of that API; the server adds no
endpoint of its own.

## Connection

| Fact | Value |
|---|---|
| Base URL | `https://<host>:<port>{API_PATH_PREFIX}` |
| Default port | 4444 (the Web Admin Console port) |
| Authentication | HTTP bearer, one API key created in the Web Admin Console |
| Transport | HTTPS only; MCP over STDIO, diagnostics on stderr |

The base URL is fixed by configuration. No tool argument can name a host, a path, a URL or
a header.

## Inventory

| Fact | Value |
|---|---|
| Paths | {API_PATHS} |
| Operations | {API_OPERATIONS} ({methods}) |
| Component schemas | {API_COMPONENT_SCHEMAS} |
| Operations exposed as tools | {TOOL_MAP_COUNT} |
| One-to-one tools over those operations | {ONE_TO_ONE_TOOL_COUNT} |
| Composite tools over those operations | {COMPOSITE_TOOL_COUNT} |
| Tools published | {TOTAL_TOOL_COUNT} ({READ_ONLY_TOOL_COUNT} read-only, {MUTATION_TOOL_COUNT} mutations) |

## Pagination

{API_PAGINATED_GET_OPERATIONS} GET operations declare `page`, `pageSize` and `pageTotal`. A tool publishes them
as `page`, `page_size` and `page_total`. `page` is 1-based and defaults to 1,
`page_total` defaults to false, and the tool's `page_size` defaults to 10 (the API's own
default is 50). One call returns one page plus the appliance's page metadata; the server
never walks a collection for you.

## Errors

Every documented non-2xx response uses one JSON envelope with `error`, `message` and
`code`. The server maps it to a short message that names the failed operation and the HTTP
status; the API key never appears in it.

## Updates

{_method_count("PATCH")} PATCH operations accept `application/json` with JSON Merge Patch semantics: an
omitted property keeps its stored value and an explicit `null` removes an optional
property.

## Tool mapping

One tool per concept, named `<resource>_<verb>`: for example `firewall_rule_list`,
`nat_rule_get`, `address_create_fqdn`. The IPv4 and IPv6 families share one tool and the
required `ip_family` argument (`ipv4` or `ipv6`) selects the collection, so the family is
never inferred. The wire body is unchanged for each family.

Five composite tools compose audited operations and add no endpoint:

{composites}

Read `sophos://coverage` for the per-domain matrix, `sophos://conventions` for the calling
conventions and `sophos://read-only-policy` for what the server does and does not do.
"""


def _coverage_document() -> str:
    """The per-domain coverage matrix, as Markdown."""
    rows = "\n".join(
        f"| {domain.title} | {domain.api_operations} | {domain.tools} | {domain.access} |"
        for domain in COVERAGE_DOMAINS
    )
    api_total = sum(domain.api_operations for domain in COVERAGE_DOMAINS)
    tool_total = sum(domain.tools for domain in COVERAGE_DOMAINS)
    return f"""# Coverage matrix

{api_total} operations across {API_PATHS} paths, published as {tool_total} tools: {ONE_TO_ONE_TOOL_COUNT} tools map one-to-one
to an audited operation (the IPv4/IPv6 pairs share one tool each) and {COMPOSITE_TOOL_COUNT} are composites over those same operations.

| Domain | API operations | Tools | Access |
|---|---:|---:|---|
{rows}
| **Total** | **{api_total}** | **{tool_total}** | {READ_ONLY_TOOL_COUNT} read-only, {MUTATION_TOOL_COUNT} mutations |

## What is not exposed

Bulk deletes, administrator CRUD, user groups, network-user login and logout, every VPN
mutation, WAF rules, IPS, and the mutation families outside the VLAN-only interface writes
(zones, gateways, routes, SD-WAN, DHCP, DNS, neighbors, router advertisements, multicast,
mDNS, country groups).

The per-operation inventory, with the reason recorded for every exclusion, is
`docs/API-COVERAGE.md` in the source repository. It is generated from the checked-in
OpenAPI document and is not shipped in the wheel, which is why this summary is embedded.
"""


def _read_only_document(*, read_only: bool) -> str:
    """What the server does and does not do, as Markdown."""
    mode = "enabled" if read_only else "disabled"
    if read_only:
        mutation_sentence = (
            f"Read-only mode is **{mode}** in this process: the {MUTATION_TOOL_COUNT} mutation tools are\n"
            "not registered at all. They are absent from `tools/list`, not hidden behind a\n"
            "runtime check, so a call cannot reach them."
        )
    else:
        mutation_sentence = (
            f"Read-only mode is **{mode}** in this process: all {TOTAL_TOOL_COUNT} tools are registered,\n"
            f"including the {MUTATION_TOOL_COUNT} mutations. Set `SOPHOS_READ_ONLY_MODE=true` to publish\n"
            f"only the {READ_ONLY_TOOL_COUNT} read-only tools."
        )
    return f"""# Read-only policy

## What this server does

- Administers exactly one Sophos Firewall appliance through its Configuration REST API.
- Publishes narrow, typed tools: list, get, create, update, move and delete for firewall
  and NAT rules, address and service objects, users and live sessions, plus read-only
  network, VPN and status tools.
- Annotates every tool: a read-only tool carries `readOnlyHint=true`; a mutation carries
  `readOnlyHint=false` plus `destructiveHint` and `idempotentHint` where they apply.
- Reads one page per call and returns the appliance's page metadata instead of walking a
  collection.

## What this server does not do

- No shell, no file access and no arbitrary HTTP. A tool argument can never name a host, a
  path, a URL or a header; the base URL comes from configuration only.
- No packet test. The API exposes no ping, traceroute, packet capture or live flow
  simulation, so `explain_connectivity` analyses configuration and says so.
- No bulk delete, no administrator CRUD, no user-group CRUD, no network-user login or
  logout, no VPN mutation, no WAF rule and no IPS change.
- No interface write other than a VLAN: `network_interface_create_vlan`,
  `network_interface_update_vlan` and `network_interface_delete_vlan` read the interface
  first and refuse any type other than `vlan`.
- No secret exposure. The API key is a `SecretStr`; it is placed in the `Authorization`
  header only, and is never logged, echoed in tool output or included in an error message.

## Read-only mode

{mutation_sentence}

The mode is resolved from `SOPHOS_READ_ONLY_MODE` before any tool is registered, so the
tool set is fixed for the process lifetime. It is defense in depth on top of a Sophos
administrator profile with `Read-only` permissions, not a substitute for one: the API key's
profile is what actually authorizes a request.
"""


def _conventions_document() -> str:
    """The calling conventions, as Markdown."""
    no_argument = "\n".join(f"- `{name}`" for name in NO_ARGUMENT_TOOLS)
    return f"""# Calling conventions

## Flat arguments

Every tool that takes arguments publishes those arguments at the top level of `arguments`,
exactly as the MCP specification's own examples do. There is no wrapper object to unwrap:
the fields the tool's `inputSchema` lists are the fields the call sends.

```json
{{"name": "firewall_rule_list",
 "arguments": {{"ip_family": "ipv4", "page": 1, "page_size": 10, "page_total": true}}}}
```

{ARGUMENT_TOOL_COUNT} of the {TOTAL_TOOL_COUNT} tools take arguments. The other {len(NO_ARGUMENT_TOOLS)} take an empty `arguments` object
because they declare no parameters:

{no_argument}

A tool whose request is a union of shapes (`address_create`, `firewall_rule_create`,
`nat_rule_create` and the other create/update tools that exist for both IP families)
publishes a root `oneOf` instead of one flat object, because each variant has its own
required fields; `mac_address_create` publishes `anyOf` because the API declares no
discriminator for it. Send the variant's own fields at the top level and let its
discriminator (`ip_family` or `type`) select it.

The rejection is actionable and names the accepted arguments, so a model can self-correct
on the next call:

```
invalid arguments: bogus is not an accepted argument; accepted arguments are ip_family, id_or_name
```

## Names

Input names are snake_case (`page_size`, `name_contains`, `id_or_name`, `rule_type`,
`reference_item`, `ip_family`). Output names are the appliance's camelCase (`pageSize`,
`nameContains`, `idOrName`).

## The IP family

A tool that exists for both IP families publishes one required `ip_family` argument
(`ipv4` or `ipv6`) instead of two tools. It is required, not defaulted: a default would
silently target one family, and for a mutation (delete, update, move, enable/disable,
clone) that would make a destructive target a guess. The audit composites are the one
exception: they are read-only and can span both families, so their `ip_family` is optional
and omitting it means both.

## One page per call

A paginated list publishes `page`, `page_size` and `page_total` as top-level arguments. `page` is
1-based, `page_size` defaults to 10 and is capped at 100, and `page_total=true` adds
`pages.total` and `pages.items` to the result. There is no cursor: call the next page
explicitly when you need it.

## Read one of `content` / `structuredContent`

Every successful result carries the payload twice: a pretty-printed JSON text block in
`content` and the same object in `structuredContent`. Read `structuredContent` when the
client supports it and fall back to `content` otherwise; never parse both, because a single
list page is 28-70 KB.

## Errors

A failed call returns `isError: true` with a short, sanitized message that names the failed
operation, and the HTTP status when there is one. For example, a transport failure:

```
the firewall could not be reached or did not answer in time; retry the read [GET /network/dns/settings]
```

and an error the appliance answered with:

```
the firewall rejected the request as invalid; check the field values (HTTP 400) [POST /firewall/rules/ipv4]
```

An unknown argument is rejected before the handler runs, with the field path and the rule
that failed. A 401 means the API key is the problem, not the administrator profile.
"""


def register_resources(server: MCPServer[AppContext], *, read_only: bool) -> None:
    """Register the server's resources on ``server``.

    Args:
        server: The server being built. Registration happens before the lifespan starts,
            so every resource is a constant for the process lifetime.
        read_only: The resolved read-only mode. It is only used by
            ``sophos://read-only-policy``, which states the mode this process runs in.
    """

    @server.resource(
        "sophos://api/surface",
        name="api-surface",
        title="Sophos Firewall REST API surface",
        description=(
            "The Configuration REST API this server wraps: base URL, authentication, the "
            "operation inventory, pagination, errors, update semantics and the tool mapping."
        ),
        mime_type="text/markdown",
    )
    def api_surface() -> str:
        """The REST API surface and the tool mapping."""
        return _surface_document()

    @server.resource(
        "sophos://coverage",
        name="coverage-matrix",
        title="Coverage matrix",
        description=(
            "Per-domain coverage: API operations, tools published and access, plus what the "
            "server deliberately does not expose."
        ),
        mime_type="text/markdown",
    )
    def coverage() -> str:
        """The per-domain coverage matrix."""
        return _coverage_document()

    @server.resource(
        "sophos://read-only-policy",
        name="read-only-policy",
        title="Read-only policy",
        description=(
            "What the server does and does not do, and what read-only mode changes in this "
            "process."
        ),
        mime_type="text/markdown",
    )
    def read_only_policy() -> str:
        """The read-only policy and the mode this process runs in."""
        return _read_only_document(read_only=read_only)

    @server.resource(
        "sophos://conventions",
        name="calling-conventions",
        title="Calling conventions",
        description=(
            "How to call a tool: flat arguments, input and output naming, pagination, "
            "reading one of content/structuredContent, and error semantics."
        ),
        mime_type="text/markdown",
    )
    def conventions() -> str:
        """The calling conventions."""
        return _conventions_document()
