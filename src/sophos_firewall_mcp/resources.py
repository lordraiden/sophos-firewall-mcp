"""MCP resources: the passive context a client reads instead of calling a tool.

The MCP specification splits a server's surface into three primitives: tools are
model-controlled actions, resources are application-controlled passive context, and
prompts are user-controlled templates. This server's tools are narrow and typed, so the
context a model needs *before* it calls them -- the REST API surface, the coverage matrix,
the read-only policy and the calling conventions -- is published here once instead of
being repeated in 112 tool descriptions.

Every resource is a constant for the process lifetime, but not a constant of the codebase:
each document is built from the :class:`SurfaceSummary` the server factory reads back from
the live tool registry, so a process that enables only some domains describes the tools it
actually publishes. The catalog totals stay in the documents as the *full supported
catalog*, explicitly distinguished from the subset this process enabled, because an
operator comparing two deployments needs both numbers.

The coverage matrix is a summary of ``docs/API-COVERAGE.md``, which is generated from the
checked-in OpenAPI document. That document is not shipped in the wheel, so the summary is
embedded here and ``tests/test_server.py`` compares it against the document: a
regeneration that changes a count fails the test instead of leaving a stale resource.

Nothing here touches the network or the appliance: a resource is a string built from
module-level constants and the surface summary.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, NamedTuple

from sophos_firewall_mcp.config import API_PATH_PREFIX, TOOL_DOMAINS

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
    "SurfaceSummary",
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


def _join(names: tuple[str, ...]) -> str:
    """Join names as ``a, b and c``; ``none`` for an empty selection."""
    if not names:
        return "none"
    if len(names) == 1:
        return names[0]
    return f"{', '.join(names[:-1])} and {names[-1]}"


class SurfaceSummary(NamedTuple):
    """The tool surface this process actually registered.

    The resources and the server instructions describe *this*, not the catalog: a filtered
    instance must never claim a tool it did not register. The server factory builds it from
    the live tool registry after every selected domain has registered, so the counts and the
    names cannot drift from ``tools/list``.

    Attributes:
        domains: The domain identifiers this process enabled, in canonical order. Empty when
            the server was built from an explicit registrar list that names no known domain
            (the synthetic registrars the tests use).
        tool_names: Every registered tool name, in registration order.
        read_only_tool_names: The registered names whose annotation is ``readOnlyHint=true``.
    """

    domains: tuple[str, ...]
    tool_names: tuple[str, ...]
    read_only_tool_names: tuple[str, ...]

    @property
    def tool_count(self) -> int:
        """Tools registered in this process."""
        return len(self.tool_names)

    @property
    def read_only_tool_count(self) -> int:
        """Registered tools that only read from the appliance."""
        return len(self.read_only_tool_names)

    @property
    def mutation_tool_count(self) -> int:
        """Registered tools that mutate the appliance; zero in read-only mode."""
        return self.tool_count - self.read_only_tool_count

    @property
    def is_full(self) -> bool:
        """Whether every domain is enabled, so the surface is the complete catalog."""
        return self.domains == TOOL_DOMAINS

    @property
    def disabled_domains(self) -> tuple[str, ...]:
        """The domains this process does not enable, in canonical order."""
        return tuple(name for name in TOOL_DOMAINS if name not in self.domains)

    def enabled_summary(self) -> str:
        """One sentence naming the enabled domains and the counts they publish.

        It never claims the complete catalog unless every domain is enabled, and it names the
        excluded domains explicitly so a reader knows their tools are absent rather than
        merely undocumented.
        """
        if self.is_full:
            return (
                f"All {len(TOOL_DOMAINS)} domains are enabled ({_join(TOOL_DOMAINS)}): "
                f"{self.tool_count} tools ({self.read_only_tool_count} read-only, "
                f"{self.mutation_tool_count} mutations)."
            )
        disabled = self.disabled_domains
        return (
            f"This process enables {len(self.domains)} of the {len(TOOL_DOMAINS)} domains "
            f"({_join(self.domains)}): {self.tool_count} of the {TOTAL_TOOL_COUNT} catalog "
            f"tools ({self.read_only_tool_count} read-only, {self.mutation_tool_count} "
            f"mutations). The {_join(disabled)} "
            f"{'domain is' if len(disabled) == 1 else 'domains are'} not enabled, so those "
            "tools are not registered."
        )


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
        domain: The ``SOPHOS_TOOL_DOMAINS`` identifier this row belongs to, or ``None`` for
            a row that publishes no tool at all (the excluded families). The coverage
            resource marks the rows of a domain this process did not enable.
    """

    title: str
    api_operations: int
    tools: int
    access: str
    tool_prefixes: tuple[str, ...]
    domain: str | None = None


#: The coverage matrix, in the canonical domain order of the generated document.
#:
#: ``api_operations`` sums to :data:`API_OPERATIONS` and ``tools`` to
#: :data:`TOTAL_TOOL_COUNT`; both are asserted in ``tests/test_server.py``.
COVERAGE_DOMAINS: tuple[CoverageDomain, ...] = (
    CoverageDomain("Firewall rules", 14, 8, "read + write", ("firewall_rule_",), "firewall"),
    CoverageDomain("NAT rules", 14, 6, "read + write", ("nat_rule_",), "nat"),
    CoverageDomain(
        "Addresses and address groups",
        48,
        27,
        "read + write",
        ("address_", "mac_address_", "country_group_"),
        "objects",
    ),
    CoverageDomain("Services and service groups", 12, 10, "read + write", ("service_",), "objects"),
    CoverageDomain(
        "Authentication users, administrators and groups",
        23,
        6,
        "read + write",
        ("network_user_", "user_"),
        "users",
    ),
    CoverageDomain("Live users", 2, 2, "read + write", ("live_user_",), "users"),
    CoverageDomain("IPsec VPN", 30, 11, "read-only", ("ipsec_",), "network"),
    CoverageDomain("SSL VPN", 26, 9, "read-only", ("sslvpn_",), "network"),
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
        "network",
    ),
    CoverageDomain("Network status", 2, 2, "read-only", ("network_status_",), "network"),
    CoverageDomain(
        "Audit (composite)", 0, 3, "read-only", ("audit_", "explain_", "find_"), "audit"
    ),
    CoverageDomain("Administration and system", 31, 0, "excluded", ()),
    CoverageDomain("Other catalog", 385, 0, "excluded", ()),
)


def _surface_document(surface: SurfaceSummary) -> str:
    """The REST API surface and the tool mapping, as Markdown."""
    methods = ", ".join(f"{method} {count}" for method, count in API_OPERATIONS_BY_METHOD)
    composites = tuple(name for name in COMPOSITE_TOOLS if name in surface.tool_names)
    if composites:
        composite_block = (
            f"{len(composites)} composite tools compose audited operations and add no endpoint:\n\n"
            + "\n".join(f"- `{name}`" for name in composites)
        )
    else:
        composite_block = "No composite tool is registered in this process."
    naming_examples = tuple(
        name
        for name in ("firewall_rule_list", "nat_rule_get", "address_create_fqdn")
        if name in surface.tool_names
    )
    naming = (
        ": for example " + ", ".join(f"`{name}`" for name in naming_examples)
        if naming_examples
        else ""
    )
    domains_cell = (
        f"{_join(TOOL_DOMAINS)} (all {len(TOOL_DOMAINS)})"
        if surface.is_full
        else f"{_join(surface.domains)} ({len(surface.domains)} of {len(TOOL_DOMAINS)})"
    )
    return f"""# Sophos Firewall Configuration REST API

This server administers one Sophos Firewall (SFOS 23) appliance through its Configuration
REST API. Every tool wraps one or more audited operations of that API; the server adds no
endpoint of its own.

## Connection

Base URL `https://<host>:<port>{API_PATH_PREFIX}`, default port 4444 (the Web Admin Console
port), HTTP bearer with one API key, HTTPS only, MCP over STDIO with diagnostics on stderr.
The base URL is fixed by configuration: no tool argument can name a host, a path, a URL or a
header.

## Inventory

| Fact | Value |
|---|---|
| Paths | {API_PATHS} |
| Operations | {API_OPERATIONS} ({methods}) |
| Component schemas | {API_COMPONENT_SCHEMAS} |
| Operations exposed as tools | {TOOL_MAP_COUNT} |
| One-to-one tools over those operations | {ONE_TO_ONE_TOOL_COUNT} |
| Composite tools over those operations | {COMPOSITE_TOOL_COUNT} |
| Domains enabled in this process | {domains_cell} |
| Tools registered in this process | {surface.tool_count} ({surface.read_only_tool_count} read-only, {surface.mutation_tool_count} mutations) |

The last two rows describe this process; the rest describe the catalog it supports.

## Pagination

{API_PAGINATED_GET_OPERATIONS} GET operations declare `page`, `pageSize` and `pageTotal`; a tool publishes them as
`page`, `page_size` and `page_total`. `page` is 1-based, `page_size` defaults to 10 (the
API's own default is 50) and `page_total` defaults to false. One call returns one page plus
the appliance's page metadata; the server never walks a collection for you.

## Errors

Every documented non-2xx response uses one JSON envelope with `error`, `message` and
`code`. The server maps it to a short message that names the failed operation and the HTTP
status; the API key never appears in it.

## Updates

{_method_count("PATCH")} PATCH operations accept `application/json` with JSON Merge Patch semantics: an
omitted property keeps its stored value and an explicit `null` removes an optional
property.

## Tool mapping

One tool per concept, named `<resource>_<verb>`{naming}. The IPv4 and IPv6 families share one tool and the
required `ip_family` argument (`ipv4` or `ipv6`) selects the collection, so the family is
never inferred. The wire body is unchanged for each family.

{composite_block}

Read `sophos://coverage` for the per-domain matrix, `sophos://conventions` for the calling
conventions and `sophos://read-only-policy` for what the server does and does not do.
"""


def _coverage_document(surface: SurfaceSummary) -> str:
    """The per-domain coverage matrix, as Markdown."""
    rows = "\n".join(
        f"| {domain.title} | {domain.api_operations} | {_tools_cell(domain, surface)} "
        f"| {domain.access} |"
        for domain in COVERAGE_DOMAINS
    )
    api_total = sum(domain.api_operations for domain in COVERAGE_DOMAINS)
    tool_total = sum(domain.tools for domain in COVERAGE_DOMAINS)
    return f"""# Coverage matrix

The full supported catalog: {api_total} operations across {API_PATHS} paths, published as {tool_total} tools: {ONE_TO_ONE_TOOL_COUNT} tools map one-to-one
to an audited operation (the IPv4/IPv6 pairs share one tool each) and {COMPOSITE_TOOL_COUNT} are composites over those same operations.

## Enabled in this process

{surface.enabled_summary()}

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


def _tools_cell(domain: CoverageDomain, surface: SurfaceSummary) -> str:
    """The Tools cell of one coverage row, marked when the row's domain is not enabled."""
    if domain.domain is None or domain.domain in surface.domains:
        return str(domain.tools)
    return f"{domain.tools} (not enabled)"


def _read_only_document(surface: SurfaceSummary, *, read_only: bool) -> str:
    """What the server does and does not do, as Markdown."""
    mode = "enabled" if read_only else "disabled"
    if read_only:
        # The registry holds no mutation in this mode, so its count is zero and cannot say
        # what read-only mode removed. The catalog constant is correct when every domain is
        # enabled; a filtered instance names the domains instead of inventing a number.
        removed = (
            f"the {MUTATION_TOOL_COUNT} mutation tools are"
            if surface.is_full
            else "the mutation tools of the enabled domains are"
        )
        mutation_sentence = (
            f"Read-only mode is **{mode}** in this process: {removed}\nnot registered at all. "
            "They are absent from `tools/list`, not hidden behind a\nruntime check, so a call "
            "cannot reach them."
        )
    else:
        mutation_sentence = (
            f"Read-only mode is **{mode}** in this process: all {surface.tool_count} tools are "
            "registered,\nincluding the "
            f"{surface.mutation_tool_count} mutations. Set `SOPHOS_READ_ONLY_MODE=true` to "
            f"publish\nonly the {surface.read_only_tool_count} read-only tools."
        )
    if surface.is_full:
        domains_sentence = f"All {len(TOOL_DOMAINS)} domains are enabled ({_join(TOOL_DOMAINS)})."
    else:
        disabled = surface.disabled_domains
        domains_sentence = (
            f"This process enables {len(surface.domains)} of the {len(TOOL_DOMAINS)} domains "
            f"({_join(surface.domains)}); the {_join(disabled)} "
            f"{'domain is' if len(disabled) == 1 else 'domains are'} not registered."
        )
    vlan_tools = tuple(
        name
        for name in (
            "network_interface_create_vlan",
            "network_interface_update_vlan",
            "network_interface_delete_vlan",
        )
        if name in surface.tool_names
    )
    if vlan_tools:
        vlan_sentence = (
            "- No interface write other than a VLAN: "
            + ", ".join(f"`{name}`" for name in vlan_tools)
            + " read the interface\n  first and refuse any type other than `vlan`.\n"
        )
    else:
        vlan_sentence = ""
    if "explain_connectivity" in surface.tool_names:
        packet_sentence = (
            "- No packet test. The API exposes no ping, traceroute, packet capture or live flow\n"
            "  simulation, so `explain_connectivity` analyses configuration and says so.\n"
        )
    else:
        packet_sentence = (
            "- No packet test. The API exposes no ping, traceroute, packet capture or live flow\n"
            "  simulation.\n"
        )
    return f"""# Read-only policy

## What this server does

- Administers exactly one Sophos Firewall appliance through its Configuration REST API.
- Publishes narrow, typed tools for the enabled domains: list, get, create, update, move and
  delete for firewall and NAT rules, address and service objects, users and live sessions,
  plus read-only network, VPN and status tools.
- Annotates every tool: a read-only tool carries `readOnlyHint=true`; a mutation carries
  `readOnlyHint=false` plus `destructiveHint` and `idempotentHint` where they apply.
- Reads one page per call and returns the appliance's page metadata instead of walking a
  collection.

## What this server does not do

- No shell, no file access and no arbitrary HTTP. A tool argument can never name a host, a
  path, a URL or a header; the base URL comes from configuration only.
{packet_sentence}- No bulk delete, no administrator CRUD, no user-group CRUD, no network-user login or
  logout, no VPN mutation, no WAF rule and no IPS change.
{vlan_sentence}- No secret exposure. The API key is a `SecretStr`; it is placed in the `Authorization`
  header only, and is never logged, echoed in tool output or included in an error message.

## Read-only mode

{mutation_sentence}

{domains_sentence}

The mode is resolved from `SOPHOS_READ_ONLY_MODE` before any tool is registered, so the
tool set is fixed for the process lifetime. It is defense in depth on top of a Sophos
administrator profile with `Read-only` permissions, not a substitute for one: the API key's
profile is what actually authorizes a request.
"""


def _conventions_document(surface: SurfaceSummary) -> str:
    """The calling conventions, as Markdown."""
    no_argument = tuple(name for name in NO_ARGUMENT_TOOLS if name in surface.tool_names)
    if no_argument:
        no_argument_block = "\n".join(f"- `{name}`" for name in no_argument)
        other = len(no_argument)
        if other == 1:
            argument_sentence = (
                f"{surface.tool_count - 1} of the {surface.tool_count} tools take arguments. "
                "The other 1 takes an empty `arguments` object because it declares no "
                "parameters:"
            )
        else:
            argument_sentence = (
                f"{surface.tool_count - other} of the {surface.tool_count} tools take "
                f"arguments. The other {other} take an empty `arguments` object because they "
                "declare no parameters:"
            )
    else:
        no_argument_block = ""
        argument_sentence = f"All {surface.tool_count} tools take arguments."
    example_tool = next(
        (
            name
            for name in ("firewall_rule_list", "nat_rule_list", "address_list")
            if name in surface.tool_names
        ),
        None,
    )
    if example_tool is None:
        example_block = ""
    else:
        example_block = (
            "\n```json\n"
            f'{{"name": "{example_tool}",\n'
            ' "arguments": {"ip_family": "ipv4", "page": 1, "page_size": 10, '
            '"page_total": true}}\n'
            "```\n"
        )
    union_tools = tuple(
        name
        for name in ("address_create", "firewall_rule_create", "nat_rule_create")
        if name in surface.tool_names
    )
    any_of = "mac_address_create" in surface.tool_names
    if union_tools:
        union_sentence = (
            "A tool whose request is a union of shapes ("
            + ", ".join(f"`{name}`" for name in union_tools)
            + " and the other create/update tools that exist for both IP families) publishes a "
            "root `oneOf` instead of one flat object, because each variant has its own required "
            "fields"
        )
        if any_of:
            union_sentence += (
                "; `mac_address_create` publishes `anyOf` because the API declares no "
                "discriminator for it"
            )
        union_sentence += (
            ". Send the variant's own fields at the top level and let its discriminator "
            "(`ip_family` or `type`) select it.\n"
        )
    elif any_of:
        union_sentence = (
            "`mac_address_create` publishes a root `anyOf` because the API declares no "
            "discriminator for it; send the variant's own fields at the top level.\n"
        )
    else:
        union_sentence = ""
    return f"""# Calling conventions

## Flat arguments

Every tool that takes arguments publishes those arguments at the top level of `arguments`,
exactly as the MCP specification's own examples do. There is no wrapper object to unwrap:
the fields the tool's `inputSchema` lists are the fields the call sends.
{example_block}
{argument_sentence}

{no_argument_block}

{union_sentence}
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

A paginated list publishes `page`, `page_size` and `page_total`. `page` is 1-based,
`page_size` defaults to 10 and is capped at 100, and `page_total=true` adds `pages.total`
and `pages.items`. There is no cursor: call the next page explicitly.

## Read one of `content` / `structuredContent`

Every successful result carries the payload twice: a JSON text block in `content` and
the same object in `structuredContent`. Read `structuredContent` when the client supports
it, else `content`; never parse both.

## Catalog size and discovery

`tools/list` is one page of 112 tools (~494KB) with no `nextCursor`; call it once per
session and prefer progressive discovery.

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


def register_resources(
    server: MCPServer[AppContext], *, read_only: bool, surface: SurfaceSummary
) -> None:
    """Register the server's resources on ``server``.

    Args:
        server: The server being built. Registration happens before the lifespan starts,
            so every resource is a constant for the process lifetime.
        read_only: The resolved read-only mode. It is only used by
            ``sophos://read-only-policy``, which states the mode this process runs in.
        surface: The tool surface this process registered. Every document is built from it,
            so a filtered instance describes the tools it publishes instead of the catalog.
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
        return _surface_document(surface)

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
        return _coverage_document(surface)

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
        return _read_only_document(surface, read_only=read_only)

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
        return _conventions_document(surface)
