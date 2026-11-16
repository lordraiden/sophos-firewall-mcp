# Sophos Firewall 23 MCP Server (SFOS 23.0 REST API)

[![SFOS 23](https://img.shields.io/badge/SFOS-23.0%20REST%20API-informational.svg)](#supported-appliance-and-api)
[![Container image](https://img.shields.io/badge/ghcr.io-lordraiden%2Fsophos--firewall--mcp-blue.svg)](https://github.com/lordraiden/sophos-firewall-mcp/pkgs/container/sophos-firewall-mcp)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python Version](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue.svg)](pyproject.toml)
[![MCP protocol](https://img.shields.io/badge/MCP-2026--07--28-informational.svg)](https://modelcontextprotocol.io/)

A local **MCP server** for **Sophos Firewall 23**, built on the
[Model Context Protocol](https://modelcontextprotocol.io/): it administers a **Sophos Firewall 23
(SFOS 23.0)** appliance through the **Sophos Firewall Configuration REST API**, over **STDIO**. It is
built for **firewall automation** and for **AI agents** — Claude Desktop, Cursor, VS Code, Antigravity
IDE and any other MCP client — that need typed, bounded access to a firewall's configuration instead of
a raw HTTP surface.

It is not the Sophos Central Firewall Management API: the only backend is
`https://<SOPHOS_HOST>:<SOPHOS_PORT>/api/firewall-config/v1` on the appliance itself, authenticated with a
Bearer API key.

> **0.7.1 is the current release.** It is a patch release that closes the High finding and the cheap
> findings of the [0.7.0 MCP standards review](docs/architecture/sophos-rest-api-redesign/MCP-STANDARDS-REVIEW-0.7.md):
> the four gated delete descriptions now state that the confirmation is **best-effort** (it fires on
> the legacy handshake path and is skipped, with a logged warning, on the `2026-07-28` path), and
> `nat_rule_create` now requires `position`, which the appliance already rejected a create without.
> No tool is renamed and no argument is removed. **0.7.0 remains the breaking release:** the 40
> IPv4/IPv6 tool pairs collapse into one tool per concept behind a **required `ip_family`** argument,
> and tool arguments are published **flat** instead of inside a `request` wrapper. The surface is 112
> tools. The
> [migration table](docs/architecture/sophos-rest-api-redesign/MIGRATION-0.7.md) maps every removed
> tool name to its replacement. 0.6.0 unified the published *output* field names on camelCase (the
> Sophos wire names); 0.5.0 unified every published *input* parameter on snake_case; 0.4.0 was the
> breaking, REST-only migration: the XML transport, the XML credentials, the raw XML tool, the
> semantic router and FastEmbed are gone, with no compatibility mode. See
> [`CHANGELOG.md`](CHANGELOG.md), the [0.7.1 release notes](docs/release/RELEASE-0.7.1.md), the
> [0.7.0 release notes](docs/release/RELEASE-0.7.0.md), the
> [0.6.0 release notes](docs/release/RELEASE-0.6.0.md), the
> [0.5.0 release notes](docs/release/RELEASE-0.5.0.md) and the
> [0.4.0 release notes](docs/release/RELEASE-0.4.0.md).

---

## Contents

- [What it does](#what-it-does)
- [Supported appliance and API](#supported-appliance-and-api)
- [Requirements](#requirements)
- [Sophos Firewall prerequisites](#sophos-firewall-prerequisites)
- [Tool surface](#tool-surface)
- [Calling the tools](#calling-the-tools)
- [Context cost](#context-cost)
- [Configuration](#configuration)
- [Install and run](#install-and-run)
- [MCP client configuration](#mcp-client-configuration)
- [Container usage](#container-usage)
- [Read-only mode](#read-only-mode)
- [Domain selection](#domain-selection)
- [Security model](#security-model)
- [Known limitations and accepted regressions](#known-limitations-and-accepted-regressions)
- [Development](#development)
- [Documentation](#documentation)
- [License](#license)

---

## What it does

- **112 typed tools across 11 domains** (the complete catalog; `SOPHOS_TOOL_DOMAINS` publishes a
  subset), covering 145 audited operations of the checked-in OpenAPI
  contract (`firewall_config_openapi.yaml`, 700 operations) plus 5 composite tools that add no new
  endpoint. The IPv4 and IPv6 families share one tool each, selected by a required `ip_family`
  argument. Every tool maps to a documented `operationId`; the mapping is in
  [`docs/API-COVERAGE.md`](docs/API-COVERAGE.md).
- **One shared async REST client** (`httpx.AsyncClient`) created in the MCP lifespan and closed exactly
  once on shutdown. No client is created per tool call.
- **Typed, bounded inputs and outputs.** Outputs are Pydantic DTOs with an object root, never raw Sophos
  payloads. Listings return **one page per call** (`page`, `pageSize`, `pageTotal` where the contract
  declares them); the server never auto-paginates or returns an entire configuration.
- **No raw REST tool.** No tool accepts a URL, path, header, HTTP method or arbitrary JSON payload, so a
  model cannot reach an operation that is not in the audited surface.
- **STDIO only.** No HTTP listener, no OAuth, no multi-user mode. Logs go to `stderr`; `stdout` carries
  the MCP protocol only.
- **Read-only mode** that refuses to register mutation tools at all.

## Supported appliance and API

This server implements the **Sophos Firewall 23 (SFOS 23.0) Configuration REST API**. It is not a
wrapper around the legacy XML API, the Sophos Central API or a vendor SDK: every tool is a typed
projection of one audited operation of the SFOS 23 REST contract.

| Item | Value |
|---|---|
| Appliance | **Sophos Firewall 23** (SFOS 23.0), model **SFVH** (virtual appliance) |
| Tested firmware build | **SFOS 23.0.0 GA-Build371** — the build every live-evidence record in this repository was produced against |
| API | Sophos Firewall **Configuration REST API v1**, base path `/api/firewall-config/v1` |
| Transport | HTTPS to the appliance Web Admin Console port (SFOS default `4444`), Bearer API key |
| MCP transport | STDIO only |
| Not supported | Sophos Central Firewall Management API; the legacy XML API (`/webconsole/APIController`) that 0.3.x used |

**Compatibility scope.** The Configuration REST API is the same across SFOS versions (the contract is
version-independent; the API exposes no version endpoint), so the tools are not tied to a build. The
live evidence in [`docs/live-evidence/`](docs/live-evidence/) records what was exercised on
**SFOS 23.0.0 GA-Build371**; verify the behaviour you depend on against your own appliance before
relying on a tool. The [known limitations](#known-limitations-and-accepted-regressions) list what was
and was not exercised.

## Requirements

| Item | Requirement |
|---|---|
| Python | `>=3.11` (3.11, 3.12, 3.13 and 3.14 are supported) |
| MCP SDK | `mcp==2.3.0` (exact pin; see [SDK compatibility](docs/SDK-COMPATIBILITY.md)) |
| Network | HTTPS reachability to the appliance Web Admin Console port (SFOS default `4444`) |
| Credential | A Sophos Firewall **API key** (Bearer token) |
| TLS | A certificate the client can verify, or a PEM CA bundle via `SOPHOS_CA_BUNDLE` |

## Sophos Firewall prerequisites

All four controls below are separate and all are required. Configure them in the Web Admin Console
(`https://<SOPHOS_HOST>:4444`) before starting the server.

1. **API access enabled.** Under **Administration > API access** (API configuration), enable the API.
   The Configuration REST API is served from `/api/firewall-config/v1`.
2. **Allowed IP hosts.** Add the source IP address of the machine or container that runs this server.
   Sophos rejects requests from any address that is not listed, and the allowlist accepts **at most 64
   entries**.
3. **Device access.** Under **Administration > Device access**, HTTPS / Web Admin Console must be
   enabled for the administrator's source zone. From the WAN zone the only documented mechanism is a
   Local service ACL exception rule scoped to specific source IPs — never `Any` / `0.0.0.0`.
4. **A dedicated, least-privilege administrator.** The API key inherits the permissions of the
   administrator that generated it. Create a dedicated administrator with only the per-feature
   permissions you need (`None`, `Read-only` or `Read-write`), and generate the key from that account.
   Do not use the default full-privilege administrator.

**Key lifecycle (manual, no auto-renewal).** The key is displayed **once** at creation. Sophos documents
**10 keys per administrator**, **1,024 keys per appliance** and a **one-year validity**. Rotation and
revocation are manual: create the replacement, deploy it, then revoke the old key. All administrators can
view the API key list, and the default administrator can delete any administrator's keys — so never share
one key across automations.

> The MCP tool surface is **not** an authorization boundary. Tool annotations (`readOnlyHint`,
> `destructiveHint`, `idempotentHint`, `openWorldHint`) are advisory metadata for the client; effective
> authorization comes from the Sophos administrator profile, the API allowlist and your host-side
> approval policy.

## Tool surface

112 tools, 11 domains: **74 read-only and 38 mutations**, of which **7 take no arguments** and 105
take arguments. The Access column shows whether a domain exposes mutation tools; with
`SOPHOS_READ_ONLY_MODE=true` the server registers **74 tools and 0 mutations**.

This is the complete catalog. A deployment that needs only some of it sets `SOPHOS_TOOL_DOMAINS` to
publish just those domains — see [Domain selection](#domain-selection).

The server publishes its identity in `serverInfo`: `name`, `title`, `version`, `websiteUrl` and a
`description` taken verbatim from the installed package metadata. The description names the product
and the API, never a tool count, so it stays true for the complete surface, a read-only deployment
and a domain-filtered one; the counts live in `tools/list` and in the resources, where they can be
computed per instance.

| Domain | Tools | Access | Coverage |
|---|---:|---|---|
| Firewall rules (IPv4/IPv6) | 8 | read + write | List, get, create, update, delete and move, plus `firewall_rule_set_enabled` (PATCH `enabled`) and `firewall_rule_clone` (get + create). The required `ip_family` selects the IPv4 or IPv6 rule base. A created rule is never auto-enabled or repositioned. |
| NAT rules (IPv4/IPv6) | 6 | read + write | List, get, create, update, delete and move; `ip_family` selects the rule base. A create requires `position` (`top`, `bottom`, `after` or `before`), because the appliance rejects a create without it. |
| Addresses and address groups | 27 | read + write | IPv4/IPv6 addresses and groups (one tool each, `ip_family` selects the collection), FQDN addresses and groups (full CRUD), MAC addresses (full CRUD), country groups (read-only). |
| Services and service groups | 10 | read + write | List, get, create, update, delete. |
| Network users | 6 | read + write | General user list and network-user CRUD. Passwords are write-only and never returned or logged. |
| Live users | 2 | read + write | List active sessions and disconnect one session. |
| IPsec VPN | 11 | read-only | Profiles, failover groups, site-to-site connections (policy- and route-based, IPv4), live connections, remote-access settings. |
| SSL VPN | 9 | read-only | Remote-access policies, clientless policies, bookmark groups, bookmarks, global settings. |
| Network architecture | 28 | read + VLAN-only write | Interfaces, zones, gateways, static unicast routes, SD-WAN routes, DHCP servers/leases/relays, DNS settings/host entries/request routes, static neighbors. The only writes are `network_interface_create_vlan`, `network_interface_update_vlan` and `network_interface_delete_vlan`, which read the interface first and refuse any type other than `vlan`. |
| Network status | 2 | read-only | DNS protection status and cellular WAN modem status. |
| Audit (composite) | 3 | read-only | `audit_firewall_rules`, `explain_connectivity`, `find_object_usage`. Configuration analysis over the audited read operations; they add no new endpoint. |

Excluded by design: all bulk deletes, administrator CRUD, user groups, network-user login/logout, every
VPN mutation, WAF rules, IPS, and the mutation families outside the VLAN-only interface writes (zones,
gateways, routes, SD-WAN, DHCP, DNS, neighbors, router advertisements, multicast, mDNS, country groups).
The full per-operation inventory, with the reason for every exclusion, is in
[`docs/API-COVERAGE.md`](docs/API-COVERAGE.md).

### Tool annotations

Every tool publishes MCP `ToolAnnotations`. The hints are advisory metadata for the client —
they are not an authorization boundary (see [Security model](#security-model)) — but they are
part of the published contract, so a test pins every mutation's pair.

- **Read-only tools** publish `readOnlyHint: true` and no `destructiveHint`/`idempotentHint`.
  The spec says the write hints are meaningful only when `readOnlyHint` is false.
- **Mutation tools** publish `readOnlyHint: false` and declare both write hints explicitly.
  The server refuses to register a mutation that omits either one, so a new tool cannot
  silently inherit the spec default (`destructiveHint: true`).
- `destructiveHint: false` is reserved for operations that only add state: the eleven
  creates and `firewall_rule_clone`. Everything that replaces, removes or reorders existing
  state — the eleven JSON Merge Patch updates, the eleven deletes, the two moves,
  `firewall_rule_set_enabled` and `live_user_disconnect` — publishes `destructiveHint: true`.
- `idempotentHint` is independent of `destructiveHint`. Deletes, updates, moves and the
  enable/disable flip are destructive and idempotent; creates and the clone are additive and
  not idempotent; `live_user_disconnect` is destructive and not idempotent because a live
  session id is not stable across calls.
- `openWorldHint` is decided per tool: `false` for everything that reads or writes the one
  configured appliance, `true` only for the six tools whose result is produced by an entity
  the appliance does not own (DHCP leases, live sessions, live IPsec peers, the cellular
  carrier and the vendor's DNS Protection verdict).

## Calling the tools

### Flat arguments

Every tool that takes arguments publishes those arguments **flat**: the fields its `inputSchema`
lists are the fields the call sends, with no wrapper object. This matches the MCP specification's own
call examples, so a model's prior is correct on the first attempt.

105 of the 112 tools take arguments. The other 7 declare no request parameters and take an empty
`arguments` object: `dns_settings_get`, `ipsec_live_connection_list_ipv4`,
`ipsec_remote_access_settings_get`, `live_user_list`, `network_status_cellular_wan`,
`network_status_dns_protection` and `sslvpn_global_settings_get`.

A tool whose request is a union of shapes publishes a root `oneOf` of the closed variants instead of
one flat object, because each variant has its own required fields; the discriminator (`ip_family` or
`type`) selects the variant. `firewall_rule_create`/`_update`, `nat_rule_create`/`_update`,
`address_create`/`_update` and `address_group_create`/`_update` work this way, and
`mac_address_create` publishes an `anyOf` because the API declares no discriminator for it.

An unknown argument is rejected by name, and the message names the accepted set, so a model can
self-correct on the next call:

```
invalid arguments: bogus is not an accepted argument; accepted arguments are ip_family, id_or_name
```

**Input names are snake_case; output names are camelCase.** The published input fields are the
snake_case names (`page_size`, `name_contains`, `id_or_name`); the fields of the result are the
Sophos wire names (`pageSize`, `nameContains`, `idOrName`). See
[known limitations](#known-limitations-and-accepted-regressions).

### Three call shapes

A **no-argument read** — the tool publishes no properties, so `arguments` is empty:

```json
{"jsonrpc": "2.0", "id": 1, "method": "tools/call",
 "params": {"name": "dns_settings_get", "arguments": {}}}
```

A **paginated list** — `firewall_rule_list` publishes `ip_family`, `page`, `page_size`,
`page_total`, `name_contains` and `name_not_equals`:

```json
{"jsonrpc": "2.0", "id": 2, "method": "tools/call",
 "params": {"name": "firewall_rule_list",
            "arguments": {"ip_family": "ipv4", "page": 1, "page_size": 10, "page_total": true}}}
```

A **delete** — `firewall_rule_delete` publishes `ip_family` and `id_or_name`:

```json
{"jsonrpc": "2.0", "id": 3, "method": "tools/call",
 "params": {"name": "firewall_rule_delete",
            "arguments": {"ip_family": "ipv4", "id_or_name": "Allow LAN to WAN"}}}
```

### The IP family

A tool that exists for both IP families publishes one required `ip_family` argument (`ipv4` or
`ipv6`) instead of two tools. 40 tools take it. It is **required, not defaulted**: a default would
silently target one family, and for a mutation (delete, update, move, enable/disable, clone) that
would make a destructive target a guess. The audit composites are the one exception: they are
read-only and can span all families, so their `ip_family` is optional and omitting it means all of them (`find_object_usage` also accepts `fqdn`).
The wire body is unchanged for each family; the adapter strips `ip_family` and selects the IPv4 or
IPv6 path. The 80 tool names this replaces, and the `ip_family` value that reproduces each one, are
in the [migration table](docs/architecture/sophos-rest-api-redesign/MIGRATION-0.7.md).

Every required `ip_family` publishes the same description in `inputSchema` — *"IP family of the
collection: 'ipv4' or 'ipv6'. Required: the two collections are separate, so the family is never
inferred."* — on the 32 tools that require it and on the union variants, so the argument reads the
same everywhere. The three audit composites keep their own optional description, where omitting the
field means "all families" (`find_object_usage` also accepts `fqdn`).

### Read one of `content` / `structuredContent`, not both

Every successful result carries the payload **twice**: a pretty-printed JSON text block in `content`
and the same object in `structuredContent`. The duplication is sanctioned by the MCP specification for
backwards compatibility, so it is not a defect — but reading both doubles the token cost of every
call, and a single list page is 28–70 KB. Read `structuredContent` when the client supports it and
fall back to the `content` text block otherwise; never parse both.

## Context cost

`tools/list` returns all **112 tools in a single response**: **493,965 bytes** on the wire
(the raw JSON-RPC response line over STDIO, including the trailing newline) — roughly
**123k tokens** at ~4 bytes per token. The four-way split is:

| Component | Bytes | Share |
|---|---:|---:|
| Input schemas | 191,630 | 38.8% |
| Output schemas | 242,915 | 49.2% |
| Descriptions | 38,399 | 7.8% |
| Envelope (names, titles, annotations, JSON-RPC wrapper) | 21,021 | 4.3% |

The output schemas are still the largest part, but the catalog trim removed **133,883
bytes (−21.3%)** from the pre-trim baseline measured with the same script (627,848
bytes): the repeated `$defs` model
docstrings and field descriptions (the same `ObjectRef` definition appeared 64 times and
`Pages` 33 times) and the response-only `default` annotations are no longer published. The
trim is annotation-only: every `required`, `enum`, `const`, `type`, `format`, `$ref`,
nullability and alias is unchanged, and the SDK still validates `structuredContent`
against the output model. `Pages` and `FirewallRuleOutput` keep their field descriptions
because they document the `total`/`items` trap and the 1-based position. The measurement
is reproducible with `scripts/measure_catalog.py`; the full method and the before/after
table are in [`docs/CATALOG-SIZE.md`](docs/CATALOG-SIZE.md).

There is **no pagination cursor**: the pinned MCP SDK's `MCPServer` accepts
`PaginatedRequestParams` and ignores it, and exposes no public hook to supply a page. The
protocol supports `nextCursor` and the SDK's `ListToolsResult` carries it, but the
`MCPServer` wrapper discards the request cursor, so the server cannot paginate without a
private override. The limitation and the smallest upstream-compatible path are documented
in [`docs/CATALOG-SIZE.md`](docs/CATALOG-SIZE.md). A client that injects the whole catalog
into the prompt either truncates it — and then cannot call the tools that were cut — or
exhausts the context window before the first call.

The catalog is static for the process lifetime, so:

- **Call `tools/list` once per session and cache it.** Do not re-fetch it per turn.
- **Prefer progressive discovery** when the client supports it: load a subset of tools on demand
  instead of every definition up front. The MCP client guidance puts the threshold at 1–5% of the
  context window.
- **Use read-only mode** (`SOPHOS_READ_ONLY_MODE=true`) to publish 74 tools instead of 112 when the
  deployment only inspects.
- **Use domain selection** (`SOPHOS_TOOL_DOMAINS`) to publish only the domains the deployment needs:
  `SOPHOS_TOOL_DOMAINS=firewall,nat` publishes 14 tools, and adding `SOPHOS_READ_ONLY_MODE=true`
  publishes 4. See [Domain selection](#domain-selection).
- The server publishes **4 resources** (`sophos://api/surface`, `sophos://coverage`,
  `sophos://read-only-policy`, `sophos://conventions`) and up to **3 prompts** (`audit_firewall`,
  `explain_flow`, `find_unused_objects`), so a client can read the contract and the conventions
  without loading the tool catalog. A prompt is registered only when every tool its workflow names is
  registered, so a filtered instance publishes only the workflows it can run.

Earlier catalog work: 0.7.0 removed **185,133 bytes** (807,920 → 622,787, −22.9%) and 40
tools — the IPv4/IPv6 collapse behind `ip_family` removed 152,886 bytes, and publishing
flat arguments removed a further 32,247 bytes — on top of the earlier trim that removed
2,783 auto-generated property `title` keys and compacted 1,646 nullable unions.

## Configuration

The server reads exactly these ten environment variables. There are no XML-era settings.

| Variable | Required | Default | Description |
|---|---|---|---|
| `SOPHOS_HOST` | yes | — | Appliance hostname or IP address **only**. No scheme, port, user information, path or query. |
| `SOPHOS_PORT` | no | `4444` | HTTPS port of the Web Admin Console. |
| `SOPHOS_API_KEY` | one of the two | — | The API key inline. |
| `SOPHOS_API_KEY_FILE` | one of the two | — | Path to a file containing the API key (preferred for containers). The value is read and stripped. |
| `SOPHOS_VERIFY_SSL` | no | `true` | TLS certificate verification. Set `false` only for a lab appliance with a self-signed certificate; prefer `SOPHOS_CA_BUNDLE`. |
| `SOPHOS_CA_BUNDLE` | no | — | PEM CA bundle used to verify a private or self-signed appliance certificate. |
| `SOPHOS_TIMEOUT` | no | `30` | Request timeout in seconds (connect, read, write and pool). |
| `SOPHOS_MAX_CONCURRENCY` | no | `4` | Maximum concurrent HTTP requests to the appliance (1–64). A concurrency bound, not an invocation-rate limit; see [Invocation rate and concurrency](#invocation-rate-and-concurrency). |
| `SOPHOS_READ_ONLY_MODE` | no | `false` | When `true`, mutation tools are not registered at all. The application default is `false`; the shipped `.env.example` and `docker-compose.yml` default to `true`. |
| `SOPHOS_TOOL_DOMAINS` | no | unset (all six) | Comma-separated allowlist of the domains to publish: `firewall`, `nat`, `objects`, `users`, `network`, `audit`. Unset publishes the complete 112-tool surface. See [Domain selection](#domain-selection). |

Exactly one of `SOPHOS_API_KEY` / `SOPHOS_API_KEY_FILE` must be set; setting both is a startup error. The
key is held as a `SecretStr` and never appears in logs, errors, `repr` or tool output. Environment proxy
variables (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`) are deliberately **not** used, so the Bearer token
cannot travel through an inherited proxy; route traffic at the host level.

A commented template is in [`.env.example`](.env.example).

The application default for `SOPHOS_READ_ONLY_MODE` is `false`, but the shipped `.env.example` and
`docker-compose.yml` set it to `true`: a copy-and-run deployment publishes the 74 read-only tools and
no mutations. Exposing the 38 mutation tools requires an explicit `SOPHOS_READ_ONLY_MODE=false`.
Neither the Compose default nor the MCP tool annotations are an authorization boundary — the Sophos
administrator profile behind the API key is what actually authorizes a request.

## Install and run

This package is **not published on PyPI**. Install it from a clone or from the git URL.

```bash
# From a clone, with uv (recommended; uses the locked dependency set)
git clone https://github.com/lordraiden/sophos-firewall-mcp.git
cd sophos-firewall-mcp
uv sync --locked
uv run sophos-firewall-mcp-server

# From a clone, with pip
python -m venv .venv && . .venv/bin/activate
pip install .
sophos-firewall-mcp-server

# Straight from git, without a clone
uvx --from git+https://github.com/lordraiden/sophos-firewall-mcp.git sophos-firewall-mcp-server
```

The server speaks MCP over STDIO, so running it in a terminal waits for JSON-RPC frames on `stdin`. A
configuration error exits with status `2` and one actionable line on `stderr`.

## MCP client configuration

Add one of the snippets below to your MCP client settings (for example `.vscode/mcp.json`, Claude
Desktop's `claude_desktop_config.json`, or the equivalent in Cursor / Antigravity IDE).

### Container (Docker or Podman)

```json
{
  "mcpServers": {
    "sophos-firewall": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "-e", "SOPHOS_HOST",
        "-e", "SOPHOS_PORT",
        "-e", "SOPHOS_API_KEY",
        "-e", "SOPHOS_VERIFY_SSL",
        "-e", "SOPHOS_MAX_CONCURRENCY",
        "-e", "SOPHOS_READ_ONLY_MODE",
        "ghcr.io/lordraiden/sophos-firewall-mcp:0.7.1"
      ],
      "env": {
        "SOPHOS_HOST": "192.168.1.1",
        "SOPHOS_PORT": "4444",
        "SOPHOS_API_KEY": "your_api_key_here",
        "SOPHOS_VERIFY_SSL": "true",
        "SOPHOS_MAX_CONCURRENCY": "4",
        "SOPHOS_READ_ONLY_MODE": "true"
      }
    }
  }
}
```

Replace `"command": "docker"` with `"command": "podman"` for a rootless Podman setup. Keep `-i` and
**never** add `-t`: a TTY injects carriage returns into the JSON-RPC stream and breaks the protocol.

### Local `uv` workspace

```json
{
  "mcpServers": {
    "sophos-firewall": {
      "command": "uv",
      "args": ["--directory", "/path/to/sophos-firewall-mcp", "run", "sophos-firewall-mcp-server"],
      "env": {
        "SOPHOS_HOST": "192.168.1.1",
        "SOPHOS_PORT": "4444",
        "SOPHOS_API_KEY": "your_api_key_here",
        "SOPHOS_VERIFY_SSL": "true"
      }
    }
  }
}
```

### Local Python install

```json
{
  "mcpServers": {
    "sophos-firewall": {
      "command": "/path/to/venv/bin/sophos-firewall-mcp-server",
      "env": {
        "SOPHOS_HOST": "192.168.1.1",
        "SOPHOS_PORT": "4444",
        "SOPHOS_API_KEY_FILE": "/run/secrets/sophos_api_key",
        "SOPHOS_VERIFY_SSL": "true"
      }
    }
  }
}
```

### The server exits immediately and the client reports an empty error

The most common cause is a `PYTHONPATH` inherited from the process that launches the server: it shadows
the server's own virtualenv, so `mcp` is imported from the parent environment instead of the pinned
dependency. The server checks this at startup and, when it fails, prints the cause on `stderr` and exits
non-zero, naming the path `mcp` was loaded from. Run and install with a clean interpreter environment:

```bash
env -u PYTHONPATH -u PYTHONHOME .venv/bin/sophos-firewall-mcp-server
```

The same inherited `PYTHONPATH` also makes `pip` treat the parent's packages as already satisfying the
requirements and silently skip real dependencies, so install with it cleared too.

## Container usage

The image is published to GHCR as **`ghcr.io/lordraiden/sophos-firewall-mcp`**.

| Tag | Meaning |
|---|---|
| `0.7.1`, `0.7` | Stable release tags, published only from an approved release. |
| `latest` | Moved **only** by an approved release promotion — never by a push to `main`. |
| `main`, `sha-<short>` | Development builds from `main`. Not a release; no stability guarantee. |

The container runs the server over STDIO: no TTY, no HTTP port, no health endpoint. Pass configuration as
environment variables (or mount the key as a file) and keep `stdin` open.

```bash
# Key from a mounted secret file (preferred)
docker run -i --rm \
  -e SOPHOS_HOST=192.168.1.1 \
  -e SOPHOS_PORT=4444 \
  -e SOPHOS_API_KEY_FILE=/run/secrets/sophos_api_key \
  -e SOPHOS_VERIFY_SSL=true \
  -v "$PWD/sophos_api_key:/run/secrets/sophos_api_key:ro" \
  ghcr.io/lordraiden/sophos-firewall-mcp:0.7.1
```

`docker-compose.yml` in this repository is a REST-only reference: it passes the same variables, keeps
`stdin_open: true`, does not enable a TTY, and defaults `SOPHOS_READ_ONLY_MODE` to `true`.

Compose is a way to describe the process, not to run a daemon. The MCP client owns the lifecycle, so
the supported invocation is one container per session:

```bash
docker compose run --rm -T sophos-firewall-mcp
```

`-T` disables the pseudo-TTY that `docker compose run` allocates by default (a TTY corrupts the
JSON-RPC stream) and `--rm` removes the container when the session ends. Point the MCP client at that
command, for example:

```json
{
  "mcpServers": {
    "sophos-firewall": {
      "command": "docker",
      "args": ["compose", "-f", "/path/to/docker-compose.yml", "run", "--rm", "-T", "sophos-firewall-mcp"]
    }
  }
}
```

`docker compose up` is **not** the supported invocation: it does not attach the client's stdin/stdout
to the container. The service therefore has no `restart` policy — restarting would only re-spawn a
server whose stdin has already closed, with no client attached.

A deployment that bridges STDIO over TCP/SSE (for example an MCP gateway) is a different shape: it
needs a long-running bridge process and a published port, so it should use its own Compose file and
may add `restart: unless-stopped` in an override file. The shipped file stays a per-session STDIO
example.

## Read-only mode

Set `SOPHOS_READ_ONLY_MODE=true` to register only the 74 read-only tools. Mutation tools are not
registered at all, so a client cannot discover or call them. This is defence in depth, not the primary
control: the API key's administrator profile is what actually authorizes a request. Use a read-only
administrator profile for any deployment that only needs inspection.

The application default is `false`, but the shipped `.env.example` and `docker-compose.yml` set it to
`true`, so a copy-and-run deployment starts read-only. Exposing mutation tools requires an explicit
`SOPHOS_READ_ONLY_MODE=false`; MCP tool annotations and Compose defaults are advisory metadata, not an
authorization boundary.

Read-only mode composes with [domain selection](#domain-selection) and the two settings stay
independent: the selection decides which capabilities exist, and read-only mode then removes the
mutation tools *within* the selected domains.

## Domain selection

`SOPHOS_TOOL_DOMAINS` narrows the published tool surface to the domains a deployment needs, so a
client is not handed 112 tool definitions when it uses six. It is a comma-separated allowlist of the
six stable domain identifiers:

| Identifier | Tools | Read-only | Mutations | What it publishes |
|---|---:|---:|---:|---|
| `firewall` | 8 | 2 | 6 | Firewall rules, including `firewall_rule_set_enabled` and `firewall_rule_clone`. |
| `nat` | 6 | 2 | 4 | NAT rules. |
| `objects` | 37 | 16 | 21 | Addresses, address groups, FQDN addresses and groups, MAC addresses, country groups, services and service groups. |
| `users` | 8 | 4 | 4 | General users, network users and live sessions. |
| `network` | 50 | 47 | 3 | Interfaces, zones, gateways, routes, SD-WAN, DHCP, DNS, neighbors, IPsec VPN, SSL VPN and network status. |
| `audit` | 3 | 3 | 0 | The three composite tools. |

Unset (the default) registers all six domains in the order above: exactly the 112 tools, with the same
names and the same order as before the setting existed. A selection is normalised to that order, so
`SOPHOS_TOOL_DOMAINS=audit,firewall` and `SOPHOS_TOOL_DOMAINS=firewall,audit` publish the same catalog
in the same order.

```env
# Only the domains this deployment needs, and only their read-only tools.
SOPHOS_TOOL_DOMAINS=firewall,nat,objects,network,audit
SOPHOS_READ_ONLY_MODE=true
```

**Validation is strict.** An unknown identifier, an empty entry (`firewall,`), a blank value, a
repeated identifier or a selection whose dependencies are missing fails startup with status `2` and
one actionable line on `stderr`. Nothing is silently dropped, because a typo that quietly narrows the
surface is only noticed when a client cannot find a tool.

**Dependencies.** No domain depends on another domain being registered. The audit composites are the
only cross-domain tools, and they call the other domains' adapter classes directly rather than their
registered tools, so `SOPHOS_TOOL_DOMAINS=audit` publishes all three composites and works on its own.
The dependency model is declared in `sophos_firewall_mcp.config.DOMAIN_DEPENDENCIES` (currently
empty) and enforced at startup, so a future domain that does need another domain's registration is
rejected instead of failing on its first call.

**The published context follows the selection.** `sophos://api/surface`, `sophos://coverage`,
`sophos://read-only-policy`, `sophos://conventions` and the server `instructions` describe the tools
this process actually registered and name the domains it did not enable. A prompt is registered only
when every tool its workflow names is registered, so a filtered instance never tells a model to call a
tool it does not have. The full catalog totals stay visible in the resources, explicitly labelled as
the catalog, so two deployments can be compared.

This is a context-budget control, not an authorization boundary: it does not replace the Sophos
administrator profile or a host-side approval policy.

## Security model

- **Bearer API key**, held as `SecretStr`, sent only in the `Authorization` header. It is never logged,
  never included in error messages, and never returned in tool output.
- **TLS verified by default.** `SOPHOS_VERIFY_SSL=false` exists for lab appliances with self-signed
  certificates; `SOPHOS_CA_BUNDLE` is the better option. No example in this README disables
  verification; the lab runbooks under `docs/architecture/` use `SOPHOS_VERIFY_SSL=false` only for the
  self-signed lab appliance and say so.
- **No inherited proxy.** Proxy environment variables are ignored so the token cannot be routed through
  an unexpected proxy.
- **No cross-origin redirects.** A redirect to another origin is refused rather than followed with the
  token attached.
- **Sanitized errors.** Anticipated failures surface as `ToolError` with a short, actionable message;
  raw remote bodies, stack traces and secrets are not returned to the model. Unexpected exceptions are
  logged server-side only.
- **No raw endpoint execution.** There is no tool that accepts a URL, path, method or arbitrary payload.
- **Remote data is untrusted.** Strings returned by the appliance are treated as data, never as
  instructions.
- **Writes are not retried.** A write that times out is reported as an ambiguous write instead of being
  repeated, because repeating it could duplicate a rule or a NAT entry.

## Invocation rate and concurrency

The server distinguishes two controls that are easy to conflate:

| Control | What it bounds | Setting | Default | Ceiling |
|---|---|---|---|---|
| Concurrency | HTTP requests in flight at once | `SOPHOS_MAX_CONCURRENCY` | `4` | `64` |
| Invocation rate | tool invocations per unit of time | none | — | — |

`SOPHOS_MAX_CONCURRENCY` is a **concurrency** bound, not a rate limit. It caps how many requests
overlap; it does not cap how many invocations a client may issue over time. A client can make an
unbounded number of sequential calls, each of which waits for a slot and then completes.

**Policy: no server-side invocation-rate limiter.** The MCP `2026-07-28` Tools specification lists
"Rate limit tool invocations" among the server's Security Considerations
([source](https://modelcontextprotocol.io/specification/2026-07-28/server/tools#security-considerations)).
This server does not implement that limiter; the decision record
([`docs/SECURITY-RATE-POLICY.md`](docs/SECURITY-RATE-POLICY.md)) records it as an **accepted residual
risk** for the local STDIO, one-client-per-process deployment, not as a discharge of the MUST. The
exposure is bounded by the STDIO transport (one local client), the concurrency semaphore, and the
appliance's own rate limits; the residual risk — a runaway model loop issuing many sequential calls —
is delegated to the client/host (timeouts, loop detection, user confirmation), whose guidance is a
SHOULD, not a MUST. A deployment that exposes the server over HTTP or shares one process across
clients must add a tool-invocation limiter at the tool dispatch layer; the decision record explains
why the HTTP client layer is the wrong place for it.

## Known limitations and accepted regressions

- **Tool arguments are flat as of 0.7.0.** Every tool that takes arguments publishes its fields at the
  top level of `inputSchema`; the `request` wrapper is gone from all 112 tools. This was a breaking
  change from 0.6.0: a call that still wraps its arguments in `request` is rejected with `request is
  not an accepted argument`. A union request publishes a root `oneOf` (or `anyOf` for
  `mac_address_create`), and its discriminator selects the variant.
- **The IPv4/IPv6 pairs are one tool each as of 0.7.0.** 80 family-specific tool names are gone; each
  merged tool takes a required `ip_family` (`ipv4` or `ipv6`). The
  [migration table](docs/architecture/sophos-rest-api-redesign/MIGRATION-0.7.md) maps every removed
  name to its replacement and the `ip_family` value that reproduces the old behaviour.
- **The four highest-blast-radius deletes require a client confirmation.** `firewall_rule_delete`,
  `nat_rule_delete`, `network_user_delete` and `network_interface_delete_vlan` ask the client to
  confirm and delete nothing unless it accepts. On the modern (`2026-07-28`) protocol the question is
  an `InputRequiredResult` round trip; on the legacy handshake it is a standalone elicitation. A
  client that declares no form-mode `elicitation` capability, or a transport that cannot carry the
  question, gets a tool error and nothing is deleted. This is a deliberate precondition, not an
  additive affordance: a non-interactive client cannot perform these four deletes.
- **Input parameter naming is uniform as of 0.5.0.** Every published input property, at every depth,
  is snake_case (`page_size`, `name_contains`, `id_or_name`, `rule_type`, `reference_item`, …). The JSON
  body sent to the appliance is unchanged: each field keeps its Sophos wire alias. This was a breaking
  change from 0.4.0, where 79 tools published the wire names; callers that hard-coded `pageSize` /
  `nameContains` / `idOrName` must update. The published schemas also set `additionalProperties: false`,
  so an unknown argument is rejected instead of ignored.
- **Output field naming is uniform on camelCase as of 0.6.0.** Every published output property is the
  Sophos wire name (`pageSize`, `nameContains`, `idOrName`, `servicesOrGroups`, …), because outputs are
  projections of the appliance payload. The three audit composites (`audit_firewall_rules`,
  `explain_connectivity`, `find_object_usage`) are camelCase by convention rather than wire names: they
  are computed, not projections. The convention is deliberate: inputs are snake_case because the
  model writes them, outputs are wire-faithful because the model reads them. This was a breaking change
  from 0.5.0 for the 23 tools that still published snake_case outputs (12 NAT, 8 users and 3 audit
  tools); callers that parsed `original_services_or_groups` or `translated_source` must update.
- **Firmware compatibility.** The lab appliance runs **SFOS 23.0.0 GA-Build371** (owner-provided). The
  Configuration REST API is the same across SFOS versions, so the tools are not build-specific; the live
  evidence records what was exercised on that build. See
  [Supported appliance and API](#supported-appliance-and-api). Verify against your own appliance before
  relying on a tool.
- **Live write validation is limited.** The 0.5.0 cycle validated create/update/delete against the lab
  appliance for an IPv4 address, an FQDN address, a service, a MAC address, a network user, a firewall
  rule and a NAT rule, with every created object deleted and the collection counts restored
  ([`docs/live-evidence/phase-4-write-validation.md`](docs/live-evidence/phase-4-write-validation.md)).
  Rules were created `enabled: false` and the applied state was read back. What remains unverified:
  ambiguous-write reconciliation, a real `403` denial, bulk delete, interface/VPN mutations, and every
  write on a firmware other than the lab appliance. Read paths are exercised by the opt-in
  `pytest -m live` suite; see [`docs/live-evidence/`](docs/live-evidence/) for what was run and deferred.
- **Accepted regressions** (no REST endpoint exists, so no placeholder tool is advertised):
  - system information — appliance model, serial number, firmware version and uptime;
  - service status — the running state of system services;
  - log query — log destinations can be configured, but logs cannot be read through this API.
- **Audit tools are configuration analysis, not packet tests.** `explain_connectivity` reports
  `method: config-analysis` and returns `not-verifiable` when the configuration does not contain enough
  evidence. Findings are bounded and report truncation explicitly.
- **Pagination is one page per call.** The server never fetches every page automatically; request the
  next page explicitly. `pageSize` is validated to `1..100`.
- **Excluded by design:** bulk delete, administrator CRUD, user groups, all VPN mutations, WAF, IPS, and
  the network mutation families listed in [`docs/API-COVERAGE.md`](docs/API-COVERAGE.md).

## Development

```bash
uv sync --locked                 # install runtime + dev dependencies from the lock
uv run pytest -q                 # unit and contract tests (no appliance needed)
uv run pytest -m live -q         # opt-in, READ-ONLY live tests; needs SOPHOS_HOST/PORT/API_KEY
uv run mypy src/sophos_firewall_mcp
uv run flake8 src tests scripts
uv run black --check src tests scripts
uv run python scripts/generate_coverage.py --check   # docs/API-COVERAGE.md is up to date
```

`pytest -m live` is skipped by default and only runs when `SOPHOS_HOST`, `SOPHOS_PORT` and one of
`SOPHOS_API_KEY` / `SOPHOS_API_KEY_FILE` are set. It never sends a write. The evidence format is
documented in [`docs/live-evidence/README.md`](docs/live-evidence/README.md).

## Documentation

- [API coverage matrix](docs/API-COVERAGE.md) — every operation, its tool, and the reason for every
  exclusion.
- [SDK compatibility](docs/SDK-COMPATIBILITY.md) — the supported MCP SDK range, why it is an exact
  pin, and how to widen it.
- [REST client strategy (ADR-001)](docs/architecture/ADR-001-rest-client-strategy.md) — why the client is
  hand-written HTTPX + Pydantic, and the first-release scope.
- [Redesign documentation](docs/architecture/sophos-rest-api-redesign/README.md) — plan, references, lab
  access and phase reviews.
- [Live evidence](docs/live-evidence/) — what was verified against a real appliance, and what was
  deferred with a reason.
- [Release notes 0.7.1](docs/release/RELEASE-0.7.1.md) — the patch release that closes the 0.7.0
  standards-review findings, its one behaviour change, rollback plan and publication checklist.
- [Release notes 0.7.0](docs/release/RELEASE-0.7.0.md) — the breaking release, its IPv4/IPv6 collapse
  and flat arguments, rollback plan and publication checklist.
- [Migration to 0.7.0](docs/architecture/sophos-rest-api-redesign/MIGRATION-0.7.md) — the 80 removed
  tool names, their replacements and the `ip_family` value for each.
- [Release notes 0.6.0](docs/release/RELEASE-0.6.0.md) — the output-contract release, its breaking
  camelCase output naming, rollback plan and publication checklist.
- [Release notes 0.5.0](docs/release/RELEASE-0.5.0.md) — the refinement release, its breaking input
  naming, rollback plan and publication checklist.
- [Release notes 0.4.0](docs/release/RELEASE-0.4.0.md) — the REST-only migration, rollback plan and
  publication checklist.
- [Changelog](CHANGELOG.md).

## License

Distributed under the Apache 2.0 License. See [LICENSE](LICENSE) for details.
