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

> **0.7.0 is the current release.** It is a breaking release with two changes: the 40 IPv4/IPv6 tool
> pairs collapse into one tool per concept behind a **required `ip_family`** argument, and tool
> arguments are published **flat** instead of inside a `request` wrapper. The surface drops from 152
> tools to 112 and the catalog from 807,920 to 622,787 bytes. The
> [migration table](docs/architecture/sophos-rest-api-redesign/MIGRATION-0.7.md) maps every removed
> tool name to its replacement. 0.6.0 unified the published *output* field names on camelCase (the
> Sophos wire names); 0.5.0 unified every published *input* parameter on snake_case; 0.4.0 was the
> breaking, REST-only migration: the XML transport, the XML credentials, the raw XML tool, the
> semantic router and FastEmbed are gone, with no compatibility mode. See
> [`CHANGELOG.md`](CHANGELOG.md), the [0.7.0 release notes](docs/release/RELEASE-0.7.0.md), the
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
- [Security model](#security-model)
- [Known limitations and accepted regressions](#known-limitations-and-accepted-regressions)
- [Development](#development)
- [Documentation](#documentation)
- [License](#license)

---

## What it does

- **112 typed tools across 11 domains**, covering 145 audited operations of the checked-in OpenAPI
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
| MCP SDK | `mcp>=2.3.0,<3` (installed as a dependency) |
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

| Domain | Tools | Access | Coverage |
|---|---:|---|---|
| Firewall rules (IPv4/IPv6) | 8 | read + write | List, get, create, update, delete and move, plus `firewall_rule_set_enabled` (PATCH `enabled`) and `firewall_rule_clone` (get + create). The required `ip_family` selects the IPv4 or IPv6 rule base. A created rule is never auto-enabled or repositioned. |
| NAT rules (IPv4/IPv6) | 6 | read + write | List, get, create, update, delete and move; `ip_family` selects the rule base. |
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
read-only and can span both families, so their `ip_family` is optional and omitting it means both.
The wire body is unchanged for each family; the adapter strips `ip_family` and selects the IPv4 or
IPv6 path. The 80 tool names this replaces, and the `ip_family` value that reproduces each one, are
in the [migration table](docs/architecture/sophos-rest-api-redesign/MIGRATION-0.7.md).

### Read one of `content` / `structuredContent`, not both

Every successful result carries the payload **twice**: a pretty-printed JSON text block in `content`
and the same object in `structuredContent`. The duplication is sanctioned by the MCP specification for
backwards compatibility, so it is not a defect — but reading both doubles the token cost of every
call, and a single list page is 28–70 KB. Read `structuredContent` when the client supports it and
fall back to the `content` text block otherwise; never parse both.

## Context cost

`tools/list` returns all **112 tools in a single response**: **622,787 bytes**, roughly **156k tokens**
at ~4 bytes per token. The size is the raw JSON-RPC `tools/list` response line measured over STDIO,
including the trailing newline; the envelope is identical across the protocol versions the server
negotiates. There is no pagination cursor, so a client
that injects the whole catalog into the prompt either truncates it — and then cannot call the tools
that were cut — or exhausts the context window before the first call.

The catalog is static for the process lifetime, so:

- **Call `tools/list` once per session and cache it.** Do not re-fetch it per turn.
- **Prefer progressive discovery** when the client supports it: load a subset of tools on demand
  instead of every definition up front. The MCP client guidance puts the threshold at 1–5% of the
  context window.
- **Use read-only mode** (`SOPHOS_READ_ONLY_MODE=true`) to publish 74 tools instead of 112 when the
  deployment only inspects.
- The server publishes **4 resources** (`sophos://api/surface`, `sophos://coverage`,
  `sophos://read-only-policy`, `sophos://conventions`) and **3 prompts** (`audit_firewall`,
  `explain_flow`, `find_unused_objects`), so a client can read the contract and the conventions
  without loading the tool catalog.

The payload is dominated by the output schemas. 0.7.0 removed **185,133 bytes** from the catalog
(807,920 → 622,787, −22.9%) and 40 tools: the IPv4/IPv6 collapse behind `ip_family` removed 152,886
bytes (807,920 → 655,034), and publishing flat arguments removed a further 32,247 bytes (655,034 →
622,787). That is on top of the earlier catalog trim that removed 2,783 auto-generated property
`title` keys and compacted 1,646 nullable unions.

## Configuration

The server reads exactly these nine environment variables. There are no XML-era settings.

| Variable | Required | Default | Description |
|---|---|---|---|
| `SOPHOS_HOST` | yes | — | Appliance hostname or IP address **only**. No scheme, port, user information, path or query. |
| `SOPHOS_PORT` | no | `4444` | HTTPS port of the Web Admin Console. |
| `SOPHOS_API_KEY` | one of the two | — | The API key inline. |
| `SOPHOS_API_KEY_FILE` | one of the two | — | Path to a file containing the API key (preferred for containers). The value is read and stripped. |
| `SOPHOS_VERIFY_SSL` | no | `true` | TLS certificate verification. Set `false` only for a lab appliance with a self-signed certificate; prefer `SOPHOS_CA_BUNDLE`. |
| `SOPHOS_CA_BUNDLE` | no | — | PEM CA bundle used to verify a private or self-signed appliance certificate. |
| `SOPHOS_TIMEOUT` | no | `30` | Request timeout in seconds (connect, read, write and pool). |
| `SOPHOS_MAX_CONCURRENCY` | no | `4` | Maximum concurrent HTTP requests to the appliance (1–64). |
| `SOPHOS_READ_ONLY_MODE` | no | `false` | When `true`, mutation tools are not registered at all. |

Exactly one of `SOPHOS_API_KEY` / `SOPHOS_API_KEY_FILE` must be set; setting both is a startup error. The
key is held as a `SecretStr` and never appears in logs, errors, `repr` or tool output. Environment proxy
variables (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`) are deliberately **not** used, so the Bearer token
cannot travel through an inherited proxy; route traffic at the host level.

A commented template is in [`.env.example`](.env.example).

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
        "-e", "SOPHOS_READ_ONLY_MODE",
        "ghcr.io/lordraiden/sophos-firewall-mcp:0.7.0"
      ],
      "env": {
        "SOPHOS_HOST": "192.168.1.1",
        "SOPHOS_PORT": "4444",
        "SOPHOS_API_KEY": "your_api_key_here",
        "SOPHOS_VERIFY_SSL": "true",
        "SOPHOS_READ_ONLY_MODE": "false"
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
| `0.7.0`, `0.7` | Stable release tags, published only from an approved release. |
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
  ghcr.io/lordraiden/sophos-firewall-mcp:0.7.0
```

`docker-compose.yml` in this repository is a REST-only reference: it passes the same variables, keeps
`stdin_open: true` and does not enable a TTY.

## Read-only mode

Set `SOPHOS_READ_ONLY_MODE=true` to register only the 74 read-only tools. Mutation tools are not
registered at all, so a client cannot discover or call them. This is defence in depth, not the primary
control: the API key's administrator profile is what actually authorizes a request. Use a read-only
administrator profile for any deployment that only needs inspection.

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
- **Elicitation is available to handshake clients only.** The four highest-blast-radius deletes ask
  the client to confirm when it declared the `elicitation` capability and the transport has a
  back-channel. `mcp` 2.3.0 refuses a server-initiated request on the modern (`2026-07-28`)
  per-request path, so the confirmation is silently skipped there and the delete proceeds exactly as
  before; a non-interactive client is unaffected either way. The confirmation is an additive
  affordance, never a new precondition.
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
- [REST client strategy (ADR-001)](docs/architecture/ADR-001-rest-client-strategy.md) — why the client is
  hand-written HTTPX + Pydantic, and the first-release scope.
- [Redesign documentation](docs/architecture/sophos-rest-api-redesign/README.md) — plan, references, lab
  access and phase reviews.
- [Live evidence](docs/live-evidence/) — what was verified against a real appliance, and what was
  deferred with a reason.
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
