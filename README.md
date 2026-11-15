# Sophos Firewall MCP Server (`sophos-firewall-mcp`)

[![Container image](https://img.shields.io/badge/ghcr.io-lordraiden%2Fsophos--firewall--mcp-blue.svg)](https://github.com/lordraiden/sophos-firewall-mcp/pkgs/container/sophos-firewall-mcp)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python Version](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue.svg)](pyproject.toml)
[![MCP protocol](https://img.shields.io/badge/MCP-2026--07--28-informational.svg)](https://modelcontextprotocol.io/)

A local [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server that administers a
**Sophos Firewall (SFOS)** appliance through its **Configuration REST API**, over **STDIO**.

It is not the Sophos Central Firewall Management API: the only backend is
`https://<SOPHOS_HOST>:<SOPHOS_PORT>/api/firewall-config/v1` on the appliance itself, authenticated with a
Bearer API key.

> **0.4.0 is a breaking, REST-only release.** The XML API transport, the XML username/password
> credentials, the raw XML tool, the semantic tool router and the FastEmbed dependency are removed.
> There is no compatibility mode. See [`CHANGELOG.md`](CHANGELOG.md) and the
> [release notes](docs/release/RELEASE-0.4.0.md).

---

## Contents

- [What it does](#what-it-does)
- [Requirements](#requirements)
- [Sophos Firewall prerequisites](#sophos-firewall-prerequisites)
- [Tool surface](#tool-surface)
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

- **152 typed tools across 11 domains**, covering 145 audited operations of the checked-in OpenAPI
  contract (`firewall_config_openapi.yaml`, 700 operations) plus 7 composite tools that add no new
  endpoint. Every tool maps to a documented `operationId`; the mapping is in
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

152 tools, 11 domains. The Access column shows whether a domain exposes mutation tools; with
`SOPHOS_READ_ONLY_MODE=true` the server registers **98 tools and 0 mutations**.

| Domain | Tools | Access | Coverage |
|---|---:|---|---|
| Firewall rules (IPv4/IPv6) | 16 | read + write | List, get, create, update, delete and move, plus `firewall_rule_set_enabled_*` (PATCH `enabled`) and `firewall_rule_clone_*` (get + create). A created rule is never auto-enabled or repositioned. |
| NAT rules (IPv4/IPv6) | 12 | read + write | List, get, create, update, delete and move. |
| Addresses and address groups | 37 | read + write | IPv4, IPv6 and FQDN addresses and groups (full CRUD), MAC addresses (full CRUD), country groups (read-only). |
| Services and service groups | 10 | read + write | List, get, create, update, delete. |
| Network users | 6 | read + write | General user list and network-user CRUD. Passwords are write-only and never returned or logged. |
| Live users | 2 | read + write | List active sessions and disconnect one session. |
| IPsec VPN | 11 | read-only | Profiles, failover groups, site-to-site connections (policy- and route-based, IPv4), live connections, remote-access settings. |
| SSL VPN | 9 | read-only | Remote-access policies, clientless policies, bookmark groups, bookmarks, global settings. |
| Network architecture | 44 | read + VLAN-only write | Interfaces, zones, gateways, static unicast routes, SD-WAN routes, DHCP servers/leases/relays, DNS settings/host entries/request routes, static neighbors. The only writes are `network_interface_create_vlan`, `network_interface_update_vlan` and `network_interface_delete_vlan`, which read the interface first and refuse any type other than `vlan`. |
| Network status | 2 | read-only | DNS protection status and cellular WAN modem status. |
| Audit (composite) | 3 | read-only | `audit_firewall_rules`, `explain_connectivity`, `find_object_usage`. Configuration analysis over the audited read operations; they add no new endpoint. |

Excluded by design: all bulk deletes, administrator CRUD, user groups, network-user login/logout, every
VPN mutation, WAF rules, IPS, and the mutation families outside the VLAN-only interface writes (zones,
gateways, routes, SD-WAN, DHCP, DNS, neighbors, router advertisements, multicast, mDNS, country groups).
The full per-operation inventory, with the reason for every exclusion, is in
[`docs/API-COVERAGE.md`](docs/API-COVERAGE.md).

## Configuration

The server reads exactly these eight environment variables. There are no XML-era settings.

| Variable | Required | Default | Description |
|---|---|---|---|
| `SOPHOS_HOST` | yes | — | Appliance hostname or IP address **only**. No scheme, port, user information, path or query. |
| `SOPHOS_PORT` | no | `4444` | HTTPS port of the Web Admin Console. |
| `SOPHOS_API_KEY` | one of the two | — | The API key inline. |
| `SOPHOS_API_KEY_FILE` | one of the two | — | Path to a file containing the API key (preferred for containers). The value is read and stripped. |
| `SOPHOS_VERIFY_SSL` | no | `true` | TLS certificate verification. Set `false` only for a lab appliance with a self-signed certificate; prefer `SOPHOS_CA_BUNDLE`. |
| `SOPHOS_CA_BUNDLE` | no | — | PEM CA bundle used to verify a private or self-signed appliance certificate. |
| `SOPHOS_TIMEOUT` | no | `30` | Request timeout in seconds (connect, read, write and pool). |
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
        "ghcr.io/lordraiden/sophos-firewall-mcp:0.4.0"
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
| `0.4.0`, `0.4` | Stable release tags, published only from an approved release. |
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
  ghcr.io/lordraiden/sophos-firewall-mcp:0.4.0
```

`docker-compose.yml` in this repository is a REST-only reference: it passes the same variables, keeps
`stdin_open: true` and does not enable a TTY.

## Read-only mode

Set `SOPHOS_READ_ONLY_MODE=true` to register only the 98 read-only tools. Mutation tools are not
registered at all, so a client cannot discover or call them. This is defence in depth, not the primary
control: the API key's administrator profile is what actually authorizes a request. Use a read-only
administrator profile for any deployment that only needs inspection.

## Security model

- **Bearer API key**, held as `SecretStr`, sent only in the `Authorization` header. It is never logged,
  never included in error messages, and never returned in tool output.
- **TLS verified by default.** `SOPHOS_VERIFY_SSL=false` exists for lab appliances with self-signed
  certificates; `SOPHOS_CA_BUNDLE` is the better option. No example in this repository disables
  verification.
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

- **Target firmware build is not verified.** The contract exposes no version endpoint
  (`getSystemSettings` returns only `hostname`, `loginDisclaimer` and `updatedAt`), so the SFOS build
  behind the checked-in OpenAPI file is unknown. This project makes **no firmware compatibility claim**;
  verify against your own appliance before relying on a tool.
- **No live write validation.** The shared lab credential is read-only, so no POST, PATCH or DELETE has
  been executed against a real appliance. Write tools are covered by contract tests (mocked HTTP) only.
  Read paths are exercised by the opt-in `pytest -m live` suite; see
  [`docs/live-evidence/`](docs/live-evidence/) for what was actually run and what was deferred.
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
- [Release notes 0.4.0](docs/release/RELEASE-0.4.0.md) — breaking changes, rollback plan and publication
  checklist.
- [Changelog](CHANGELOG.md).

## License

Distributed under the Apache 2.0 License. See [LICENSE](LICENSE) for details.
