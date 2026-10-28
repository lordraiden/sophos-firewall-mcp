# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-10-28

Breaking: requires `mcp>=2`, which renamed `FastMCP` to `MCPServer` and moved the import to
`mcp.server.mcpserver`. `SophosPartialResultError` is new and partial results (201, 203, 211-215) now
raise instead of returning as success, so a caller that treated them as applied will see an exception.
Everything else below is additive or fixes a wrong answer.

## [Unreleased]

### Added
- **Documented upstream sync policy (`docs/UPSTREAM-SYNC.md`, `scripts/sync-upstream.sh`)**: this fork is the
  maintained copy, so `main` carries the fixes and is never rewritten; upstream arrives as a merge
  commit. The script fetches, reports what is missing, and merges — refusing to run on a dirty tree
  and never rebasing, force-pushing or resolving conflicts on its own.

### Fixed
- **A slow appliance produced an error with no text at all (`client.py`)**: the HTTP timeout was hardcoded
  at 30 s, while a full `Get FirewallRule` on a real configuration takes longer (~64 KB over a VPN).
  httpx then raised `ReadTimeout`, whose `str()` is the empty string, and the MCP layer formats failures
  as `Error executing tool <name>: <str(exc)>` — so the caller got `Error executing tool
  sophos_list_firewall_rules: ` and nothing else. Four of 61 calls failed this way in one session, and the
  symptom is indistinguishable from a crashed server. Now: the timeout comes from `SOPHOS_TIMEOUT`
  (default **120 s**, above what a real listing needs), and `httpx.TimeoutException` / `TransportError`
  are re-raised as `SophosResponseError` with codes `TIMEOUT` / `CONNECT` naming the endpoint, the
  operation and tag, the elapsed seconds, and the knob to change. An invalid `SOPHOS_TIMEOUT` warns and
  falls back instead of stopping the server from booting.
- **Migrated to `mcp` 2.x (`MCPServer`) and dropped the `mcp<2` pin (`pyproject.toml`, `server.py`,
  `resources.py`, `prompts.py`, `_env_guard.py`)**: `mcp.server.fastmcp` no longer exists in 2.0, so the
  server could not start under any environment that had 2.x installed — which is exactly what happened
  inside Hermes and produced the empty "Error executing tool" report. Now:
  - `FastMCP` -> `MCPServer` from `mcp.server.mcpserver`; the tool/resource/prompt/run API is unchanged.
  - `ToolAnnotations` fields take snake_case kwargs (`read_only_hint`, `destructive_hint`,
    `idempotent_hint`); the JSON sent to clients is still `readOnlyHint`/`destructiveHint`/`idempotentHint`.
  - the guard now reports the version requirement it actually needs ("requires mcp>=2").
  - `tests/test_server.py` reads the tool list through the public `list_tools()` coroutine instead of
    FastMCP 1.x internals (`_tool_manager._tools`) and asserts the **wire** annotations, so the next SDK
    bump breaks loudly at the right place.
- **`sophos_get_system_info` promised data the API cannot give (`tools/system.py`)**: the description read
  "appliance model, firmware version, serial number, and uptime", but SFOS answers 529 for every module
  that would carry them (`SystemInformation`, `SystemInfo`, `System`, `SystemStatus`, `Up2Date`) — verified
  on SFOS 22, where even `AdminSettings` returns only hostname, admin ports and login policy. The
  description now states what the tool cannot return, names the alternatives (SNMP, syslog,
  `sophos_get_service_status`, `raw Get AdminSettings`) and matches the diagnostic the tool already
  returned at runtime. Behaviour is unchanged; only what the agent reads before calling it.
- **Install instructions named a package that does not exist on PyPI (`README.md`)**: the router note
  suggested `pip install "sophos-firewall-mcp-server[router]"`, which cannot resolve because the project
  is not published there (pypi.org returns 404 for the name). The instructions now use a clone or the git
  URL, and a note states plainly that there is no PyPI release, so nobody spends time debugging a 404 that
  is not theirs.
- **Status codes are read from the documented table, not from the message text (`client.py`)**: the old
  check exempted `500` and accepted anything whose text contained "successfully", so **500 ("Operation
  could not be performed on Entity") was reported as success** and **203 ("successful but few
  configurations could not be applied") was indistinguishable from a clean 200**. Codes are now classified
  `ok` (200, 216) / `warning` (201, 203, 211-215) / `error` (everything else), with the official description
  in the message. Partial results raise `SophosPartialResultError` — a subclass of `SophosResponseError`,
  so existing handlers keep working — because an agent that believes a rule was applied when only part of
  it was will not retry. `526` ("Record does not exist") on a `Get` now returns no rows instead of raising;
  on a `Set` it stays an error.
- **Empty or non-XML responses were undiagnosable (`client.py`)**: `xmltodict.parse` on an empty body
  raised `ExpatError: no element found: line 1, column 0`, which names neither the appliance nor the
  cause — and an empty body is an ordinary configuration symptom (API access disabled, client IP missing
  from Allowed IP Addresses, wrong admin port, or a proxy stripping the form body). Both cases now raise
  `SophosResponseError` with the checks to perform, and the non-XML case quotes a redacted snippet of what
  arrived so the diagnosis does not depend on guesswork.
- **Silent death on a shadowed interpreter environment (`_env_guard.py`, `server.py`)**: a `PYTHONPATH`
  inherited from the launching process shadowed the virtualenv, so `mcp` was imported from the parent's
  environment (2.x), `mcp.server.fastmcp` raised `ModuleNotFoundError`, and the process exited before
  answering a single JSON-RPC request — which MCP clients surface as an empty error with no message.
  The server now verifies at startup that `mcp` resolves inside its own environment and still provides
  `mcp.server.fastmcp`, exiting with code 2 and an actionable message that names the path it loaded `mcp`
  from. The README documents running and installing with a clean interpreter environment, because the same
  inherited `PYTHONPATH` also makes `pip` skip real dependencies.
- **Unbounded `mcp` dependency (`pyproject.toml`, `requirements.txt`)**: `mcp[cli]>=1.2.0,<3.0.0` resolved to `mcp` 2.x on a clean install, where `mcp.server.fastmcp` no longer exists, so the server failed to import and the test suite could not even be collected. Pinned to `<2.0.0`, which keeps the v1 import path this code targets.
- **Service status queried the wrong module (`tools/system.py`, `resources.py`)**: `sophos_get_service_status` and the `sophos://services/status` resource read the `Services` module, which returns service *definitions* (AH, AOL, HTTP…), so the documented operational state was never returned. They now read `SystemServices` (AntiVirus, IPS, DNSServer, WebProxy, WAF…) as verified against SFOS 22.
- **Nested API errors returned as data (`client.py`)**: SFOS nests `<Status code="529">` *inside* the echoed tag, so `send_request` only inspected the top-level status and the raw error came back as a successful payload. Errors are now detected anywhere in the response tree, which makes `sophos_get_system_info` fail with an explicit, actionable message instead of raw XML.
- **Credential material leaked to callers (`client.py`)**: `get_tag` returned the `<Interface>` `Username` and `Password` (PPPoE credentials) verbatim. Credential-bearing keys are now stripped from every `Get` payload, with a per-tag denylist for `Username` on `Interface` only, so `sophos_list_users` keeps its identifier field.

## [0.2.0] - 2026-07-27

### Changed
- **Secure Default SSL Verification (`client.py`)**: Updated `SophosFirewallClient` to default `verify_ssl` to `True` (`SOPHOS_VERIFY_SSL` defaults to `"true"`). Ensures TLS certificate validation by default, allowing explicit override (`SOPHOS_VERIFY_SSL=false`) for lab/testing environments.
- **Destructive Tool Safety Metadata (`server.py`)**: Set `destructiveHint=True` on `sophos_raw_api_request` tool annotation to ensure MCP client UIs request explicit user confirmation before running raw XML mutations.

### Fixed
- **Module Import Event Loop Safety (`server.py`)**: Refactored semantic tool router initialization to lazy async loading (`get_initialized_router()`). Resolves `RuntimeError: asyncio.run() cannot be called from a running event loop` when importing the server module within an existing event loop.
- **Code Cleanliness (`client.py`)**: Removed unreachable duplicate `return` statement in `send_request()`.

## [0.1.5] - 2026-07-27

### Added
- **Generic Low-Level API Tool (`raw_api.py`, `server.py`)**: Added `sophos_raw_api_request` to allow LLMs to execute low-level `Get`, `Set`, or `Remove` SFOS XML operations for any tag (e.g. `Interface`, `DNS`, `DHCP`, `WebFilterPolicy`, `Route`, `Zone`) with arbitrary parameters.
- **NAT Rule Management (`nat_rules.py`)**: Added `sophos_create_nat_rule`, `sophos_update_nat_rule`, and `sophos_delete_nat_rule` tools.
- **Service Object CRUD (`services_objects.py`)**: Added `sophos_delete_service`, `sophos_create_service_group`, and `sophos_delete_service_group` tools.
- **Host Object Deletions (`hosts_objects.py`)**: Added `sophos_delete_ip_host_group` and `sophos_delete_fqdn_host` tools.
- **User Account Deletion (`users_auth.py`)**: Added `sophos_delete_user` tool.

## [0.1.4] - 2026-07-27

### Fixed
- **Tool Router Event Loop (`server.py`)**: Converted `route_tools` to `async def` and replaced `asyncio.run(mcp.list_tools())` with `await mcp.list_tools()`. Fixes `asyncio.run() cannot be called from a running event loop` when tool routing is enabled.
- **Firewall Rule XML Schema (`firewall_rules.py`)**: Included mandatory `PolicyType` (`"Network"`) and `IPFamily` (`"IPv4"`) in top-level `sophos_create_firewall_rule` payload dictionary. Fixes Sophos SFOS API Error `Status 501: Configuration parameters validation failed. InvalidParams: /FirewallRule/PolicyType`.

### Added
- **General Firewall Rule Modification Tool (`firewall_rules.py`, `server.py`)**: Added `sophos_update_firewall_rule` tool to fetch existing rule configuration, update specified properties (e.g. `action`, `log_traffic`, `source_zones`, `destination_zones`, `source_networks`, `destination_networks`, `services`, `status`), clean transaction IDs, and apply updates to Sophos SFOS via `set_tag`.

## [0.1.3] - 2026-07-27

### Fixed
- **Pre-download FastEmbed Model (`Dockerfile`)**: Pre-downloads embedding model weights (`BAAI/bge-small-en-v1.5`) directly into the container image during Docker build step. Eliminates runtime startup downloads over HuggingFace Hub, preventing client connection timeouts (`context canceled`).
- **Log Noise & Startup Resilience (`router.py`)**: Suppressed verbose `httpx`, `httpcore`, and `huggingface_hub` HTTP request log spam during model load. Updated `get_router()` error handling to catch all initialization exceptions and fall back gracefully to standard tool mode.

## [0.1.2] - 2026-07-27

### Fixed
- **Configurable API Version (`client.py`)**: Updated `SophosFirewallClient` to accept an `api_version` parameter (defaulting to `2200.1` for SFOS v22+ compatibility or reading from `SOPHOS_API_VERSION` env var). Fixes Sophos API Error 529 ("There is no API Version").
- **System Information Error Handling (`system.py`, `resources.py`)**: Added graceful handling for error code 529 ("Input request module is Invalid") in `sophos_get_system_info` and `sophos://system/info` when querying unsupported `<SystemInformation>` tags on SFOS appliances.
- **Environment & Deployments (`.env.example`, `docker-compose.yml`, `README.md`)**: Documented and passed `SOPHOS_API_VERSION` across container definitions and configuration files.

## [0.1.1] - 2026-07-27

### Fixed
- **Graceful Optional Dependency Fallback (`router.py`)**: Added `try...except (ImportError, ModuleNotFoundError)` to `get_router()` to catch missing `fastembed` / `numpy` dependencies when `USE_ROUTER=true` is enabled. Instead of crashing server initialization with `ModuleNotFoundError`, it logs a warning and gracefully disables tool routing while serving all 28 standard tools.
- **Dockerfile Package Installation (`Dockerfile`)**: Updated container build to `pip install .[router]` so official Docker images include `fastembed` and `numpy` out of the box for router compatibility.
- **Unit Test Coverage (`tests/test_router.py`)**: Added unit test `test_get_router_missing_fastembed` verifying graceful fallback behavior.
- **Documentation (`README.md`)**: Updated semantic tool routing documentation with explicit instructions for `pip`, `uv`, and `uvx` when using router extras.

## [0.1.0] - 2026-07-27

### Added
- **Initial release** of `sophos-firewall-mcp-server`.
- **Async API Client (`client.py`)**: Built on `httpx.AsyncClient` with XML API request generation and `xmltodict` parsing for Sophos SFOS endpoints (`/webconsole/APIController`).
- **7 Modular Tool Domains (28 Tools)**:
  - System diagnostics, service state, network interfaces (`system.py`).
  - Firewall security policies CRUD and status toggling (`firewall_rules.py`).
  - IP host definitions, network subnets, host groups, FQDN objects (`hosts_objects.py`).
  - TCP/UDP service definitions and service groups (`services_objects.py`).
  - SNAT and DNAT port-forwarding inspection (`nat_rules.py`).
  - User accounts and live session monitoring (`users_auth.py`).
  - IPsec site-to-site tunnels and SSL VPN remote access policies (`vpn.py`).
- **FastMCP Resources & Prompts**: Read-only URIs (`sophos://system/info`, `sophos://interfaces`) and diagnostic prompts (`audit_firewall_rules`, `troubleshoot_connectivity`).
- **Semantic Tool Routing (`router.py`)**: FastEmbed embedding-based tool discovery (`USE_ROUTER=true`).
- **Tier A+ Quality Score**: 100% parameter descriptions, full `ToolAnnotations` safety metadata, and 100% test pass rate audited against the [glama-ai TDQS framework](https://github.com/glama-ai/tool-definition-quality-score).
- **Automated CI/CD & Security Pipelines**: GitHub Actions workflows for testing, linting, SAST security (pip-audit, Semgrep), Dependabot auto-merging, and container publishing to GHCR.
