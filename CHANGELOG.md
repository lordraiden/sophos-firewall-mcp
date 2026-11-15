# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.6.0] - 2026-11-15

**Sophos Firewall 23 support, stated explicitly.** This server implements the **Sophos Firewall 23
(SFOS 23.0) Configuration REST API** (`/api/firewall-config/v1`). The live evidence in this repository
was produced against **SFOS 23.0.0 GA-Build371**; no general firmware compatibility claim is made for
any other SFOS build. It is not the Sophos Central Firewall Management API and not the legacy XML API.

**Breaking: published output field names are unified on camelCase (the Sophos wire names).** 0.5.0
unified the *inputs* on snake_case; the *outputs* were still split — 119 tools published camelCase
because their outputs are projections of the appliance payload, while 23 tools (12 NAT, 8 users and
3 audit tools) published snake_case. Every published output property is now camelCase; for the 119
projection tools that is the wire name, and the three audit composites are camelCase by convention
because they are computed, not projections. The names are
(`pageSize`, `nameContains`, `idOrName`, `servicesOrGroups`, `originalServicesOrGroups`,
`translatedSource`, …). The convention is deliberate and now documented: **inputs are snake_case
because the model writes them, outputs are wire-faithful because the model reads them.** The JSON
request body sent to the appliance is unchanged; the default `pageSize` query value changes from 50
to 10 (see M11 below). Callers that parsed the 0.5.0 snake_case output names must update.

### Fixed

- **M11 — list and audit outputs no longer threaten a model context by default.** Every list tool
  defaults to `page_size: 10`, and the heavy domains (firewall rules, NAT, services) state the
  approximate size of a full page, so a default call no longer returns a 72 KB firewall-rule
  collection (~18,000 tokens) into the context.
- **M12 — firewall and NAT rule objects expose their evaluation `position`.** List outputs carry the
  page offset plus the index; a get-by-id returns `position: null`, because a single object has no
  evaluation order. Evaluation order no longer requires a full `audit_firewall_rules` run.
- **M13 — NAT rules carry a derived `kind`** (`snat` / `dnat` / `unknown`), computed from which
  translation field is populated, because the appliance exposes no discriminator.
- **M14 — one shape for object references across domains.** NAT projections now use the same
  `{"name": …}` reference objects as firewall rules, so one parser works for "the services of a rule"
  in both domains.
- **M15 — the keyset pagination ceiling of `dhcp_lease_list_ipv4` is documented.** The tool exposes no
  undeclared inputs; the description states that only the first page is reachable and that a non-null
  `nextKey` means the list is incomplete.
- **M16 — the four unpaginated list tools return a uniform envelope.** `dhcp_server_list_ipv4/ipv6` and
  `dhcp_relay_list_ipv4/ipv6` return `pages: null` instead of omitting the key, so "empty" is
  distinguishable from "truncated" and a generic pagination loop no longer breaks.
- **L1 — `Pages` field descriptions reach the published `outputSchema`.** `pages.total` is the number of
  **pages** and `pages.items` the number of **items**; the ambiguity that made `total: 12` read as
  "12 addresses" is gone.
- **L3 — the `audit_firewall_rules` description matches the finding shape.** Object-scoped findings
  (`unused-object`) carry the object and leave `ruleName` / `ruleId` / `position` null, which the
  description now says.
- **L6 — the epoch sentinel is mapped to `null`.** Built-in objects no longer report
  `createdAt` / `updatedAt` as `1970-01-01T00:00:00Z`; the appliance's "never" sentinel becomes `null`,
  as the DNS settings fix already did for the empty string.
- **L7 — the duplicated payload is documented.** Every result carries the JSON in a `TextContent` block
  and the same object in `structuredContent`; the duplication is the MCP SDK's single-argument
  convention, so it is documented rather than silently changed.
- **L8 — `dhcp_lease_list_ipv4` `pages.maxSize` is documented as the item count**, not a page-size
  bound, so `maxSize: 21` no longer reads as a limit of 21 items per page.
- **L9 — the 1000-item ceiling of `ipsec_live_connection_list_ipv4` is documented**, because the tool
  takes no arguments and a larger set would be silently truncated.
- **L10 — `ipsec_remote_access_settings_get` explains the unset state.** An all-null object with
  `connectionState: "unset"` is described as "not configured" instead of leaving the agent to infer it.
- **M9 — the `dhcp_relay_get_ipv4` 401 quirk is documented.** The appliance answers `401` for a UUID
  that does not exist, unlike every other get tool's `404`; the description says so, so an agent does
  not conclude that the API key is broken.
- **M10 — the `request` argument wrapper is documented.** The wrapper is the SDK's single-argument
  convention; the descriptions now state it instead of leaving the agent to discover it from a
  validation error.

### Known limitations

- **Firmware compatibility is limited to the tested build.** The live evidence applies to **SFOS 23.0.0
  GA-Build371** only. The Configuration REST API exposes no version endpoint, so the server cannot
  detect the firmware and makes no claim for other SFOS builds, including later 23.0 maintenance
  builds and SFOS 24.
- **Live write validation is limited** to the object kinds exercised on the lab appliance; ambiguous
  write reconciliation, a real `403` denial, bulk delete and interface/VPN mutations remain unverified.
- **Accepted regressions** are unchanged: no system information, no service status and no log query,
  because the Configuration REST API exposes no endpoint for them.
- **Audit tools are configuration analysis, not packet tests**; `explain_connectivity` reports
  `method: config-analysis` and `not-verifiable` when the configuration lacks the evidence.
- **Pagination is one page per call**; the server never fetches every page automatically.

## [0.5.0] - 2026-11-15

**Breaking: input parameter names are unified on snake_case.** The 0.4.0 surface published two
conventions (measured on the published `request` objects: 74 camelCase-only, 55 snake_case-only, 5
mixed, 6 single-word-only and 12 parameterless tools). Every tool now publishes
snake_case parameters (`page_size`, `name_contains`, `id_or_name`, `rule_type`, `reference_item`, …);
the JSON body sent to the appliance is unchanged because each field keeps its wire alias. Callers that
hard-coded `pageSize`/`nameContains`/`idOrName` must update. The published input schemas also gain
`additionalProperties: false`, so an unknown argument is rejected instead of ignored.

### Fixed

- **`explain_connectivity` no longer returns a false verdict when a rule's service criterion does not
  match** (blocker): a rule is decisive only when every projected criterion matches; the same guard
  applies to NAT rules.
- **`audit_firewall_rules` no longer reports in-use objects as unused** when `ip_family` restricts the
  scan: the reference scan reads both families.
- **`explain_connectivity` models the WAN gateway as the default route**, so internet destinations are
  no longer reported as `no-route`.
- **`service_list`'s `type` filter now works client-side** instead of being a silent no-op.
- **HTTP 401 is reported as an authentication failure**, not as a permission problem; 403 keeps the
  authorization message.
- **`network_user_create`/`update` send `group` as a `{"name": …}` reference**, so creating a network
  user no longer fails with 400.
- **Built-in and list-returned identifiers are accepted** (`##ALL_RW`, names containing `/`).
- **Audit findings are sorted by severity before truncation**, built-in objects are excluded from
  `unused-object`, `rule_name_contains` narrows the report, and `not-verifiable` outputs include the
  candidate rules and the missing evidence.
- **Validation errors no longer leak internal model names or pydantic URLs.**
- **`live_user_list` no longer names a tool that is not registered in read-only mode.**

### Known limitations

- Output field naming is still split (NAT/users snake_case, other domains camelCase); it will be
  unified in a later release.
- The remaining dogfooding findings (M9–M16, L1, L3, L6–L10) are recorded in
  `docs/live-evidence/phase-4-feedback.md` and deferred.

## [0.4.0] - 2026-11-15

**Breaking: REST-only.** The server now speaks the **Sophos Firewall Configuration REST API**
(`https://<host>:<port>/api/firewall-config/v1`, Bearer API key) and nothing else. The XML API
transport, the XML credentials, the raw XML tool, the semantic tool router and the FastEmbed
dependency are removed; there is no compatibility mode and no XML fallback. Tool names, inputs and
outputs are new, so every existing client configuration and every saved tool call must be updated.

### Breaking changes

- **XML transport removed.** `SOPHOS_USERNAME`, `SOPHOS_PASSWORD` and `SOPHOS_API_VERSION` are no
  longer read, `/webconsole/APIController` is no longer called, and `xmltodict` is no longer a
  dependency. Authentication is a single Bearer API key (`SOPHOS_API_KEY` or `SOPHOS_API_KEY_FILE`).
- **Tool surface replaced.** The 28 XML-era `sophos_*` tools are gone. The server now registers
  **152 typed tools across 11 domains** (145 audited operations plus 7 composite tools), named by
  domain (`firewall_rule_*`, `nat_rule_*`, `address_*`, `service_*`, `network_user_*`,
  `live_user_*`, `ipsec_*`, `sslvpn_*`, `network_interface_*`, `zone_*`, `gateway_*`,
  `unicast_route_*`, `sdwan_route_*`, `dhcp_*`, `dns_*`, `static_neighbor_*`,
  `network_status_*`, `audit_firewall_rules`, `explain_connectivity`, `find_object_usage`).
- **Raw API tool removed.** There is no replacement: no tool accepts a URL, path, HTTP method,
  header or arbitrary payload. Operations outside the audited surface are not reachable.
- **Semantic router removed.** `USE_ROUTER` / `TOOL_ROUTING`, the `route_tools` and
  `call_routed_tool` meta-tools, the `router` extra and the FastEmbed model download are gone. The
  full tool list is always advertised.
- **Prompts and resources removed.** The `sophos://` resources and the guided prompts are not part
  of the REST surface.
- **Packaging.** `pyproject.toml` + `uv.lock` are the single dependency source; `requirements.txt`
  and `requirements-dev.txt` are removed. Runtime dependency is `mcp>=2.3.0,<3`.

### Added

- **Typed REST client** (`client.py`, `config.py`, `errors.py`): one shared `httpx.AsyncClient`
  created in the MCP lifespan and closed exactly once; HTTPS base URL built from a validated bare
  host; Bearer key held as `SecretStr`; TLS verification on by default with optional
  `SOPHOS_CA_BUNDLE`; explicit timeouts; no inherited proxy; no cross-origin redirects; bounded
  read retries (connect/read timeouts and 502/503/504 only) and **no retry of writes**, which raise
  an ambiguous-write error instead.
- **MCP foundation** (`server.py`, `context.py`, `tools/__init__.py`): `MCPServer` with
  `subscriptions=False`, STDIO transport, logs on `stderr`, a single `AppContext`, and a registration
  contract shared by every domain.
- **Eleven tool domains**: firewall rules (16), NAT rules (12), addresses and groups (37), services
  and service groups (10), network users (6), live users (2), IPsec VPN (11, read-only), SSL VPN
  (9, read-only), network architecture (44, read-only plus three VLAN-only interface writes),
  network status (2, read-only) and audit (3, read-only composite tools).
- **Read-only mode** (`SOPHOS_READ_ONLY_MODE=true`): mutation tools are not registered at all, so
  discovery advertises 98 tools and zero mutations.
- **Deterministic coverage matrix** (`scripts/generate_coverage.py`, `docs/API-COVERAGE.md`): every
  operation of the checked-in OpenAPI contract is classified, with the tool that exposes it or the
  reason it is excluded; the generator is SHA-gated to the audited contract.
- **Live evidence protocol** (`docs/live-evidence/`): opt-in, read-only `pytest -m live` runs and a
  documented per-domain evidence format.
- **Release documentation** (`docs/release/RELEASE-0.4.0.md`): release notes, rollback plan and the
  gate-B publication checklist.

### Changed

- **Pagination is explicit and bounded.** Listings return one page per call (`page`, `pageSize`,
  `pageTotal` where the contract declares them); `page >= 1` and `1 <= pageSize <= 100` are
  validated client-side. The server never auto-paginates.
- **PATCH follows JSON Merge Patch (RFC 7396)** with `application/json`, as the contract documents;
  omitted properties keep their persisted values. The four documented array exceptions are recorded
  in `docs/API-COVERAGE.md` and are outside the v1 surface.
- **Errors are sanitized.** Anticipated failures raise `ToolError` with a short message; raw remote
  bodies, stack traces and secrets are never returned to the model.
- **Outputs are typed DTOs with an object root**, not raw Sophos payloads, and are bounded.

### Removed

- XML transport, XML credentials, `xmltodict`, the raw XML tool, the semantic router, the FastEmbed
  model download, the `router` extra, the MCP resources and prompts, and the stale
  `requirements.txt` / `requirements-dev.txt` duplication.

### Fixed

- **Known dependency advisories in the locked runtime resolution.** `pip-audit` against
  `uv export --locked --no-dev` reported 19 advisories in three transitive packages (via
  `mcp`/`httpx`): `certifi` 2026.7.22 (PYSEC-2026-4320), `cryptography` 49.0.0 (PYSEC-2026-3552) and
  `pyjwt` 2.13.0 (PYSEC-2026-4140…4152, 4183, GHSA-pxh4-856f-4h89). They are bumped to
  `certifi` 2026.10.23, `cryptography` 50.0.2 and `pyjwt` 2.15.1; the audit now reports no known
  vulnerabilities. No `pyproject.toml` constraint blocked the fix.

### Accepted regressions

The REST contract does not expose these capabilities, so they are not migrated and no placeholder
tool is advertised:

- **System information** — appliance model, serial number, firmware version and uptime. The contract
  has no endpoint for them (`getSystemSettings` returns only `hostname`, `loginDisclaimer` and
  `updatedAt`).
- **Service status** — there is no REST endpoint that returns the running state of system services.
- **Log query** — log destinations can be configured, but logs cannot be read through this API.

### Known limitations

- **Target firmware build is unknown.** The contract exposes no version endpoint, so no firmware
  compatibility is claimed; verify against your own appliance.
- **No live write validation.** The shared lab credential is read-only, so no POST, PATCH or DELETE
  has been executed against a real appliance. Write tools are covered by contract tests only.
- **Audit tools are configuration analysis**, not packet tests; they report `not-verifiable` when
  the configuration does not contain enough evidence.

## [0.3.0] - 2026-10-28

Breaking: requires `mcp>=2`, which renamed `FastMCP` to `MCPServer` and moved the import to
`mcp.server.mcpserver`. `SophosPartialResultError` is new and partial results (201, 203, 211-215) now
raise instead of returning as success, so a caller that treated them as applied will see an exception.
Everything else below is additive or fixes a wrong answer.

## [0.3.1] - 2026-10-28

Every tool failure now names itself (see #21). Patch release: no API change, only that a failure which
used to arrive as `Error executing tool <name>: ` with an empty message now carries the exception type,
its text and a traceback in the server log.

## [Unreleased]

> **Superseded by 0.4.0.** The entries below describe XML-era code that the REST migration deleted
> (`_guard.py`, the XML client, `resources.py`, `prompts.py`, the XML domain modules). They are kept
> for history only and will not ship. The one entry that still applies is the upstream sync policy.

### Added
- **Documented upstream sync policy (`docs/UPSTREAM-SYNC.md`, `scripts/sync-upstream.sh`)**: this fork is the
  maintained copy, so `main` carries the fixes and is never rewritten; upstream arrives as a merge
  commit. The script fetches, reports what is missing, and merges — refusing to run on a dirty tree
  and never rebasing, force-pushing or resolving conflicts on its own.

### Fixed
- **A failure with an empty message reached the model as a bare colon (`_guard.py`, `server.py`)**: the MCP
  SDK formats tool failures as `Error executing tool <name>: <exc>`, and `str(TimeoutError())` is the empty
  string — so an unguarded exception arrived as `Error executing tool sophos_list_firewall_rules:` with
  nothing after it, indistinguishable from a dead process. Upstream confirmed (hermes-agent#145923) that the
  empty text is born in the server, not the client. Every registered tool is now wrapped: unexpected
  exceptions are logged with their traceback and re-raised as `SophosAPIError` naming the type and the
  elapsed time, `SophosAPIError` passes through, and cancellations still propagate untouched. The next
  occurrence names itself instead of asking the question a third time.
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
