# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.8.0] - 2026-11-17

**Minor release: the four highest-blast-radius deletes now require a client confirmation and fail
closed, the published tool surface is selectable by domain, and the server enforces its own
invocation rate.** No tool is renamed, no argument is removed and the wire body is unchanged for
every call that already worked. The surface stays at **112 tools** (74 read-only / 38 mutations; 26
destructive / 12 additive), and the `tools/list` catalog drops from 627,848 to **493,965 bytes**
(−21.3%). Five changes are visible to a client or an operator and are called out as behaviour
changes below: the confirmation gate, the exact SDK pin, the JSON-RPC error codes, the Compose
defaults and the invocation rate limiter. The release closes the 0.8.0 items of the 0.7.0 MCP
standards review and the follow-up issues filed against it.

### Added

- **`SOPHOS_TOOL_DOMAINS` selects the published tool surface.** A comma-separated
  allowlist of `firewall`, `nat`, `objects`, `users`, `network` and `audit`. Unset keeps the complete
  112-tool surface, so an existing deployment is unaffected; a set value publishes only the tools of
  the named domains. The value is a closed allowlist — an unknown identifier, an empty entry or a
  duplicate is rejected at startup with a message naming the accepted identifiers, never silently
  ignored. Order does not matter (`audit,firewall` and `firewall,audit` publish the same catalog), and
  the three audit composites are self-contained, so `SOPHOS_TOOL_DOMAINS=audit` works on its own. The
  resources, the prompts and `serverInfo.instructions` now describe the surface that is actually
  registered instead of the full catalog: a prompt is registered only when every tool its workflow
  names is present, and `sophos://api/surface` reports the filtered set. Measured live in read-only
  mode: 74 tools with the variable unset, 47 with `network`, and 4 with `firewall,nat`.
- **A server-side invocation rate limiter** (behaviour change). The `2026-07-28` Tools specification
  requires servers to rate limit tool invocations; 0.7.1 recorded that as a risk acceptance, and this
  release implements it. A token bucket sits in the outermost middleware position and bounds
  `tools/call` requests: `SOPHOS_INVOCATION_RATE_PER_MINUTE` (default `60`, range 1–6000) is the
  sustained rate and `SOPHOS_INVOCATION_BURST` (default `10`, range 1–1000) is the bucket depth. A
  throttled call fails fast with an actionable `isError` result naming the limit and the retry delay
  instead of queueing, so a runaway client cannot build an unbounded backlog. A composite counts as
  one invocation, and an MRTR resume counts as one too. The limiter runs before the MRTR replay guard,
  so a throttled resume does not consume the single-use confirmation and the client can retry once the
  bucket refills. The policy, the threat model and the concurrency-versus-rate distinction are in
  [`docs/SECURITY-RATE-POLICY.md`](docs/SECURITY-RATE-POLICY.md).
- **`tests/test_sdk_compat.py` and a CI compatibility matrix.** The suite fails with a diagnostic
  naming the attribute that moved when any of the four private SDK surfaces the server depends on
  changes, when the declared dependency is not the exact verified pin, or when the installed SDK is
  not the verified release. It also proves the behaviour the seam exists for still works end to end:
  flat arguments, a closed argument model, a root union of closed variants, and a real invocation
  reaching the handler on all three argument-model branches. The `test` job gains a
  `python-version` × `mcp-version` matrix that installs the pinned release explicitly, and a
  `clean-install` job that builds the wheel, installs it into a throwaway environment and checks that
  a clean install resolves the pinned SDK and still registers a non-empty tool surface.
- **`scripts/measure_catalog.py` and [`docs/CATALOG-SIZE.md`](docs/CATALOG-SIZE.md).** The catalog is
  measured as the raw JSON-RPC `tools/list` response line over STDIO, split four ways (input schemas,
  output schemas, descriptions, envelope), so the size claim is reproducible on any commit instead of
  being a one-off number.
- **`scripts/docker_stdio_smoke.py`.** The container smoke test now drives a real STDIO session and
  synchronises on protocol responses instead of sleeping and hoping, so a slow image start can no
  longer produce a false green or a flaky red.
- **A single-use guard for the sealed MRTR `requestState`** (`src/sophos_firewall_mcp/mrtr.py`). The
  SDK verifies a resumed state's integrity, envelope, expiry, digest, audience and principal, but it
  does not track consumption, so the same sealed state could be replayed. The guard records the first
  `tools/call` carrying a given token and refuses a second use with `-32602` before the boundary
  unseals it and before any handler runs. Only accepted states are remembered, so a forged token never
  consumes a slot, and the cap fails closed rather than evicting a live entry.

### Changed

- **The four gated deletes now require a client confirmation and fail closed** (behaviour change,
  **breaking for non-interactive clients**). `firewall_rule_delete`, `nat_rule_delete`,
  `network_user_delete` and `network_interface_delete_vlan` now require the client to answer a
  confirmation through the SDK's `Resolve`/`Elicit` mechanism before the appliance is touched. 0.7.1
  documented the gate as best-effort: it fired on the legacy handshake path and was skipped, with a
  logged warning, on the `2026-07-28` per-request path. It is now a real precondition on both eras. A
  client that cannot answer — no `elicitation` capability, a `url`-only client, or a transport with no
  back-channel — is **refused**, and nothing is deleted. A declined or cancelled answer aborts the
  call with a `ToolError`. This is the release's one breaking change: a non-interactive client that
  used to delete unconfirmed must now either declare form-mode elicitation or stop calling these four
  tools. The other 34 mutations are unaffected.
- **`mcp` is pinned to exactly `2.3.0`** (behaviour change, install-time). The declared dependency was
  `>=2.3.0,<3`; it is now `mcp==2.3.0`. The server depends on four attributes the SDK does not expose
  publicly, and a different release may rename, move or remove any of them without a clean import
  error — registration would still succeed and every tool would silently fall back to the SDK's
  default `request`-wrapped, open argument model. The range is therefore the one release that was
  actually tested. A deployment that pinned a different 2.x release will now fail to resolve instead of
  running untested; the widening procedure is in
  [`docs/SDK-COMPATIBILITY.md`](docs/SDK-COMPATIBILITY.md).
- **Unknown tools and invalid prompt requests return JSON-RPC `-32602`** (behaviour change, protocol).
  An unknown tool name, an unknown prompt name, missing or invalid prompt arguments, and a
  caller-fixable render failure are now reported as *invalid params* instead of *internal error* or an
  `isError` result, matching the specification's error classes and the existing `resources/read` path.
  A genuine renderer failure still returns `-32603`. Measured over STDIO: an unknown tool returns
  `-32602` and an unknown prompt returns `-32602`.
- **The catalog is 21.3% smaller.** `tools/list` is **493,965 bytes** (was 627,848), roughly 123k
  tokens at ~4 bytes per token. The split is input schemas 191,630, output schemas 242,915,
  descriptions 38,399 and envelope 21,021. The trim removes two JSON Schema annotations from the
  published `outputSchema` — the repeated model docstrings and field descriptions (the same `ObjectRef`
  definition appeared 64 times and `Pages` 33 times) and the response-only `default` — which takes the
  output schemas from 376,788 to 242,915 bytes (−35.5%). It is annotation-only: `required`,
  `properties`, `type`, `enum`, `const`, `format`, `$ref`, `anyOf`/`oneOf`, `additionalProperties`,
  nullability and aliases are untouched, and the SDK still validates `structuredContent` against the
  output model. `Pages` and `FirewallRuleOutput` keep their field descriptions because they document
  the `total`/`items` trap and the 1-based position. The tool count and every tool name are unchanged.
- **`tools/list` is not paginated.** The protocol supports `nextCursor`, but the pinned SDK's
  `MCPServer` accepts `PaginatedRequestParams` and discards it, and exposes no public hook to supply a
  page. The server does not fake partial results; the limitation and the smallest upstream-compatible
  path are documented in [`docs/CATALOG-SIZE.md`](docs/CATALOG-SIZE.md), and a test pins the
  single-page behaviour so it fails when the SDK grows a supported hook.
- **`destructiveHint` and `idempotentHint` are pinned for all 38 mutations.** The two hints were
  correct per tool but not governed by a stated policy, so the same operation class could drift apart
  again. A centralized annotation policy now classifies every mutation — 26 destructive, 12 additive —
  and a 38-row regression table pins each tool's pair, failing with a diagnostic that names the stale
  row. The read-only tools are unchanged.
- **Sixteen getter descriptions describe the payload they return.** The `*_get` tools published a
  description of the *request* and said nothing about the response, so a model had to call one to learn
  its shape. Each now names the object it returns and the fields that matter. The union tools state
  which selector field chooses the variant, `mac_address_create` publishes one message for its
  mutually-exclusive `macAddress`/`macAddresses` pair instead of two competing ones, and several
  published input names that had drifted to camelCase are corrected to snake_case.
- **The package description no longer embeds a tool count** (behaviour change, metadata). The
  `pyproject.toml` summary said "152 typed tools" against a 112-tool surface. It now describes the
  domains instead, and `serverInfo.description` publishes the installed distribution's metadata
  verbatim, so the two cannot disagree. A drift test compares the published description with
  `project.description`.
- **Compose defaults to read-only** (behaviour change, deployment). `docker-compose.yml` now defaults
  `SOPHOS_READ_ONLY_MODE` to `true`, so the reference deployment publishes 74 tools and cannot write
  until an operator sets it to `false` explicitly. It passes `SOPHOS_MAX_CONCURRENCY` through, and it
  deliberately declares **no `restart` policy**: the MCP client owns the process lifecycle, so a
  restart would only re-spawn a server whose `stdin` is gone. The supported invocation is one container
  per session, `docker compose run --rm -T sophos-firewall-mcp`, where `-T` disables the pseudo-TTY
  that would otherwise corrupt the JSON-RPC stream.
- **The GitHub repository description no longer claims 152 tools.** It matches the package metadata:
  the domains, not a count that goes stale on every surface change.

### Fixed

- **A cancelled destructive write keeps its confirmation consumed.** The single-use guard released the
  reservation on any exception, including `asyncio.CancelledError`. A cancellation can arrive after the
  request reached the appliance, so the write may have landed; releasing the state made an ambiguous
  write replayable, and a retry could delete a re-created object of the same name without a fresh
  confirmation. The reservation is now released only for an `MCPError` raised by the SDK boundary
  before the handler runs — the one case where the state was provably never accepted. A handler
  failure is returned as a `CallToolResult` rather than raised, so a legitimate state whose handler
  failed stays consumed.
- **Legacy handshakes return `-32603` for a genuine prompt-renderer failure.** On the legacy
  `initialize` path a renderer exception was mapped to JSON-RPC `code=0`, which is not a valid error
  code and which a client cannot classify. It is now `-32603` (internal error), matching the modern
  path. A caller-fixable failure on the same path is still `-32602`.
- **The Docker STDIO smoke test no longer races the server.** It waited a fixed interval and then
  asserted, so a slow image start produced a flaky failure and a fast one could pass before the server
  had answered. It now reads until it has the protocol response it is waiting for, with a bounded
  timeout.
- **The published metadata matches the installed package.** `serverInfo.description` is read from the
  installed distribution instead of being assembled from a stale editable install, so a development
  checkout can no longer advertise a surface it does not register.

### Security

- **Destructive deletes fail closed.** The four gated deletes refuse the call when the client cannot
  answer the confirmation, instead of proceeding unconfirmed. A non-interactive client can no longer
  delete a firewall rule, a NAT rule, a network user or a VLAN interface by accident or by prompt
  injection: the confirmation is a precondition, not an affordance.
- **A sealed confirmation cannot be replayed.** The single-use guard refuses a second use of the same
  `requestState` with `-32602` before the boundary unseals it, so a client that retries on timeout
  cannot execute the confirmed delete twice, and a captured state cannot delete a re-created object of
  the same name. Only accepted states are remembered, so a flood of forged states cannot displace a
  legitimate one — the cap fails closed.
- **Tool invocations are rate limited.** The `2026-07-28` specification's *Security Considerations*
  require servers to rate limit tool invocations. The token bucket bounds a runaway loop, a prompt
  injection or a buggy agent to `SOPHOS_INVOCATION_RATE_PER_MINUTE` sustained with a
  `SOPHOS_INVOCATION_BURST` burst, and fails fast rather than queueing. This supersedes the risk
  acceptance recorded in 0.7.1 (issue #63), which is retained in
  [`docs/SECURITY-RATE-POLICY.md`](docs/SECURITY-RATE-POLICY.md) as the rationale for the design.
- **The SDK dependency is an exact pin.** `mcp==2.3.0` removes the window in which a resolver could
  install an untested release that silently degrades every tool's argument model, and the
  compatibility test fails loudly if the pin, the installed release and the startup guard ever
  disagree.

### Known limitations

- **The confirmation gate requires a client that can answer it.** A client that declares no
  `elicitation` capability, a `url`-only client, or a transport with no back-channel is refused on the
  four gated deletes. That is the intended fail-closed behaviour, but it means a non-interactive
  automation client cannot use those four tools at all; it must use a client that supports form-mode
  elicitation.
- **`tools/list` is one page.** The pinned SDK's `MCPServer` discards the pagination cursor and exposes
  no public hook to supply a page, so the server cannot paginate without a private override. The
  mitigations are the cache hint, read-only mode, domain selection, the resources and the prompts.
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

## [0.7.1] - 2026-11-16

**Patch release: the High finding and the cheap findings of the 0.7.0 MCP standards review are
closed.** No tool is renamed, no argument is removed and the wire body is unchanged for every call
that already worked. One input becomes required — `nat_rule_create`'s `position`, which the appliance
already rejected a create without — and the four gated delete descriptions now state the
confirmation's real scope instead of promising a question that cannot be asked on the protocol era
the server advertises. The findings are
in [`MCP-STANDARDS-REVIEW-0.7.md`](docs/architecture/sophos-rest-api-redesign/MCP-STANDARDS-REVIEW-0.7.md).

### Changed

- **`nat_rule_create` now requires `position`** (behaviour change). The appliance rejects a create
  without it with `400 invalidRequest` ("Invalid position.") for both families and every
  match/translation variant, although the OpenAPI document does not list it as required. 0.7.0
  published it as optional and the adapter omitted it, so every create that did not send `position`
  failed with a generic `400`. It is now a required input on both variants, like
  `firewall_rule_create`, and the adapter always sends it: `top`, `bottom`, `after` or `before`, with
  `after`/`before` still requiring `reference_item`. A caller that omits it gets a clear argument
  error before any request is sent. This is the only input-contract change in 0.7.1.

### Fixed

- **H1 — the four gated delete descriptions are honest about the confirmation.**
  `firewall_rule_delete`, `nat_rule_delete`, `network_user_delete` and
  `network_interface_delete_vlan` now say the confirmation is **best-effort**: it fires on the legacy
  handshake path, where the transport can carry a server-initiated request, and is skipped on the
  `2026-07-28` per-request path, where the client's own confirmation UI is the only gate.
  `confirm_destructive` logs a `WARNING` naming the action and the target when the skip happens, so an
  operator can see a delete that ran without the question. The MRTR `InputRequiredResult` round trip
  that would make the gate work on both eras is deferred to 0.8.0.
- **M1 — `destructiveHint` is consistent for the PATCH-merge updates.** All eleven update tools
  publish `destructiveHint: true`; the nine object, user and VLAN updates were `false` while the two
  rule updates were already `true`. A JSON Merge Patch overwrites stored values, so it is not an
  additive update, and the same operation class is no longer classified two ways.
- **M2 — one shared `ip_family` description.** Every required `ip_family` publishes the same sentence
  — *"IP family of the collection: 'ipv4' or 'ipv6'. Required: the two collections are separate, so
  the family is never inferred."* — on the 32 tools that require it (including the six firewall tools,
  which published no description at all) and on the 8 union tools that carry it (22 variant
  definitions). The three audit composites keep their own optional description, where omitting the
  field means "both families".
- **M3 — `serverInfo.description` publishes the real tool count.** The description substitutes the
  number of tools the server actually registered (112, or 74 in read-only mode) instead of the
  installed distribution's summary, so a stale editable install can no longer publish "152 typed
  tools" against a 112-tool surface. A drift test compares the published description with
  `project.description` in `pyproject.toml`.
- **M4 — `prompts/get` returns `-32602` for a caller-fixable failure.** An unknown prompt, missing or
  invalid arguments, or a render failure is reported as invalid params instead of an internal error,
  matching the specification's prompts error handling and the `resources/read` path.
- **M5 — `elicitation: {}` counts as form-mode support.** The specification defines the empty
  capabilities object as equivalent to declaring form mode, so the confirmation gate now fires for
  that client generation instead of treating it as unable to answer. A `url`-only client is still not
  asked, because it cannot answer a boolean question.
- **M7 — a bad union selector is reported by name.** `address_create` with `ip_family: "ipv5"` now
  reports `ip_family must be one of 'ipv4', 'ipv6'` instead of "type is required", because the union
  error names a selector field the caller actually sent with a value no variant accepts. The
  `address_create` description also states that `type` selects the variant and must match
  `ip_family`.
- **L5 — `annotations.title` is dropped.** The tool-level `title` already wins the specification's
  display precedence, so the duplicate string is no longer published on any of the 112 tools.
- **L7 — `INSTRUCTIONS` names the resources and prompts.** A model that reads only `instructions` now
  learns that `sophos://conventions` exists and that `audit_firewall`, `explain_flow` and
  `find_unused_objects` carry the three analysis workflows.
- **L9 — the elicitation schema is plain prose.** The confirmation form's
  `requestedSchema.description` is user-facing text instead of the internal
  `_DestructiveConfirmation` docstring.
- **L10 — the six IPv4-only IPsec tools say so.** `ipsec_connection_list_ipv4`,
  `ipsec_live_connection_list_ipv4`, `ipsec_policy_based_connection_get_ipv4`,
  `ipsec_policy_based_connection_list_ipv4`, `ipsec_route_based_connection_get_ipv4` and
  `ipsec_route_based_connection_list_ipv4` now state "The API has no IPv6 counterpart", so a model
  does not look for an `_ipv6` sibling that does not exist.

### Known limitations

- **The MRTR round trip is 0.8.0.** The confirmation still cannot fire on the `2026-07-28`
  per-request path: `mcp` 2.3.0 refuses a standalone server-to-client request there, and the
  specification's `InputRequiredResult` round trip would change every handler signature. 0.7.1 makes
  the limitation visible — the descriptions say it and the skip is logged — instead of leaving it
  silent; the real fix is scheduled for 0.8.0.
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

## [0.7.0] - 2026-11-16

**Breaking: the IPv4/IPv6 tool pairs collapse behind a required `ip_family`, and tool arguments are
published flat.** The surface drops from 152 tools to **112** (107 one-to-one + 5 composites; **74
read-only / 38 mutations**), and the `tools/list` catalog from 807,920 to **622,787 bytes**. Both
changes break a client that hard-coded a family-specific tool name or wrapped its arguments in
`request`; the migration table is in
[`docs/architecture/sophos-rest-api-redesign/MIGRATION-0.7.md`](docs/architecture/sophos-rest-api-redesign/MIGRATION-0.7.md).

### Breaking changes

- **One tool per concept, with a required `ip_family`.** The 40 IPv4/IPv6 pairs
  (`firewall_rule_list_ipv4` / `_ipv6`, `address_create_ipv4` / `_ipv6`, …) are now 40 merged tools
  that take a required `ip_family` (`ipv4` | `ipv6`), matching the three audit composites, which
  already took it. 80 tool names are removed; the migration table maps every one to its new tool and
  `ip_family` value. The argument is **required, not defaulted**: a default would make a destructive
  target (delete, update, move, enable/disable, clone) a guess and would hide which family a read
  returned. The three audit composites keep their optional `ip_family` because they are read-only and
  can span both families. The wire body is unchanged: the adapter strips `ip_family` and selects the
  IPv4 or IPv6 path, so `firewall_rule_create` with `ip_family: "ipv4"` sends exactly the body
  `firewall_rule_create_ipv4` sent before. The output **payload** for a given family is unchanged;
  the published output **schema** is the union of both families, so 40 of the 80 merged pairs publish
  a wider schema (e.g. `address_get` publishes 8 address variants instead of 4). A client that
  generates types from `outputSchema` must regenerate them.
- **Tool arguments are published flat.** Every tool that takes arguments now publishes the request
  model's own fields at the top level of `inputSchema`; the `request` wrapper is gone from all 112
  tools. 0 tools publish a `request` property, the published input surface drops from 222,419 to
  199,114 bytes (−10.5%), and the wrapper sentence is gone from every description. A tool whose
  request is a union of shapes publishes a root `oneOf` of the closed variants (`address_create`,
  `firewall_rule_create`, …), because flattening a union into one object would lose the per-variant
  required fields; `mac_address_create` publishes `anyOf` because the API declares no discriminator.
  The handler, its signature and the wire body are untouched; the closed argument
  model (`additionalProperties: false`) and the sanitized errors are unchanged, and an unknown
  argument is still rejected by name.

### Added

- **Confirmation for the four highest-blast-radius deletes.** `firewall_rule_delete`,
  `nat_rule_delete`, `network_user_delete` and `network_interface_delete_vlan` ask the client to
  confirm before the appliance is touched, through the MCP elicitation capability. The question names
  the object and the rule base; a declined or cancelled answer aborts the call with a `ToolError` and
  nothing is deleted. The affordance is additive, never a new precondition: it is skipped — and the
  delete proceeds exactly as before — when the client declared no `elicitation` capability or the
  transport has no back-channel, which is the normal case for a non-interactive client.
- **`openWorldHint` is set per tool instead of `true` everywhere.** 6 tools publish `true` and 106
  publish `false`. The hint describes the tool's interaction domain, not how much its data can be
  trusted: this server talks to exactly one configured appliance and no tool accepts a URL, host or
  endpoint, so a tool that reads or writes that appliance's own configuration is closed. The 6 open
  tools are the ones whose result is produced by entities the appliance does not own and cannot
  enumerate: `dhcp_lease_list`, `ipsec_live_connection_list_ipv4`, `live_user_disconnect`,
  `live_user_list`, `network_status_cellular_wan` and `network_status_dns_protection`.

### Changed

- **The catalog is 22.9% smaller.** `tools/list` is 622,787 bytes (was 807,920), roughly 156k tokens
  at ~4 bytes per token. The IPv4/IPv6 collapse removed 152,886 bytes (807,920 → 655,034) and 40
  tools; publishing flat arguments removed a further 32,247 bytes (655,034 → 622,787). Each number is
  the raw JSON-RPC `tools/list` response line over STDIO, including the trailing newline, measured on
  `origin/main` (pre-0.7), `b22731a` (after the collapse, before the flatten) and HEAD respectively.
- **The surface is 112 tools** (was 152): 107 one-to-one tools covering 145 audited operations, plus 5
  composites that add no endpoint. 74 are read-only and 38 are mutations; 7 take no arguments and 105
  take arguments. `live_user_list` joins the no-argument set: its request model is deliberately empty,
  so with flat arguments it publishes no properties at all.

### Known limitations

- **Elicitation applies to handshake clients only.** `mcp` 2.3.0 refuses a standalone
  server-to-client request on the modern (`2026-07-28`) per-request path
  (`mcp/server/runner.py:552-593`), so the confirmation is available to a client that negotiated a
  handshake version (`2024-11-05` … `2025-11-25`, the STDIO default) and is silently skipped on the
  modern path. The modern path would need the `InputRequiredResult` round trip that `mcp` 2.3.0 only
  wires for `Resolve` parameters, which would change every handler signature; that is out of scope
  for this release. A non-interactive client is unaffected either way.
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

## [0.6.0] - 2026-11-15

**Sophos Firewall 23 support, stated explicitly.** This server implements the **Sophos Firewall 23
(SFOS 23.0) Configuration REST API** (`/api/firewall-config/v1`). The live evidence in this repository
was produced against **SFOS 23.0.0 GA-Build371**; the Configuration REST API is the same across SFOS
versions, so the tools are not build-specific. It is not the Sophos Central Firewall Management API and
not the legacy XML API.

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
