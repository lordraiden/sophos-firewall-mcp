# MCP standards review — Sophos Firewall MCP Server 0.7.0 (follow-up)

| Field | Value |
|---|---|
| **Reviewer** | `mcp-review07b` (independent; did not write the code) |
| **Date** | 2026-11-16 |
| **Branch** | `docs/live-0.7` |
| **Reviewed HEAD** | `8caa853` — *docs: correct the NAT position finding and record the SFVH model* |
| **Subject** | `sophos-firewall-mcp-server` 0.7.0 — 112 tools (74 read-only, 38 mutations), flat arguments, `ip_family` on the merged tools, elicitation on 4 deletes, 4 resources, 3 prompts, STDIO, MCP `2026-07-28`, Python `mcp` 2.3.0 |
| **Scope** | Follow-up on the 0.7.0 surface against the official Model Context Protocol documentation: annotations, flat arguments and schemas, `ip_family`, elicitation, resources/prompts, catalog/identity, and anything the 0.6.0 review did not cover |
| **Method** | Read `src/`, `tests/`, `docs/`; enumerated the live `tools/list` surface with `create_server(...)`; spoke raw JSON-RPC over STDIO in both protocol eras (modern `_meta` envelope and legacy `initialize`), including elicitation accept/decline and the modern no-back-channel path; measured the wire payload; ran the four gates |
| **Prior review** | [`MCP-STANDARDS-REVIEW.md`](MCP-STANDARDS-REVIEW.md) (0.6.0, `7d2121d`) |
| **Reference docs** | [Tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools), [ToolAnnotations](https://modelcontextprotocol.io/specification/2026-07-28/schema#toolannotations), [Elicitation](https://modelcontextprotocol.io/specification/2026-07-28/client/elicitation), [Multi Round-Trip Requests](https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/mrtr), [Resources](https://modelcontextprotocol.io/specification/2026-07-28/server/resources), [Prompts](https://modelcontextprotocol.io/specification/2026-07-28/server/prompts), [Discovery](https://modelcontextprotocol.io/specification/2026-07-28/server/discover), [Caching](https://modelcontextprotocol.io/specification/2026-07-28/server/utilities/caching), [Client best practices](https://modelcontextprotocol.io/docs/2026-07-28/develop/clients/client-best-practices), [Security best practices](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices) |

---

## Verdict

**Good, with one High finding and seven Mediums.** 0.7.0 is a large, disciplined step: the two High findings of the 0.6.0 review are gone (the `request` wrapper is flattened away on all 112 tools, and the IPv4/IPv6 pairs are collapsed behind a required `ip_family`), the catalog is 34% smaller, the cache hint is real, and the server now publishes the passive-context channel (4 resources) and the workflow channel (3 prompts) it previously only declared. Fourteen of the sixteen roadmap items from the 0.6.0 review are fully closed.

The High finding is the one thing a user will actually feel: **the elicitation gate on the four highest-blast-radius deletes is inert on the only protocol era the server advertises.** On `2026-07-28` a server-initiated `elicitation/create` is not permitted — the spec requires the `InputRequiredResult` round trip — so `ctx.elicit` raises `NoBackChannelError`, the server swallows it, and the delete proceeds. A legacy client that sends `initialize` first does get the confirmation. The four tool descriptions say "When the client supports elicitation the call first asks the user to confirm", which is false on the modern path. The README is honest about this; the model-facing surface is not.

The Mediums are consistency and contract-quality issues, not wire defects: `destructiveHint` is classified two ways for the same PATCH-merge operation class; `ip_family` — the one new argument of 0.7.0 — is undescribed on the six firewall tools and described eight different ways elsewhere; `serverInfo.description` still says "152 typed tools"; `prompts/get` returns `-32603` for an unknown prompt or missing arguments where the spec says `-32602`; the spec's backwards-compatible `elicitation: {}` declaration is treated as "cannot elicit"; the catalog is still ~156k tokens with 60.5% of it optional output schemas; and the union tools do not declare their discriminator, so a bad `ip_family` on `address_create` is reported as "type is required".

**No Critical finding.** The wire behaviour is conformant: `server/discover` works, both eras negotiate correctly, `resultType`/`ttlMs`/`cacheScope` are present on every cacheable method, `resources/read` returns `-32602` for an unknown URI, stdout carries only MCP frames, and every result conforms to its published `outputSchema`.

---

## 1. What changed since 0.6.0

The 0.6.0 review's roadmap, item by item, against the 0.7.0 surface:

| # | 0.6.0 roadmap item | Status in 0.7.0 | Evidence |
|---|---|---|---|
| 1 | Fix the wrong `request` wrapper example | **Closed** — the wrapper is gone entirely | 0 tools publish a `request` property (checked at every depth) |
| 2 | Put the calling convention in `INSTRUCTIONS` | **Closed** | `server.py:140-155` states flat arguments, `oneOf`/`anyOf`, and "read one of them" |
| 3 | Pass `version`/`title`/`description`/`website_url` | **Closed** | `server.py:259-269`; live `serverInfo` carries all five fields |
| 4 | `cache_hints` with a long TTL | **Closed** | `server.py:118-131`; live `ttlMs: 3600000` on all six cacheable methods |
| 5 | Describe `page` and `page_total` | **Closed** | 31 paginated tools, 0 with an undescribed `page` |
| 6 | Document the calling convention and catalog size in `README.md` | **Closed** | `README.md:171-264` |
| 7 | Test that fails on internal markers | **Closed** | `tests/test_tool_surface.py:514`; 0 markers in the live surface |
| 8 | Drop property-level `title`; nullable as `type: [X, "null"]` | **Partial** — 0 property-level titles remain; 507 `anyOf: [X, null]` remain | measured |
| 9 | `report_progress` on the audit walk | **Closed** | `tools/audit.py:2908-2980` passes `ctx.report_progress` |
| 10 | 3–5 resources and 2–3 prompts | **Closed** — 4 and 3 | `resources.py:435`, `prompts.py:220` |
| 11 | Concurrency semaphore | **Closed** | `client.py:148`, `:342-344` |
| 12 | Downgrade `_env_guard` to a warning | **Closed** | `_env_guard.py:1-40` |
| 13 | Collapse the IPv4/IPv6 pairs behind `ip_family` | **Closed** — 152 → 112 tools | measured |
| 14 | Flatten the `request` wrapper | **Closed** | `tools/__init__.py:613-700` |
| 15 | Elicitation for the highest-blast-radius deletes | **Done, with a caveat** — legacy era only | finding H1 |
| 16 | Revisit `openWorldHint` per tool | **Closed** — 6 open, 106 closed | `tools/__init__.py:266-290` |

This is the right way to answer a review: every item is either closed or explicitly accounted for. The follow-up below is therefore about the *new* surface, not about re-litigating the old one.

---

## 2. Findings

### Critical

**None.** I looked specifically for a wire-level defect that breaks a conforming client and did not find one. The modern and legacy eras both work, the cacheable methods carry `ttlMs`/`cacheScope`, `resources/read` returns the spec's `-32602` for an unknown URI, and the result shapes conform.

---

### High

#### H1 — The elicitation gate is inert on the only protocol era the server advertises, and the four delete descriptions say otherwise

**What.** `firewall_rule_delete`, `nat_rule_delete`, `network_user_delete` and `network_interface_delete_vlan` call `confirm_destructive` before touching the appliance (`tools/__init__.py:311-370`). On the modern (`2026-07-28`) path, `ctx.elicit` raises `NoBackChannelError`, which is swallowed at `tools/__init__.py:340-343` and the delete proceeds. The server advertises `supportedVersions: ["2026-07-28"]` and nothing else, so the modern path is the normal case for any client that probes with `server/discover`.

Observed over STDIO:

| Era | Client declares | `firewall_rule_delete` |
|---|---|---|
| modern (`_meta` envelope) | `elicitation: {form: {}}` | **no `elicitation/create`**; the call proceeds to the appliance |
| legacy (`initialize` → `2025-11-25`) | `elicitation: {form: {}}` | `elicitation/create` with the rule name; `decline` → `isError: true`, "delete the firewall rule was declined by the user; nothing was changed" |
| legacy | `elicitation: {}` | **no `elicitation/create`** (see M5) |

The four descriptions still say: *"When the client supports elicitation the call first asks the user to confirm, naming the rule; a declined or cancelled confirmation aborts the call and nothing is deleted."* (`tools/firewall_rules.py:561`, `tools/nat_rules.py:359`, `tools/users_auth.py:416`, `tools/network.py:413`). On the modern path that sentence is false.

**Where.** `src/sophos_firewall_mcp/tools/__init__.py:294-308` (`_client_can_elicit`), `:311-370` (`confirm_destructive`), `:340-343` (the silent `NoBackChannelError` return); the four descriptions above.

**Why it matters.** The confirmation is the server's only safety affordance for an irreversible delete, and the model-facing contract promises it on the protocol the server advertises. A model that reads the description may tell the user "I will ask you to confirm" and then delete without asking. The README's *Known limitations* section is accurate — *"the confirmation is silently skipped there and the delete proceeds exactly as before"* (`README.md:466-472`) — but the model does not read the README, and the skip is not logged, so an operator cannot tell it happened either.

**MCP guidance.**
- [Multi Round-Trip Requests](https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/mrtr): *"Servers **MUST** send server-to-client requests (such as `roots/list`, `sampling/createMessage`, or `elicitation/create`) using the MRTR pattern. The previous pattern of server-initiated requests is no longer supported. This is a breaking change."*
- [Tools — Input Required Tool Results](https://modelcontextprotocol.io/specification/2026-07-28/server/tools#input-required-tool-results): *"Servers **MAY** respond to `tools/call` with an `InputRequiredResult` … When retrying the request with input responses, clients include `inputResponses` and, if provided by the server, `requestState`."*
- [Elicitation](https://modelcontextprotocol.io/specification/2026-07-28/client/elicitation): *"Servers **MAY** request information from a user during the processing of a client request, by sending an `InputRequiredResult` containing an `elicitation/create` request."*
- [Tools — User Interaction Model](https://modelcontextprotocol.io/specification/2026-07-28/server/tools#user-interaction-model): the confirmation burden is on the client — *"Applications **SHOULD** … Present confirmation prompts to the user for operations"* — which is why the server's gate is additive and not a precondition.

**Recommendation.** In order of preference:
1. **Implement the MRTR round trip for the four deletes.** `mcp` 2.3.0 already exposes `Resolve(...)` parameters and `InputRequiredResult` returns (`mcp/server/mcpserver/resolve.py`), and the server already depends on a private SDK seam for flat arguments, so this is in scope. The handler returns `InputRequiredResult(inputRequests={"confirm": ElicitRequest(...)}, requestState=...)`; the retry carries `inputResponses["confirm"]`. This is the spec's mechanism and it works on both eras.
2. **If that is out of scope for 0.7.x, make the description honest.** Replace "When the client supports elicitation the call first asks the user to confirm" with a sentence that names the limitation, e.g. *"On the legacy handshake path the call asks the client to confirm first; on the 2026-07-28 path the confirmation is skipped and the client's own confirmation UI is the only gate."* Log a `WARNING` when the skip happens so an operator can see it.
3. **At minimum, do not let the description promise a confirmation that cannot happen.** A model that is told the truth can ask the user itself.

---

### Medium

#### M1 — `destructiveHint` is classified two ways for the same PATCH-merge operation class

**What.** `firewall_rule_update` (`tools/firewall_rules.py:540`) and `nat_rule_update` (`tools/nat_rules.py:359`) publish `destructiveHint: true`. The other nine update tools publish `destructiveHint: false`: `address_update`, `address_update_fqdn`, `address_group_update`, `address_group_update_fqdn` (`tools/hosts_objects.py:513`), `service_update`, `service_group_update` (`tools/services_objects.py:265`), `mac_address_update` (`tools/hosts_objects.py:513`), `network_user_update` (`tools/users_auth.py:393`), `network_interface_update_vlan` (`tools/network.py:389`). All eleven are JSON Merge Patch operations that overwrite stored values.

**Why it matters.** The spec defines the hint precisely: *"`destructiveHint`: If true, the tool may perform destructive updates to its environment. If false, the tool performs only additive updates."* A merge patch that changes a firewall rule's action, an address object's IP, a user's group or a VLAN's zone replaces prior state; it is not additive. The same operation class is classified two ways, so a client that gates on the hint treats `address_update` as safe and `firewall_rule_update` as dangerous, with no principled reason. The two rule tools are the spec-faithful ones; the nine object tools understate.

**MCP guidance.** [ToolAnnotations](https://modelcontextprotocol.io/specification/2026-07-28/schema#toolannotations) — `destructiveHint` semantics and default `true`.

**Recommendation.** Make the nine consistent with the two (`destructive_hint=True`), or record why an object update is additive and a rule update is not. The former is the spec-faithful choice and is a one-line change per domain constant (`_UPDATE` in `hosts_objects.py:513` and `services_objects.py:265`, plus the two inline declarations). Add a test that pins the mapping, as `tests/test_tool_surface.py` already does for `openWorldHint`.

---

#### M2 — `ip_family` is undescribed on the six firewall tools and described eight different ways across the other 29

**What.** 35 tools publish `ip_family` (32 required, 3 optional on the audit composites). The six firewall tools publish it with **no description at all**: `firewall_rule_list`, `firewall_rule_get`, `firewall_rule_delete`, `firewall_rule_move`, `firewall_rule_set_enabled`, `firewall_rule_clone` — the field is a bare `ip_family: IpFamily` at `models/firewall.py:1006, 1059, 1069, 1083, 1105, 1120`. The other 29 use thirteen distinct descriptions (ten required, three optional):

| Description | Tools |
|---|---|
| *(none)* | 6 firewall tools |
| "IP family of the rule base: 'ipv4' or 'ipv6'. Required: the two rule bases are separate, so the family is never inferred." | `nat_rule_list` (`models/nat.py:516`) |
| "IP family of the rule base: 'ipv4' or 'ipv6'." | `nat_rule_get`, `nat_rule_delete`, `nat_rule_move` (`models/nat.py:571, 580`) |
| "IP family of the address collection: … Required." | `address_list` |
| "IP family of the object collection: … Required." | `address_get`, `address_delete`, `address_group_get`, `address_group_delete` |
| "IP family of the address-group collection: … Required." | `address_group_list` |
| "IP family of the collection: … Required." | 11 network tools |
| "IP family of the gateway collection: …" / "… SD-WAN route collection …" / "… lease collection …" / "… DHCP relay collection …" | 5 tools |
| optional, per-composite prose | `audit_firewall_rules`, `explain_connectivity`, `find_object_usage` |

**Why it matters.** `ip_family` is the single new argument of 0.7.0 and the one a model must get right on 32 tools. The highest-traffic domain — firewall rules — is the one with no description. A model reading only `tools/list` sees `{"enum": ["ipv4","ipv6"], "title": "Ip Family", "type": "string"}` and has to infer that the two rule bases are separate and that the family is never inferred. The server's own `sophos://conventions` resource explains it, but a client that does not read resources gets nothing.

**MCP guidance.** [Tools — Tool](https://modelcontextprotocol.io/specification/2026-07-28/server/tools#tool): the `inputSchema` is the model's only description of a parameter; the [JSON Schema usage guidelines](https://modelcontextprotocol.io/specification/2026-07-28/basic#json-schema-usage) treat `description` as the field's documentation.

**Recommendation.** One shared constant, e.g. *"IP family of the collection: 'ipv4' or 'ipv6'. Required: the two collections are separate, so the family is never inferred."* Apply it to all 32 required tools (the six firewall fields are the priority); keep the three composite descriptions distinct because their semantics differ (optional, "both" when omitted, `fqdn` on `find_object_usage`).

---

#### M3 — `serverInfo.description` is stale ("152 typed tools") and the drift test only checks the version

**What.** The live `serverInfo` is:

```json
{"name": "Sophos Firewall MCP Server", "title": "Sophos Firewall MCP", "version": "0.7.0",
 "description": "MCP server for the Sophos Firewall 23 (SFOS 23.0) Configuration REST API: 152 typed tools for firewall, NAT, objects, users, network and audit over STDIO",
 "websiteUrl": "https://github.com/lordraiden/sophos-firewall-mcp"}
```

`pyproject.toml:4` says **112**, and the server publishes 112. The value is read from the *installed* distribution metadata (`server.py:_package_identity`), and the editable install in this worktree still carries the 0.6.0 summary. `tests/test_server.py:358-380` compares `info.version` against `pyproject.toml` — the test exists precisely to catch this drift — but only asserts `info.description` is truthy.

**Why it matters.** `serverInfo` is what a client shows in its UI, logs and bug reports. "152 typed tools" is wrong by 40 and contradicts the same server's `tools/list`. The test that was written to catch metadata drift misses the field that drifted, so the next release can ship the same defect.

**MCP guidance.** [Discovery — DiscoverResult](https://modelcontextprotocol.io/specification/2026-07-28/server/discover#discoverresult): `serverInfo` is *"intended for display, logging, and debugging"*.

**Recommendation.** In `tests/test_server.py`, compare `info.description` against `project.description` from `pyproject.toml` (the same `declared_project_version` helper can read it). Reinstall the editable package so the installed metadata matches. This is a two-line test change plus a `uv sync`.

---

#### M4 — `prompts/get` returns `-32603` for an unknown prompt and for missing or invalid arguments

**What.** Observed over STDIO on the modern path:

| Request | Response |
|---|---|
| `prompts/get {"name": "nope"}` | `-32603 Internal server error` |
| `prompts/get {"name": "explain_flow", "arguments": {}}` (missing `source`, `destination`, `service`) | `-32603 Internal server error` |
| `prompts/get {"name": "explain_flow", "arguments": {…, "bogus": "x"}}` | `-32603 Internal server error` |
| `prompts/get {"name": "explain_flow", "arguments": {…, "port": 53}}` (port without protocol) | `-32602 Invalid request parameters` |
| `resources/read {"uri": "sophos://nope"}` | `-32602` "Unknown resource: sophos://nope" ✔ |

The server logs a full traceback at `ERROR` for each of the first three, because the SDK raises `ValueError` and the runner maps it to an internal error.

**Why it matters.** The spec is explicit about the codes, and a client cannot distinguish "you asked for a prompt that does not exist" from "the server crashed". The `resources/read` path gets this right, so the inconsistency is visible within the same server.

**MCP guidance.** [Prompts — Error Handling](https://modelcontextprotocol.io/specification/2026-07-28/server/prompts#error-handling): *"Servers **SHOULD** return standard JSON-RPC errors for common failure cases: Invalid prompt name: `-32602` (Invalid params); Missing required arguments: `-32602` (Invalid params); Internal errors: `-32603` (Internal error)."*

**Recommendation.** The SDK owns the `ValueError` → `-32603` mapping, but the server can wrap `prompts/get` with a middleware (the SDK exposes `server.middleware`) that maps a `ValueError` whose message starts with `Unknown prompt:` or `Error rendering prompt` to `-32602` with the message. At minimum, file it upstream and record it in the README's known limitations.

---

#### M5 — The spec's backwards-compatible `elicitation: {}` declaration is treated as "cannot elicit"

**What.** `_client_can_elicit` (`tools/__init__.py:294-308`) returns `False` unless `capabilities.elicitation.form` is not `None`. A client that declares `"elicitation": {}` — which the spec says is *"equivalent to declaring support for `form` mode only"* — is therefore treated as unable to elicit. Observed: legacy `initialize` with `capabilities: {"elicitation": {}}`, then `firewall_rule_delete` → no `elicitation/create`, the delete proceeds.

**Why it matters.** The server skips a confirmation the client could have handled, for a whole client generation. `docs/architecture/sophos-rest-api-redesign/PHASE-8-REVIEW.md:104-108` recorded this as a residual risk and recommended *"a sentence in the release notes"*; `docs/release/RELEASE-0.7.0.md` does not contain it, and the code is unchanged.

**MCP guidance.** [Elicitation — Capabilities](https://modelcontextprotocol.io/specification/2026-07-28/client/elicitation#capabilities): *"For backwards compatibility, an empty capabilities object is equivalent to declaring support for `form` mode only: `"elicitation": {}`."*

**Recommendation.** Treat an empty `elicitation` object as form-mode support:

```python
return elicitation is not None and (
    elicitation.form is not None
    or (elicitation.form is None and elicitation.url is None)
)
```

Add a test for `{}` (the existing `tests/test_destructive_confirmation.py` already has the stub-context harness). This is a small, safe fix that makes the gate fire for one more client generation.

---

#### M6 — The catalog is still ~156k tokens, 60.5% of it optional output schemas, with no pagination

**What.** Measured from the live surface:

| Measurement | Value |
|---|---|
| `tools/list` wire line (modern, compact) | **623,373 bytes** ≈ **156k tokens** at 4 B/token |
| — compact tool payload | 622,809 B |
| — input schemas | 186,096 B (29.9%) |
| — output schemas | **376,813 B (60.5%)** |
| — descriptions | 35,366 B (5.7%) |
| Largest tool | `nat_rule_create`, 23,600 B |
| Median tool | 4,257 B |
| Union tools (9) | 123,036 B (19.8%) |
| `nextCursor` | absent — all 112 tools in one frame |

This is a 34% reduction from 0.6.0's 950,591 B, and the server has added the mitigations the 0.6.0 review asked for: `ttlMs: 3600000` on `tools/list`, `server/discover`, `prompts/list`, `resources/list`, `resources/templates/list` and `resources/read`; 4 resources and 3 prompts as a cheaper channel; and a README section that documents progressive discovery and the 1–5% threshold.

**Why it matters.** The client best practices still put the threshold at 1–5% of the context window, and 156k tokens is far beyond it. A naive host that injects the catalog either truncates it (and then cannot call the tools that were cut) or exhausts the context. The server cannot control the host, but it controls the 60.5% that is output schemas — and the spec makes `outputSchema` optional.

**MCP guidance.** [Client best practices — Progressive Tool Discovery](https://modelcontextprotocol.io/docs/2026-07-28/develop/clients/client-best-practices#progressive-tool-discovery): *"Loading every tool definition into the model's context window upfront wastes tokens, increases latency, and degrades model performance"*; threshold *"1%-5%"*. [Tools — Tool](https://modelcontextprotocol.io/specification/2026-07-28/server/tools#tool): `outputSchema` is *"Optional JSON Schema defining expected output structure"*.

**Recommendation.** The remaining lever is the output schemas, in this order:
1. **Trim the output schemas** — drop the `description` strings inside `$defs` (they are documentation for the model, but the tool description already carries the semantics), and collapse the 13 shared output schemas that 44 tools repeat. Measure after each change; the 0.6.0 review's Appendix A gives the method.
2. **Add pagination** (`nextCursor`) so a client can fetch a subset. The spec supports it for `tools/list`; the SDK may already expose it. This does not reduce the total, but it removes the single-frame cliff.
3. **Do not drop `outputSchema` wholesale** — the SDK's `structured_output=False` would also drop `structuredContent`, losing the typed result. A per-tool decision on the largest tools is defensible; a global one is not.

---

#### M7 — The union tools do not declare their discriminator, and a bad `ip_family` on `address_create` is reported as "type is required"

**What.** The 9 union tools publish a root `oneOf` (8) or `anyOf` (`mac_address_create`) whose variants are `$ref`s to closed `$defs`. The schema has no `discriminator` keyword, so the field that selects the variant is stated only in `INSTRUCTIONS` and `sophos://conventions`. Observed:

| Call | Message |
|---|---|
| `address_create {"ip_family": "ipv5", "name": "x"}` | "invalid arguments: **type is required**; accepted values are 'ipv4Address', …" |
| `address_create {"name": "x", "type": "ipv4Address", "ip_family": "ipv6", "ipv4_address": "1.2.3.4"}` | "invalid arguments: ip_family must be one of 'ipv4'" ✔ |
| `firewall_rule_create {"name": "x"}` | "invalid arguments: ip_family is required; accepted values are 'ipv4', 'ipv6'" ✔ |

The first row is the problem: the caller's mistake is the bad `ip_family`, but the message names `type`, because `_union_argument_message` (`tools/__init__.py:844-900`) resolves the pydantic discriminator (`type`) first and never looks at the other const field. The `INSTRUCTIONS` sentence *"its discriminator (`ip_family` or `type`) selects the variant"* invites exactly this call.

**Why it matters.** A model that reads the instructions and sends `ip_family` only for `address_create` gets a message about a field it did not send, and may conclude the tool is broken. The schema itself does not say which field selects, so the model has no way to recover except by reading the `$defs`.

**MCP guidance.** [Tools — Tool](https://modelcontextprotocol.io/specification/2026-07-28/server/tools#tool): the `inputSchema` is the contract; [JSON Schema usage](https://modelcontextprotocol.io/specification/2026-07-28/basic#json-schema-usage).

**Recommendation.**
1. Add one sentence to the `address_create`, `address_update`, `address_group_create` and `address_group_update` descriptions: *"Send `type` (the discriminator) and the matching `ip_family`; `type` selects the variant."* This is the cheap fix and it matches the schema.
2. Optionally emit `"discriminator": {"propertyName": "type", "mapping": {…}}` in `_union_schema` (`tools/__init__.py:768-786`). It is an OpenAPI keyword, not core JSON Schema, so validators ignore it — but schema-aware tooling and models can use it, and it costs ~200 bytes per union tool.
3. Optionally make `_union_argument_message` report a const field the caller *did* send with a bad value before falling back to "the discriminator is required".

---

### Low

#### L1 — An unknown tool returns `isError: true` instead of `-32602`

Observed: `tools/call {"name": "nope"}` → `{"isError": true, "content": [{"text": "Unknown tool: nope"}]}`. The spec puts unknown tools in the *protocol error* class: *"Protocol Errors indicate issues with the request structure itself … Unknown tool … They are returned as standard JSON-RPC errors: `-32602`"* ([Tools — Error Handling](https://modelcontextprotocol.io/specification/2026-07-28/server/tools#error-handling)). This is SDK-owned (the SDK's `call_tool` returns a tool result), and it was already recorded as L1 in the 0.6.0 review. Record it in the README's known limitations or wrap `tools/call` in a middleware that maps the unknown-name case to `-32602`.

#### L2 — `mac_address_create` with both variants returns a self-contradictory message

Observed: `{"name": "x", "mac_address": "aa:bb:…", "mac_addresses": ["aa:bb:…"]}` → *"invalid arguments: mac_addresses is not an accepted argument; accepted arguments are name, description, mac_address **or** mac_address is not an accepted argument; accepted arguments are name, description, mac_addresses"*. The caller's actual mistake is sending both; the message reads as if neither is accepted. Add a model-level validator that rejects both with *"send exactly one of mac_address or mac_addresses"*, or special-case the two-variant `anyOf` in `_union_argument_message`.

#### L3 — The `explain_flow` prompt cannot mix endpoint types

`explain_connectivity` accepts a per-endpoint type (`source: {ip|zone|fqdn}`, `destination: {ip|zone|fqdn}`), but the `explain_flow` prompt has one `endpoint_type` argument applied to both: *"both endpoints above are read as `{kind}`"* (`prompts.py:120-160`). A user who wants "source zone LAN, destination IP 8.8.8.8" cannot express it through the prompt. Add `source_type` and `destination_type` (both optional, defaulting to `ip`), or document the limitation in the prompt description.

#### L4 — The `sophos://` URIs mix two forms

`sophos://coverage`, `sophos://read-only-policy` and `sophos://conventions` are authority-only; `sophos://api/surface` is authority + path. All four are RFC 3986-valid (the spec requires custom schemes to be: *"Custom URI schemes **MUST** be in accordance with RFC3986"*, [Resources — Common URI Schemes](https://modelcontextprotocol.io/specification/2026-07-28/server/resources#custom-uri-schemes)), but a client that groups resources by authority sees four different "hosts". Pick one form, e.g. `sophos://docs/coverage`, `sophos://docs/conventions`, … (a breaking change for anyone who hard-coded the URIs; the resources are new in 0.7.0, so now is the cheap moment).

#### L5 — `annotations.title` duplicates `title` on all 112 tools

`_build_annotations` sets `annotations.title = title` (`tools/__init__.py:985-1021`), so every tool carries the same string twice (2,487 B total). The spec's display precedence is `title`, then `annotations.title`, then `name` ([Tools — Tool](https://modelcontextprotocol.io/specification/2026-07-28/server/tools#tool)), so the duplicate is harmless but redundant. Drop it from the annotations and keep the tool-level `title`.

#### L6 — Sixteen getter descriptions are one sentence and do not say what they return

`zone_get` is *"Read one network zone by name or UUID. Read-only."* (49 chars); `ipsec_profile_get` (50), `dns_host_entry_get` (51), `dns_request_route_get` (54), `ipsec_failover_group_get` (57), `sslvpn_clientless_policy_get` (62), `sslvpn_remote_access_policy_get` (65), `sslvpn_bookmark_group_get` (70), `ipsec_route_based_connection_get_ipv4` (77), `ipsec_policy_based_connection_get_ipv4` (78), `dhcp_server_get` (99), `wan_gateway_get` (99), `sdwan_route_get` (100), `custom_gateway_get` (102), `unicast_route_get` (108) and `static_neighbor_get` (109) are the same shape. The list tools document their payload; the getters do not. One sentence on the returned object (as `address_get_fqdn` already does: *"Returns the object's `name`, `description` and `fqdn`"*) would close the gap.

#### L7 — `INSTRUCTIONS` does not mention the resources or the prompts

`INSTRUCTIONS` (`server.py:140-155`) covers flat arguments, `oneOf`/`anyOf`, read-only mode and the `content`/`structuredContent` duplication, but not the 4 resources or the 3 prompts. A model that reads only `instructions` never learns that `sophos://conventions` exists or that `audit_firewall` is a workflow. Add one sentence: *"Read `sophos://conventions` before the first call; the prompts `audit_firewall`, `explain_flow` and `find_unused_objects` carry the three analysis workflows."*

#### L8 — No rate limiting beyond the concurrency semaphore

The spec's [Security Considerations](https://modelcontextprotocol.io/specification/2026-07-28/server/tools#security-considerations) say servers **MUST** *"Rate limit tool invocations"*. The server bounds in-flight requests (`SOPHOS_MAX_CONCURRENCY`, `client.py:148`, `:342-344`) but has no per-tool or per-session rate limit. **Decision recorded (issue #63):** no separate invocation-rate limiter is added for the local STDIO, one-client-per-process deployment. The semaphore is a concurrency bound, not a rate limiter; the rationale, the residual risk and the conditions that would require a limiter are in [`docs/SECURITY-RATE-POLICY.md`](../../../SECURITY-RATE-POLICY.md). If a limiter is added, it belongs at the tool dispatch layer (one `tools/call` is one invocation, however many adapter reads it performs), not at the HTTP client layer.

#### L9 — The elicitation `requestedSchema.description` leaks an internal docstring

The form the client renders carries the `_DestructiveConfirmation` docstring as its schema description:

> *"The one question :func:`confirm_destructive` asks. Elicitation schemas are restricted to primitive properties, so the answer is a single boolean rather than a free-text acknowledgement."*

That is internal prose with a Sphinx role, shown to a user in a confirmation dialog. Give the model a plain `model_config`/`Field` description (or a plain docstring) and keep the implementation note in a comment. This is the same class of defect as the 0.6.0 review's M4 (internal markers in the published surface), just in a different channel.

#### L10 — The six IPv4-only IPsec tools keep an `_ipv4` suffix that now reads as a missing pair

`ipsec_connection_list_ipv4`, `ipsec_live_connection_list_ipv4`, `ipsec_policy_based_connection_get_ipv4`, `ipsec_policy_based_connection_list_ipv4`, `ipsec_route_based_connection_get_ipv4`, `ipsec_route_based_connection_list_ipv4` are unchanged from 0.6.0 because the API has no IPv6 counterpart (`MIGRATION-0.7.md`). After the 0.7.0 collapse, every other tool is `<resource>_<verb>` with `ip_family`; these six are the only `_ipv4` names left, so a model may look for `ipsec_connection_list_ipv6` and not find it. Either rename them in a future breaking release (`ipsec_connection_list`, …) or add *"the API has no IPv6 counterpart"* to each description.

---

## 3. What is already good

The report would be misleading without this section. 0.7.0 is a strong release, and most of what follows is better than the ecosystem norm.

**Annotations**
- **The policy is enforced, not just declared.** Read tools are *rejected* if they declare write hints; mutation tools must declare both `destructiveHint` and `idempotentHint` explicitly (`tools/__init__.py:985-1021`). A new tool cannot ship with a missing or contradictory hint.
- **`openWorldHint` is per tool and pinned by a test.** 6 open, 106 closed, with the rationale for each of the 6 in `OPEN_WORLD_TOOLS` (`tools/__init__.py:266-290`) and `tests/test_tool_surface.py:297-321` pinning the set. The classification is by *what the result describes* (leases, live sessions, live peers, carrier state, vendor verdict), which is the right axis.
- **Read tools omit `destructiveHint`/`idempotentHint`** rather than publishing `false`. The spec says those hints are *"meaningful only when `readOnlyHint == false`"*, so omitting them is correct and better than the common `false`/`false` noise.

**Flat arguments and schemas**
- **The wrapper is gone on all 112 tools**, at every depth (checked). The published schema is the request model's own fields, and the handler signature is unchanged — a clean seam (`tools/__init__.py:613-700`).
- **Closed inputs.** 103 flat tools publish root `additionalProperties: false`; the 9 union tools publish closed `$defs` variants under a root `oneOf`/`anyOf` (the root deliberately omits `additionalProperties` so the variants' own closure applies). Zero open nested objects in any input schema.
- **Argument errors are excellent.** Observed: *"invalid arguments: ip_family is required; bogus is not an accepted argument; accepted arguments are ip_family, page, page_size, page_total, name_contains, name_not_equals"*; *"ip_family must be one of 'ipv4' or 'ipv6'"*; *"source_zones is required; destination_zones is required; …"*. The union path reports one readable line instead of every variant's errors, and the sanitized `ValidationError` subclass keeps the SDK's catch behaviour (`tools/__init__.py:563-580`).
- **`page` and `page_total` are described** on all 31 paginated tools, and `page_size` documents the 10-vs-50 default difference from the API.
- **No property-level `title` noise** remains in output schemas (0, down from 3,486), and the internal planning markers are gone from the published surface (0 occurrences of "the contract", "lab appliance", "issue #", "live observation", `M<n>`; `tests/test_tool_surface.py:514` guards it).

**`ip_family`**
- **Required on all 32 merged tools, optional only on the 3 audit composites**, and the rationale is documented (`MIGRATION-0.7.md`): a default would make a destructive target a guess. That is the right call, and the adapter strips the field before the wire body so the per-family request is byte-identical to 0.6.0.
- **The union variants carry `const` `ip_family`**, so a mismatched family is rejected before any I/O (observed: *"ip_family must be one of 'ipv4'"*).

**Elicitation**
- **The legacy path works end to end.** Observed: `elicitation/create` with the rule name and the rule base, `decline` → `isError: true` and *"nothing was changed"*, `cancel` → the same, `accept` → the delete proceeds. The question names the object and the family, which is what a user needs to decide.
- **The fallback is additive, never a precondition.** A client with no capability, or a transport with no back-channel, keeps the previous behaviour — the delete is never broken by the gate. That is the right shape for an optional affordance.
- **The limitation is documented honestly** in `README.md:466-472` and `docs/release/RELEASE-0.7.0.md`, and pinned by `tests/test_destructive_confirmation.py:297-315`. The defect in H1 is that the *model-facing* description does not match the documented limitation, not that the limitation is hidden.

**Resources and prompts**
- **4 resources, all `text/markdown`, all with `name`, `title`, `description` and a `sophos://` URI**, and all static for the process lifetime (`resources.py:435-499`). The content is accurate: the inventory (384 paths, 700 operations, 145 mapped, 107 one-to-one, 5 composites, 112 tools, 74/38) matches the live surface and the coverage rows sum to 700 operations and 112 tools.
- **The coverage matrix is drift-tested** against the checked-in OpenAPI document (`tests/test_server.py`), so a regeneration that changes a count fails the test instead of leaving a stale resource.
- **3 prompts, each a self-contained workflow** that names the real tools, the exact argument shape and the argument values (`prompts.py:220-341`). The rendered `audit_firewall` message is a complete instruction; the `find_unused_objects` prompt handles the `fqdn` special case correctly; all three are read-only by construction and say so.
- **Prompt arguments are typed and described** (`required` is correct: `explain_flow` has 3 required, the other two have 0), and `prompts/list` carries `title` and `description`.

**Catalog and identity**
- **`ttlMs: 3600000` on all six cacheable methods** (`server.py:118-131`), which is the spec's own `server/discover` example value. The 0.6.0 review's `ttlMs: 0` finding is closed.
- **`serverInfo` carries `name`, `title`, `version` (0.7.0), `description` and `websiteUrl`**, read from the distribution metadata so the version is not duplicated in code (`server.py:177-205`). The version is drift-tested against `pyproject.toml`.
- **`INSTRUCTIONS` is a real calling convention**, not a marketing sentence: flat arguments, `oneOf`/`anyOf`, read-only mode, and the `content`/`structuredContent` rule.
- **`subscriptions=False`** is passed deliberately because the catalog is static, so the server does not advertise `listChanged` it cannot honour.

**Protocol and transport**
- **Both eras work.** Modern: `server/discover` → `supportedVersions: ["2026-07-28"]`, `resultType: "complete"`, `ttlMs`, `cacheScope: "private"`, `_meta.serverInfo`. Legacy: `initialize` first → `protocolVersion: "2025-11-25"`, and `initialize` after discovery is refused with `-32022`.
- **`resources/read` returns `-32602` for an unknown URI**, exactly as the spec requires (*"If the requested resource does not exist, servers **MUST** return a JSON-RPC error with code `-32602`"*).
- **STDIO is clean.** stdout carries only JSON-RPC frames; diagnostics go to stderr; the process exits promptly on stdin close.
- **The `content`/`structuredContent` duplication is the spec's recommendation**, not a defect: *"For backwards compatibility, a tool that returns structured content **SHOULD** also return the serialized JSON in a TextContent block"* ([Tools — Structured Content](https://modelcontextprotocol.io/specification/2026-07-28/server/tools#structured-content)). The 0.6.0 review's M1 should be read as a cost, not a violation; the server now documents the "read one of them" rule in `INSTRUCTIONS` and `sophos://conventions`.

**Engineering practice**
- **Gates are green.** `pytest -q` → **1240 passed, 100 skipped** (206.7 s); `mypy src` → *"Success: no issues found in 28 source files"*; `flake8 src tests` → clean; `black --check src tests` → *"52 files would be left unchanged"*.
- **The surface is pinned by tests**: the exact 112-tool set, the 74/38 split, the read-only filter, the snake_case input convention at every depth, the camelCase output convention at every depth, the `openWorldHint` mapping, the internal-marker guard, and the four gated deletes.
- **Progress reporting, concurrency and the env guard** are all fixed as the 0.6.0 roadmap asked (`tools/audit.py:2908-2980`, `client.py:148`, `_env_guard.py`).

---

## 4. Prioritized roadmap

### Do first (before the next release; cheap, no breaking change)

| # | Action | Finding | Effort |
|---|---|---|---|
| 1 | Make the four delete descriptions honest about the modern-path skip, and log a `WARNING` when the skip happens | H1 | ~10 lines |
| 2 | Compare `serverInfo.description` against `project.description` in `tests/test_server.py`; reinstall the editable package | M3 | 2 lines + `uv sync` |
| 3 | Treat `elicitation: {}` as form-mode support; add a test | M5 | ~5 lines |
| 4 | One shared `ip_family` description on all 32 required tools (start with the six firewall fields) | M2 | ~10 lines |
| 5 | Make the nine object-update tools `destructive_hint=True`, or document why they are additive | M1 | ~6 lines |
| 6 | Add the "send `type` and the matching `ip_family`" sentence to the four address/address-group create/update descriptions | M7 | 4 lines |
| 7 | Map `prompts/get` `ValueError` to `-32602` via a middleware (or file upstream and document) | M4 | ~20 lines |
| 8 | Add the resources/prompts sentence to `INSTRUCTIONS` | L7 | 1 line |
| 9 | Give `_DestructiveConfirmation` a plain description | L9 | 2 lines |
| 10 | Drop `annotations.title` (keep the tool `title`) | L5 | 1 line |

### Do next (one focused change each)

| # | Action | Finding | Effort |
|---|---|---|---|
| 11 | Implement the MRTR `InputRequiredResult` round trip for the four deletes | H1 | medium; the real fix |
| 12 | Trim the output schemas (drop `$defs` descriptions, collapse the 13 shared schemas) and re-measure the catalog | M6 | ~1 day |
| 13 | Add `nextCursor` pagination to `tools/list` | M6 | small if the SDK exposes it |
| 14 | Add `source_type`/`destination_type` to the `explain_flow` prompt | L3 | ~20 lines |
| 15 | One sentence on the returned object for the 16 terse getters | L6 | ~16 lines |
| 16 | Reject "both `mac_address` and `mac_addresses`" with a dedicated message | L2 | ~10 lines |
| 17 | Add "the API has no IPv6 counterpart" to the six IPsec descriptions | L10 | 6 lines |

### Consider for a breaking release (0.8/1.0)

| # | Action | Finding | Effort |
|---|---|---|---|
| 18 | Rename the six IPv4-only IPsec tools to drop the `_ipv4` suffix | L10 | small; breaking |
| 19 | Normalise the `sophos://` URIs to one form | L4 | small; breaking for hard-coded URIs |
| 20 | Emit `discriminator` in the union schemas | M7 | small; additive |

### Optional / record-only

- L1 (unknown tool → `-32602`): SDK-owned; document it.
- L8 (rate limiting): decision recorded in `docs/SECURITY-RATE-POLICY.md`; the semaphore is a concurrency bound, not a rate limiter.

---

## 5. What I could not verify

- **No live appliance.** This environment has no `SOPHOS_HOST`/API key, so I could not exercise a successful tool call end to end. The error paths, the argument validation, the elicitation flow and the protocol surface are all measured live; the success payloads are verified from the SDK's conversion code and the server's own tests, not from a real SFOS response. `docs/live-evidence/phase-9-live-0.7.md` covers what was exercised on SFOS 23.0.0 GA-Build371.
- **Which era a real client negotiates.** H1's practical impact depends on whether Claude Desktop, VS Code, Cursor or Antigravity IDE probe with `server/discover` (modern → the gate is inert) or send `initialize` first (legacy → the gate fires). The SDK's `mode="auto"` probes first, so a client built on `mcp` 2.3.0 will adopt the modern era; a client that does not probe will get the legacy era. I could not test a real host.
- **The installed-metadata drift in CI.** I observed the stale `serverInfo.description` in this worktree's editable install. I did not check whether the CI image or the published wheel carries the same stale summary; the test gap in M3 means it could.
- **The `mcp` 2.3.0 private seam.** `tools/__init__.py:613-700` depends on `MCPServer._tool_manager`, `Tool.fn_metadata.arg_model` and `Tool.parameters`. The project pins and tests it, but I cannot predict when the SDK will move it. The failure modes are loud (a `RuntimeError` at registration) or benign (the published schema reverts to the wrapper), not silent data loss — but a `mcp` 2.3.x patch that changes `Tool.run`'s validation path would break every tool's argument handling at once.
- **Client-specific catalog limits.** I measured 623,373 bytes on the wire; I did not verify how a specific host handles it (truncation threshold, frame limit, progressive-discovery support). The 156k-token estimate is at 4 B/token, the same convention as the 0.6.0 review.
- **The Docker image and the live workflow.** I read `Dockerfile`, `docker-compose.yml` and the workflows but did not build or run them.
- **TLS against a real appliance.** The `verify_ssl`/`ca_bundle` paths are covered by unit tests with mocked transports; I did not handshake with a real SFOS certificate.
- **Whether the `InputRequiredResult` round trip is implementable with `mcp` 2.3.0 without changing every handler signature.** The SDK exposes `Resolve(...)` parameters and `InputRequiredResult` returns (`mcp/server/mcpserver/resolve.py`), and the server already depends on a private seam, so I believe it is — but I did not prototype it. H1's recommendation 1 is conditional on that.

---

## Appendix A — measured surface (reproducible)

```
tools: 112 (unique 112)
read-only / mutation: 74 / 38
annotations:
  (readOnly=True,  destructive=None, idempotent=None, openWorld=False) x 69
  (readOnly=True,  destructive=None, idempotent=None, openWorld=True)  x  5
  (readOnly=False, destructive=True,  idempotent=True,  openWorld=False) x 16
  (readOnly=False, destructive=False, idempotent=False, openWorld=False) x 12
  (readOnly=False, destructive=False, idempotent=True,  openWorld=False) x  9
  (readOnly=False, destructive=True,  idempotent=False, openWorld=True)  x  1
read-only mode: 74 tools, 0 mutations
tools/list wire line (modern, compact): 623,373 bytes (~156k tokens at 4 B/token)
  compact tool payload 622,809 B | input 186,096 B | output 376,813 B (60.5%) | descriptions 35,366 B
  largest nat_rule_create 23,600 B | median 4,257 B
  union tools 9 = 123,036 B (19.8%) | truly no-argument tools 7
  nextCursor: absent | ttlMs: 3,600,000 | cacheScope: private
root input shapes: 103 x (object, additionalProperties=false); 8 x (object, oneOf); 1 x (object, anyOf)
nested open objects in input schemas: 0
output schemas: 112/112 object-rooted; property-level titles 0; anyOf-null 507; defaults 1,904
ip_family: 35 tools (32 required, 3 optional); 6 firewall tools publish no description
pagination: 31 tools, page_size default 10 on all, page/page_total described on all
internal markers in the published surface: 0
resources: 4 (sophos://api/surface, sophos://coverage, sophos://read-only-policy, sophos://conventions)
prompts: 3 (audit_firewall, explain_flow, find_unused_objects)
serverInfo: name, title, version 0.7.0, description (stale: "152 typed tools"), websiteUrl
```

## Appendix B — reproduction commands

```bash
# surface enumeration
UV_CACHE_DIR=/tmp/dsh-uv-cache uv run --no-sync python - <<'PY'
import asyncio, json
from sophos_firewall_mcp.config import Settings
from sophos_firewall_mcp.server import create_server
s = Settings(host="fw.example.com", port=4444, api_key="k"*20)
tools = asyncio.run(create_server(s).list_tools())
print(len(tools), len(json.dumps([t.model_dump(by_alias=True, exclude_none=True) for t in tools])))
PY

# protocol probes: every request carries the modern _meta envelope
#   {"_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28",
#              "io.modelcontextprotocol/clientInfo": {"name": "probe", "version": "1.0"},
#              "io.modelcontextprotocol/clientCapabilities": {}}}
# then server/discover, tools/list, prompts/list, resources/list,
# resources/templates/list, resources/read, prompts/get, tools/call.
# The legacy era is the same server with `initialize` first and no _meta.

# elicitation probes
#   legacy: initialize with capabilities {"elicitation": {"form": {}}} -> elicitation/create
#   legacy: initialize with capabilities {"elicitation": {}}        -> no elicitation (M5)
#   modern: tools/call with clientCapabilities {"elicitation": {"form": {}}} -> no elicitation (H1)

# gates
uv run --no-sync pytest -q          # 1240 passed, 100 skipped
uv run --no-sync mypy src           # Success: no issues found in 28 source files
uv run --no-sync flake8 src tests   # clean
uv run --no-sync black --check src tests  # 52 files would be left unchanged
```
