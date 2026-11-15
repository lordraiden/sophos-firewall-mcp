# MCP standards review — Sophos Firewall MCP Server 0.6.0

| Field | Value |
|---|---|
| **Reviewer** | `mcp-standards-review` (independent; did not write the code) |
| **Date** | 2026-11-15 |
| **Branch** | `migration/phase-5-output-contract` |
| **Reviewed HEAD** | `7d2121d` — *docs: record that the Configuration REST API is the same across SFOS versions* |
| **Subject** | `sophos-firewall-mcp-server` 0.6.0 — 152 tools (98 read-only, 54 mutations), STDIO, MCP `2026-07-28`, Python `mcp` 2.3.0 |
| **Scope** | Global review of the implementation against the official Model Context Protocol documentation: tool design, schemas, results/errors, protocol, security, client experience, repository practice |
| **Method** | Read `src/`, `tests/`, `README.md`, `docs/`; enumerated the live `tools/list` surface with `create_server(...)`; spoke raw JSON-RPC over STDIO to the real process; read the installed SDK's result-conversion code; ran the four quality gates |
| **Reference docs** | [Tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools), [ToolAnnotations](https://modelcontextprotocol.io/specification/2026-07-28/schema#toolannotations), [Resources](https://modelcontextprotocol.io/specification/2026-07-28/server/resources), [Prompts](https://modelcontextprotocol.io/specification/2026-07-28/server/prompts), [Discovery](https://modelcontextprotocol.io/specification/2026-07-28/server/discover), [stdio](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/stdio), [Pagination](https://modelcontextprotocol.io/specification/2026-07-28/server/utilities/pagination), [Caching](https://modelcontextprotocol.io/specification/2026-07-28/server/utilities/caching), [Server concepts](https://modelcontextprotocol.io/docs/2026-07-28/learn/server-concepts), [Build a server](https://modelcontextprotocol.io/docs/2026-07-28/develop/build-server), [Client best practices](https://modelcontextprotocol.io/docs/2026-07-28/develop/clients/client-best-practices), [Security best practices](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices), [Local server security](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/local-server-security), [Debugging](https://modelcontextprotocol.io/docs/2026-07-28/tools/debugging) |

---

## Verdict

**Good, with two High findings that a client will feel on every session.** The server is a careful, unusually disciplined MCP implementation: the wire behaviour is correct, the transport is clean, the security posture is strong, the annotations are honest, and the test suite pins the surface. Nothing in the protocol layer is broken.

The two High findings are not protocol violations — they are **client-experience costs that the protocol offers tools to avoid and the server does not use**:

1. **`tools/list` is ~950 KB (~238k tokens) in a single response** — no pagination, `ttlMs: 0`, no resources or prompts, and ~75 KB of auto-generated `title` noise. A naive host cannot load this; a host with a 1 MB frame limit may not parse it at all.
2. **144 of 152 tools require a non-standard `request` wrapper**, and the sentence that explains it ships a **wrong example on 103 of them** (`{"request": {"page": 1}}` on tools that have no `page` field). This is a per-call failure mode that the server's own sanitized error then has to recover from.

Everything else is Medium or Low: duplicated `content`/`structuredContent` payloads, an empty `serverInfo.version`, declared-but-empty `prompts`/`resources` capabilities, internal planning markers leaking into published descriptions, an IPv4/IPv6 split that doubles the surface, long-running composites with no progress reporting, and a handful of schema-quality issues.

**No Critical finding.** I looked specifically for a wire-level defect that breaks a conforming client and did not find one: `server/discover` works, the legacy `initialize` path negotiates correctly, `resultType`/`ttlMs`/`cacheScope` are present in the modern era, stdout is clean, and every result conforms to its published `outputSchema`.

---

## 1. Scope, method and evidence

### 1.1 What I measured

All numbers below come from the **live surface** of `create_server(Settings(...))` on `7d2121d`, not from reading the models by eye.

| Measurement | Value |
|---|---|
| Tools published | **152** (152 unique names; 8–39 characters; all lower snake_case) |
| Read-only / mutation | **98 / 54**; with `SOPHOS_READ_ONLY_MODE=true` → **98 tools, 0 mutations** |
| Tools with `title`, `description`, `inputSchema`, `outputSchema` | **152 / 152 / 152 / 152** |
| `tools/list` JSON payload | **950,591 bytes** ≈ **238k tokens** at 4 bytes/token |
| — input schemas | 257,348 bytes |
| — output schemas | 598,276 bytes |
| — descriptions | 57,295 bytes |
| Largest single tool | `nat_rule_create_ipv4`, 20,140 bytes |
| Median single tool | 5,170 bytes |
| Root `additionalProperties: false` | **152 / 152** |
| Nested open objects in input schemas | **0** |
| Output schema root type | **object** on 152 / 152 |
| `title` keys inside output schemas | **3,486** = 74,892 bytes (12.5% of the output payload) |
| `anyOf: [X, null]` wrappers in output schemas | 1,196 |
| Identical output schemas shared by >1 tool | 23 schemas across 74 tools |
| IPv4/IPv6 tool pairs | 40 pairs; 12 with byte-identical output schemas; 308,486 bytes in paired output schemas |
| Tools using the `request` wrapper | **144 / 152** (8 no-argument tools publish none) |
| — of those, tools whose wrapper example is wrong | **103** (no `page` field) |
| `request` published as `$ref` | 141 / 144 (3 inline) |
| Paginated tools | 41, all `page_size` default **10** |
| `page` / `page_total` schema descriptions | **none** (only `page_size` is described) |
| Annotation tuples observed | 98 × `(readOnly=true, destructive=null, idempotent=null, openWorld=true)`; mutations: 17 × `(F,F,F)`, 25 × `(T,T)`, 11 × `(F,T)`, 1 × `(T,F)` |

### 1.2 Protocol probes (raw JSON-RPC over STDIO)

| Probe | Observed |
|---|---|
| `server/discover` | `supportedVersions: ["2026-07-28"]`, `resultType: "complete"`, `ttlMs: 0`, `cacheScope: "private"`, `serverInfo.version: ""` |
| `initialize` as the **first** message | succeeds, negotiates `protocolVersion: "2025-11-25"` (legacy era) |
| `initialize` **after** `server/discover` | `-32022` "connection is serving the 2026-07-28 protocol; the initialize handshake is not accepted" |
| `tools/list` (modern) | 152 tools, `resultType: "complete"`, **no `nextCursor`**, `ttlMs: 0` |
| `prompts/list` | `prompts: []` |
| `resources/list` | `resources: []` |
| `resources/templates/list` | `resourceTemplates: []` |
| Unknown tool | `isError: true`, text `"Unknown tool: nope"` |
| Flat arguments (wrapper omitted) | `isError: true`, `"invalid arguments: request is required; page is not an accepted argument; accepted arguments are request"` |
| Unreachable appliance | `isError: true`, `"Error executing tool dns_settings_get: the firewall could not be reached or did not answer in time; retry the read [GET /network/dns/settings]"` |
| stdout during the whole session | only JSON-RPC frames |
| stderr | `INFO` lines only, one per event |
| Exit on stdin close | `0`, promptly |

### 1.3 Baseline gates

| Gate | Result |
|---|---|
| `pytest -q` | **1133 passed, 100 skipped**, 1 third-party deprecation warning, 162.9 s |
| `mypy src` | `Success: no issues found in 26 source files` |
| `flake8 src tests` | clean |
| `black --check src tests` | `49 files would be left unchanged` |

### 1.4 How to read the severities

- **Critical** — breaks conforming clients, loses data, or is a security hole.
- **High** — a significant deviation or cost that a client/agent will hit routinely; fix before the next release.
- **Medium** — a real deviation or cost with a workaround, or a design choice that should be revisited.
- **Low** — polish, documentation, or a judgment call worth recording.

---

## 2. Findings

### Critical

**None.** The wire behaviour is conformant: `server/discover` is implemented, both protocol eras negotiate correctly, `resultType`/`ttlMs`/`cacheScope` are present, every result conforms to its `outputSchema` (the SDK validates it before returning — `mcp/server/mcpserver/utilities/func_metadata.py:206`), stdout carries only MCP frames, and errors are sanitized.

---

### High

#### H1 — `tools/list` is ~950 KB / ~238k tokens, with no pagination, no cache hint, and no passive-context channel

**What.** A single `tools/list` response is **950,591 bytes** (measured from the live surface). The MCP spec supports pagination for exactly this case, and the server returns **no `nextCursor`** — all 152 tools in one frame. The modern-era response also carries **`ttlMs: 0`**, which the caching spec defines as "immediately stale", so a client cannot cache the list even though it is static for the process lifetime. The server declares `prompts` and `resources` capabilities but publishes **zero** of each, so the only channel it offers is the most expensive one.

**Where.**
- `src/sophos_firewall_mcp/server.py:143-148` — `MCPServer(...)` is constructed without `cache_hints` and without `version`; the tool catalog is static (`subscriptions=False`) but no TTL is advertised.
- `src/sophos_firewall_mcp/tools/__init__.py:307-317` — every tool is registered with a full `inputSchema` and `outputSchema`; nothing trims the published schema.
- The payload composition is dominated by output schemas (598,276 B), of which **74,892 B is auto-generated `title` keys** and 1,196 nullable fields are published as `anyOf: [X, null]` instead of `type: [X, "null"]`.
- 40 IPv4/IPv6 tool pairs carry **308,486 B** of output schema between them; 12 pairs are byte-identical.

**Why it matters for a client/agent.** The official client guidance is explicit: *"Loading every tool definition into the model's context window upfront wastes tokens, increases latency, and degrades model performance"* and recommends switching to progressive discovery once definitions take "1%–5%" of the context window ([Client best practices — Progressive Tool Discovery](https://modelcontextprotocol.io/docs/2026-07-28/develop/clients/client-best-practices#progressive-tool-discovery)). At ~238k tokens this list is **larger than most context windows on its own**. Two concrete failure modes follow:

1. A naive host that injects `tools/list` into the prompt either truncates the list (the model then cannot see, and cannot call, the tools that were cut) or blows the context.
2. A host that enforces a 1 MB JSON-RPC frame limit is within ~5% of failing to parse the response at all.

The local-server security guidance adds a second reason to keep the roster small: *"Because all configured servers share the model's context, every server you add extends the surface the others are exposed to"* ([Local server security — Treat Tool Definitions as Untrusted Input](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/local-server-security#treat-tool-definitions-as-untrusted-input)).

**MCP guidance.**
- [Tools — Listing Tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools#listing-tools): `tools/list` "supports pagination and caching".
- [Pagination](https://modelcontextprotocol.io/specification/2026-07-28/server/utilities/pagination): "Servers **SHOULD** provide stable cursors"; clients must treat a missing `nextCursor` as the end.
- [Caching](https://modelcontextprotocol.io/specification/2026-07-28/server/utilities/caching): `ttlMs` is the server's freshness hint; `0` means immediately stale. The `server/discover` example in the spec uses `ttlMs: 3600000`.
- [Client best practices](https://modelcontextprotocol.io/docs/2026-07-28/develop/clients/client-best-practices#progressive-tool-discovery): progressive discovery, and the 1%–5% threshold.

**Recommendation (in order of value per unit of work).**
1. **Set a cache hint.** Pass `cache_hints={...: CacheHint(ttl_ms=300_000)}` to `MCPServer` (the constructor accepts it — `MCPServer.__init__(..., cache_hints=...)`). The catalog is static for the process lifetime, so a long TTL is honest. This alone lets a client fetch once per session instead of once per turn.
2. **Trim the published schemas.** Drop property-level `title` from the output models (74.9 KB, and the auto-generated values are mangled — see L2), and publish nullable fields as `type: ["string", "null"]` instead of `anyOf: [{type: string}, {type: null}]`. Together these are ~15–20% of the payload with zero loss of validation.
3. **Merge the IPv4/IPv6 pairs** behind an `ip_family` parameter, as the audit composites already do (`audit_firewall_rules` takes `ip_family`; `firewall_rule_list_ipv4`/`_ipv6` do not). This removes ~40 tools and ~150 KB of duplicated schema, and removes the inconsistency between the two families.
4. **Paginate `tools/list`** if the SDK allows it, so a client that caps page size can still enumerate.
5. **Add the passive-context channel** (see M3): the OpenAPI contract, the coverage matrix and the read-only-mode description are natural `resources`; "audit my rule base" and "explain why this flow is blocked" are natural `prompts`. Both are cheaper than tool definitions and are what the spec intends them for.

---

#### H2 — 144 of 152 tools require a non-standard `request` wrapper, and the explanation ships a wrong example on 103 of them

**What.** Every tool with arguments publishes a single top-level property, `request`, whose value is the real argument object:

```json
{"type":"object","properties":{"request":{"$ref":"#/$defs/DeleteFirewallRuleInput"}},"required":["request"],"additionalProperties":false}
```

The project knows this is unusual and appends one sentence to the description of every wrapped tool (`src/sophos_firewall_mcp/tools/__init__.py:168-171`, applied at `:459-472`):

> Arguments are passed inside a `request` object, for example `{"request": {"page": 1}}`, not at the top level.

That example is **hard-coded to `page`**, which exists on only **41 of the 144** wrapped tools. On the other **103** — every `get`, `create`, `update`, `delete`, `move`, `set_enabled`, `clone`, `disconnect`, and every object CRUD — the sentence tells the model to send a field the tool does not accept. The delete tool's own description ends with an example that would be rejected:

```
firewall_rule_delete_ipv4: "... Arguments are passed inside a `request` object, for example
{"request": {"page": 1}}, not at the top level."
```

**Where.**
- `src/sophos_firewall_mcp/tools/__init__.py:168-171` — `_REQUEST_WRAPPER_NOTE`, the hard-coded `page` example.
- `src/sophos_firewall_mcp/tools/__init__.py:459-472` — `_document_request_wrapper`, applied to all 144.
- `src/sophos_firewall_mcp/tools/__init__.py:315-316` — the call site in `register_tool`.
- `README.md` — **no mention** of the wrapper anywhere (verified by grep); the only place a human integrator can learn the convention is a tool description.

**Why it matters for a client/agent.** The wrapper is legal — `arguments` is a JSON object and nesting is not forbidden — but it is a per-call failure mode that the ecosystem does not share. The spec's own examples are flat (`{"location": "New York"}` in [Tools — Calling Tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools#calling-tools)), and every model's prior is flat arguments. The server's own probe shows what happens when a model follows its prior:

```
isError: true
"invalid arguments: request is required; page is not an accepted argument; accepted arguments are request"
```

That message is good — it names the accepted argument — but it costs a round trip on the first call of every session, and the appended sentence makes it *worse* on 103 tools by suggesting a field that does not exist. The project's own docstring is candid about the cause (`tools/__init__.py:68-72`: "the SDK's single-argument convention is unusual for MCP, where flat arguments are the norm").

**MCP guidance.**
- [Tools — Calling Tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools#calling-tools): the canonical call shape is `{"name": ..., "arguments": {"location": "New York"}}`.
- [Tools — Tool](https://modelcontextprotocol.io/specification/2026-07-28/server/tools#tool): `inputSchema` is "a JSON Schema object defining the expected parameters"; nothing requires a wrapper, and nothing recommends one.
- [Tools — Error Handling](https://modelcontextprotocol.io/specification/2026-07-28/server/tools#error-handling): tool execution errors exist to give the model "actionable feedback … to self-correct and retry with adjusted parameters". A wrapper that must be explained in prose spends that recovery budget on every first call.

**Recommendation.**
1. **Fix the example now** (one-line change): derive it from the tool's own schema — use the first required property, or a neutral `{"request": {...}}` — instead of hard-coding `page`. This is the cheapest correctness fix in the report.
2. **Put the convention in `INSTRUCTIONS`** (`server.py:69-75`). The server-level `instructions` string is the one place every client shows the model before any tool call; the wrapper belongs there, not only in 144 descriptions.
3. **Document it in `README.md`** with one concrete call example per shape (a no-argument tool, a paginated list, a delete).
4. **Consider flattening** in a future major version. The SDK's `MCPServer.add_tool` accepts a function signature; the wrapper comes from the single-`request`-model convention. If the SDK cannot be made to publish flat arguments, a thin per-tool handler with explicit parameters would. This is a breaking change and belongs in a 0.7/1.0 discussion, not a patch.

---

### Medium

#### M1 — Every successful result is duplicated: the full payload is returned as both `content` text and `structuredContent`

**What.** The SDK returns `CallToolResult(content=unstructured_content, structured_content=structured_content)` (`mcp/server/mcpserver/utilities/func_metadata.py:226`), and `_convert_to_content` serializes a Pydantic model to pretty-printed JSON text (`:652-655`). So a 70 KB rule list is sent as ~70 KB of text **plus** ~70 KB of `structuredContent`. The server knows this and compensates in prose on five tools:

> "The MCP SDK returns the payload both as a text block and as structuredContent; read one of them, not both." — `tools/firewall_rules.py:442,465`, `tools/nat_rules.py:260,380`, `tools/services_objects.py:282`

**Where.** SDK behaviour, not project code; the project's mitigation is the five description sentences above.

**Why it matters.** It doubles the token cost of every read, which is the dominant cost of this server (list tools return 28–70 KB per page). The mitigation sentence is model-facing prose about the SDK, not about the firewall, and it consumes description budget on the tools that are already the largest.

**MCP guidance.** [Tools — Structured Content](https://modelcontextprotocol.io/specification/2026-07-28/server/tools#structured-content): *"For backwards compatibility, a tool that returns structured content SHOULD also return the serialized JSON in a TextContent block."* The duplication is therefore **spec-sanctioned**, not a violation — which is why this is Medium and not High.

**Recommendation.** Keep the duplication (it is the spec's SHOULD and the SDK's behaviour), but move the "read one of them" guidance from five tool descriptions into `INSTRUCTIONS`, where it is stated once. If the SDK ever exposes a way to return a short text summary alongside `structuredContent`, prefer that for the large list tools.

---

#### M2 — `serverInfo.version` is empty, and the server publishes no `title`, `description`, `website_url` or `icons`

**What.** Both eras report `"version": ""`:

```json
"serverInfo": {"name": "Sophos Firewall MCP Server", "version": ""}
```

`MCPServer` takes `version: str = ''` and the factory never passes it (`server.py:143-148`). The same constructor accepts `title`, `description`, `website_url` and `icons`; none are set.

**Where.** `src/sophos_firewall_mcp/server.py:143-148`.

**Why it matters.** `serverInfo` is how a client identifies the build in its UI, its logs and its bug reports. An empty version makes "which release produced this behaviour?" unanswerable from the client side, and the project ships a `CHANGELOG.md` with breaking changes between 0.4.0, 0.5.0 and 0.6.0 — exactly the case where the version matters. The spec's own `server/discover` example shows `"version": "1.0.0"` ([Discovery](https://modelcontextprotocol.io/specification/2026-07-28/server/discover#response)).

**MCP guidance.** [Discovery](https://modelcontextprotocol.io/specification/2026-07-28/server/discover): the response carries the server's "identity"; `Implementation.version` is a required string. [Tools — Tool](https://modelcontextprotocol.io/specification/2026-07-28/server/tools#tool) documents `title` as the human-readable display name.

**Recommendation.** Pass `version=__version__` (the package already has one in `pyproject.toml`; expose it via `importlib.metadata.version("sophos-firewall-mcp-server")`), plus `title="Sophos Firewall MCP"`, `description=...` and `website_url=...`. One-line change, immediate diagnostic value.

---

#### M3 — `prompts` and `resources` capabilities are declared but empty; the server offers only the most expensive channel

**What.** `server/discover` and `initialize` both advertise:

```json
"prompts": {"listChanged": false},
"resources": {"listChanged": false, "subscribe": false}
```

but `prompts/list`, `resources/list` and `resources/templates/list` all return empty arrays. The server registers 152 tools and zero resources and zero prompts.

**Where.** `src/sophos_firewall_mcp/server.py:143-148` (no `add_resource`/`add_prompt` calls anywhere in `src/`).

**Why it matters.** The three primitives exist for different jobs ([Server concepts](https://modelcontextprotocol.io/docs/2026-07-28/learn/server-concepts#core-server-features)): tools are model-controlled actions, resources are application-controlled passive context, prompts are user-controlled templates. This server has a large body of passive context that a model needs but that is currently crammed into tool descriptions and `instructions`:

- the OpenAPI contract (`firewall_config_openapi.yaml`) and the coverage matrix (`docs/API-COVERAGE.md`);
- the read-only-mode contract and the annotation policy;
- the "one page per call, `page_size` defaults to 10" pagination rule;
- the "read one of `content`/`structuredContent`" rule.

And it has obvious prompt candidates: "audit my firewall rule base", "explain why this flow is blocked", "find unused objects". Declaring the capabilities while publishing nothing also costs a client two extra round trips (`prompts/list`, `resources/list`) that always return empty.

**MCP guidance.** [Resources](https://modelcontextprotocol.io/specification/2026-07-28/server/resources): resources "allow servers to share data that provides context to language models, such as files, database schemas, or application-specific information". [Prompts](https://modelcontextprotocol.io/specification/2026-07-28/server/prompts): prompt templates "allow servers to provide structured messages and instructions". [Server concepts](https://modelcontextprotocol.io/docs/2026-07-28/learn/server-concepts): the three-way split is the protocol's core design.

**Recommendation.** Either (a) register 3–5 resources (`sophos://contract/openapi`, `sophos://coverage`, `sophos://read-only-policy`) and 2–3 prompts, which also lets H1's description budget shrink; or (b) if the SDK cannot suppress the capability declaration, accept the empty lists but stop treating them as free — they are two wasted round trips per session.

---

#### M4 — Internal planning markers leak into published descriptions and schemas

**What.** Model-facing text contains internal decision IDs, planning-document references and lab notes:

| Marker | Tools affected |
|---|---|
| `M11`/`M12`/`M13`-style decision IDs | 12 tools (schemas) |
| "the contract" (meaning the OpenAPI file) | 70 tools (schemas), 9 tools (descriptions) |
| "the lab appliance" | 13 tools (schemas), 6 tools (descriptions) |
| "live observation, 2026-11-15" | 2 tools |
| `issue #` | 1 tool |

(`PLAN.md` and `ADR-` do **not** reach the published surface — I checked; the rationale for those stays in docstrings that Pydantic does not publish.)

Concrete examples:
- `src/sophos_firewall_mcp/models/firewall.py:967` — "``page_size`` defaults to 10 (M11): a firewall rule is a large object (the lab appliance's 48-rule base is ~70 KB of JSON)…" — this docstring reaches the published `inputSchema` description.
- `src/sophos_firewall_mcp/models/nat.py:501` — same pattern.
- `src/sophos_firewall_mcp/models/users.py:530` — "the appliance accepts ``page``/``pageSize``/``pageTotal`` (live observation, 2026-11-15) but v1 does not expose them".
- `src/sophos_firewall_mcp/models/objects.py:1512` — "live observation, 2026-11-15: all four enum values return the same mixed page".

**Why it matters.** These strings are read by the model as instructions ([Local server security — Treat Tool Definitions as Untrusted Input](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/local-server-security#treat-tool-definitions-as-untrusted-input)). "M11" and "PLAN.md" are meaningless to a model and dilute the sentence that matters; "the lab appliance" tells the model about an environment it cannot see and may over-generalize from. They also disclose internal process to anyone who runs `tools/list`.

**MCP guidance.** [Tools — Tool](https://modelcontextprotocol.io/specification/2026-07-28/server/tools#tool): `description` is "a human-readable description of the tool" used "to improve the LLM's understanding". [Local server security](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/local-server-security#treat-tool-definitions-as-untrusted-input): descriptions are an injection surface and should be reviewed as such.

**Recommendation.** Keep the engineering rationale in the Python docstrings but move it out of the published schema: Pydantic publishes the model docstring as the schema `description`, so either shorten the docstrings to model-facing prose and keep the rationale in comments, or set `model_config = ConfigDict(json_schema_extra=None)` / use `Field(description=...)` for the published text. A grep-based test that fails on `M\d+`, `the contract`, `lab appliance`, `issue #` and `live observation` in the published surface would prevent regressions.

---

#### M5 — The IPv4/IPv6 split doubles the surface and is inconsistent with the audit composites

**What.** 46 tools end in `_ipv4` and 40 in `_ipv6`; 40 pairs exist, and 12 pairs publish **byte-identical** output schemas. The paired output schemas total **308,486 bytes** — more than half of the 598 KB output payload. Meanwhile the three audit composites already take an `ip_family` parameter (`audit_firewall_rules`, `explain_connectivity`, `find_object_usage`), so the server uses two different conventions for the same axis.

**Where.** `src/sophos_firewall_mcp/tools/firewall_rules.py:1-40` (the 16-tool table), `src/sophos_firewall_mcp/tools/nat_rules.py`, `src/sophos_firewall_mcp/tools/hosts_objects.py`; the `ip_family` convention is in `src/sophos_firewall_mcp/tools/audit.py`.

**Why it matters.** It is the single largest contributor to H1's payload, it doubles the number of names a model must choose between (`firewall_rule_list_ipv4` vs `firewall_rule_list_ipv6` — a coin flip when the user says "list the firewall rules"), and it contradicts the server's own `ip_family` convention. The spec's tool-name guidance does not forbid either shape, but it does say names should be unambiguous ([Tools — Tool Names](https://modelcontextprotocol.io/specification/2026-07-28/server/tools#tool-names)).

**Recommendation.** In a breaking release, collapse each pair into one tool with `ip_family: "ipv4" | "ipv6"` (defaulting to `ipv4`), matching the audit composites. This removes ~40 tools and ~150 KB, and makes the family axis consistent. If the split is kept, at minimum document the rule in `INSTRUCTIONS` and make the two descriptions cross-reference each other.

---

#### M6 — Long-running composite tools have no progress reporting, no cancellation contract and no documented worst case

**What.** `audit_firewall_rules` and `find_object_usage` walk the rule base, NAT rules, zones, interfaces and object collections with a budget of `PAGE_SIZE = 100`, `MAX_ITEMS_PER_COLLECTION = 500`, `MAX_PAGES_PER_COLLECTION = 5` and `MAX_PAGES_TOTAL = 80` (`src/sophos_firewall_mcp/tools/audit.py:171-180`). That is up to **80 sequential HTTP requests** per call. The client timeout is 30 s per request (`config.py:46`), so the theoretical worst case is tens of minutes. No tool calls `ctx.report_progress`, and no description states an expected duration or a bound.

**Where.** `src/sophos_firewall_mcp/tools/audit.py:171-180`, `:806-825` (the budget checks); no `report_progress` anywhere in `src/` (verified by grep).

**Why it matters.** A client that implements a per-call timeout (the spec tells clients to: [Tools — Security Considerations](https://modelcontextprotocol.io/specification/2026-07-28/server/tools#security-considerations), "Implement timeouts for tool calls") will abandon the call with no way to tell "still working" from "hung". The model then retries, doubling the load on the appliance. The progress utility exists for exactly this ([Progress](https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/progress)).

**MCP guidance.** [Progress](https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/progress): servers **MAY** send `notifications/progress` for long-running work; [Cancellation](https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/cancellation): servers **SHOULD** stop work on a cancelled request.

**Recommendation.** Call `ctx.report_progress(...)` once per page in the audit walk (the SDK exposes it on `Context`), and add one sentence to each composite description: "Reads up to 80 pages; expect a few seconds on a small rule base and up to a minute on a large one." That converts an opaque hang into a bounded, observable operation.

---

#### M7 — `page` and `page_total` are published without descriptions

**What.** All 41 paginated tools publish `page`, `page_size` and `page_total`. Only `page_size` has a description. `page` has `default: 1, minimum: 1` and no text; `page_total` has `default: false` and no text at all. The output side documents the consequence carefully (`models/common.py:37-78`: `total` counts pages, `items` counts items, both present only when `page_total=true`), but the input flag that turns them on is invisible.

**Where.** `src/sophos_firewall_mcp/models/firewall.py:984-988`, `src/sophos_firewall_mcp/models/nat.py:518`, `src/sophos_firewall_mcp/models/network.py:264`, `src/sophos_firewall_mcp/models/users.py:221`, `src/sophos_firewall_mcp/models/vpn.py:241`, `src/sophos_firewall_mcp/models/objects.py:251` (a bare `bool = False`).

**Why it matters.** A model cannot discover `page_total` from the schema, so it will never ask for `pages.total`/`pages.items` and will page blindly until an empty page. The `Pages` model's excellent documentation is unreachable in practice.

**MCP guidance.** [Tools — Tool](https://modelcontextprotocol.io/specification/2026-07-28/server/tools#tool): property descriptions are how the model learns what a parameter does.

**Recommendation.** Add `Field(description=...)` to `page` ("1-based page number; the appliance rejects 0") and `page_total` ("also return `pages.total` (number of pages) and `pages.items` (number of items); costs one extra count on the appliance"). One-line changes on six models.

---

#### M8 — `README.md` documents neither the calling convention nor the context cost

**What.** The README is otherwise excellent (419 lines, accurate, with a security model and a known-limitations section), but it never mentions:
- the `request` wrapper (grep: no occurrence of "wrapper" or a tool-call example);
- the size of `tools/list` or its token cost;
- that the server publishes no resources or prompts.

**Where.** `README.md` (whole file); the only wrapper documentation is the appended sentence in the tool descriptions.

**Why it matters.** A human integrator writing a client, or debugging why their agent's first call fails, has no document to read. The project's own `docs/architecture/sophos-rest-api-redesign/` folder has a `MCP-INSTALLATION.md` about panel registration but nothing about the call shape.

**Recommendation.** Add a short "Calling the tools" section to the README with three examples (no-argument, paginated list, delete) and a "Context cost" note with the measured `tools/list` size and the recommendation to use progressive discovery. This is documentation, not code, and it is the cheapest way to reduce support load.

---

### Low

#### L1 — An unknown tool returns `isError: true` instead of a JSON-RPC protocol error

**What.** `tools/call` with `name: "nope"` returns a tool result with `isError: true` and text `"Unknown tool: nope"`. The spec classifies "Unknown tool" as a **protocol error** — "issues with the request structure itself that models are less likely to be able to fix" — returned as a standard JSON-RPC error (`-32602`), not as a tool execution error.

**Where.** SDK behaviour (`_handle_call_tool`); observed on the wire.

**Why it matters.** A client that distinguishes protocol errors from tool errors (to decide whether to retry, or to surface a bug) will misclassify this. The model sees a recoverable-looking error for a request that can never succeed.

**MCP guidance.** [Tools — Error Handling](https://modelcontextprotocol.io/specification/2026-07-28/server/tools#error-handling).

**Recommendation.** Low priority because the SDK owns it; if the SDK exposes a hook, map unknown-tool to `-32602`. Otherwise record the deviation in the README's known limitations.

---

#### L2 — Auto-generated schema titles are mangled and add 75 KB of noise

**What.** Pydantic derives `title` from field names, producing `"Idorname"`, `"Ruletype"`, `"Logtraffic"`, `"Page Size"`, and the argument model publishes `"title": "firewall_rule_delete_ipv4Arguments"` — an internal Python name. There are 3,486 such titles in the output schemas (74,892 bytes).

**Where.** Every output model; e.g. `firewall_rule_delete_ipv4` publishes `"title": "Idorname"` and `"title": "firewall_rule_delete_ipv4Arguments"`.

**Why it matters.** Clients that render property titles show "Idorname"; the argument-model title leaks an internal identifier into the public schema. It is also 12.5% of the output payload (see H1).

**MCP guidance.** [Tools — Tool](https://modelcontextprotocol.io/specification/2026-07-28/server/tools#tool): `title` is for human-readable display; a mangled auto-title is worse than none.

**Recommendation.** Use a `GenerateJsonSchema` subclass that omits property-level `title` (or set `json_schema_extra` on the models to strip it), and keep titles only where they are deliberate. Do not set `ConfigDict(title=None)` — Pydantic expects a string there.

---

#### L3 — No rate limiting on tool invocations

**What.** Nothing in `src/` throttles tool calls or bounds concurrency (grep: no `rate`, `throttle`, `semaphore`).

**Why it matters.** The spec's Security Considerations list "Rate limit tool invocations" among the things servers **MUST** do. For a local STDIO server with one trusted client this is largely the client's job, and the appliance itself rate-limits, but the MUST is unconditional and a runaway agent loop can hammer the firewall.

**MCP guidance.** [Tools — Security Considerations](https://modelcontextprotocol.io/specification/2026-07-28/server/tools#security-considerations).

**Recommendation.** Add a small async semaphore (e.g. 4 concurrent requests) around the shared client, or document explicitly why the appliance's own limits are considered sufficient. The former is ~10 lines and also protects the appliance from a model that fans out.

---

#### L4 — Destructive operations rely on annotations alone; no elicitation or confirmation

**What.** The 54 mutation tools carry correct `destructiveHint`/`idempotentHint` annotations, but the server never uses `elicitation/create` (or an `InputRequiredResult`) to confirm a destructive call. The spec says clients **SHOULD** prompt for confirmation on sensitive operations, and servers **MAY** use elicitation.

**Where.** No `elicit` usage in `src/` (verified by grep); annotations are set in `src/sophos_firewall_mcp/tools/__init__.py:570-599`.

**Why it matters.** A client that does not implement confirmation (many do not) will delete a firewall rule on the model's first attempt. The annotations are hints, and the spec warns clients to treat them as untrusted.

**MCP guidance.** [Tools — User Interaction Model](https://modelcontextprotocol.io/specification/2026-07-28/server/tools#user-interaction-model): "there **SHOULD** always be a human in the loop"; [Elicitation](https://modelcontextprotocol.io/specification/2026-07-28/client/elicitation).

**Recommendation.** Optional. If added, gate only the highest-blast-radius tools (`*_delete_*`, `live_user_disconnect`) behind an elicitation that names the object; keep the rest annotation-only so the server stays usable in clients without elicitation support.

---

#### L5 — `openWorldHint: true` on all 152 tools

**What.** Every tool publishes `openWorldHint: true`, including pure reads of a single appliance.

**Why it matters.** The hint describes the tool's interaction domain, not the trustworthiness of its data ([ToolAnnotations](https://modelcontextprotocol.io/specification/2026-07-28/schema#toolannotations): "If true, this tool may interact with an 'open world' of external entities… whereas that of a memory tool is not"). A firewall appliance is a single, known external system; a client that uses the hint to decide how much to trust or sandbox a result will treat every read as open-world. The project's own rationale (`tools/firewall_rules.py:53-57`) is defensible but conservative.

**Recommendation.** Low priority; if changed, set `openWorldHint: false` for the read tools that return bounded, appliance-owned configuration and keep `true` for the composites whose results depend on the whole configuration. Document the choice either way.

---

#### L6 — `_env_guard` hard-exits when `mcp` resolves outside `sys.prefix`

**What.** `verify_local_mcp()` exits with status 2 if the imported `mcp` package's path does not start with `sys.prefix` (`src/sophos_firewall_mcp/_env_guard.py:76-81`). The intent is good (a shadowed venv otherwise produces an empty error), but the check is a string-prefix test that will also fire in legitimate layouts: a virtualenv created with `--system-site-packages` where `mcp` comes from the system, a `pipx`/`uv tool` install whose dependency environment is not the interpreter's `sys.prefix`, or a container that installs the package into a different prefix than the interpreter reports.

**Why it matters.** A hard exit is the right response to a broken environment, but a false positive turns a working install into "cannot start" with a message that tells the user to unset `PYTHONPATH` — which will not help.

**Recommendation.** Downgrade the prefix check to a warning on stderr and let the real import decide, or compare against `sysconfig.get_paths()["purelib"]`/`platlib` rather than `sys.prefix`. Keep the `mcp.server.mcpserver` import check as a hard failure (that one is unambiguous).

---

#### L7 — `ttlMs: 0` on a static catalog

Folded into **H1** for the fix, recorded separately because it is a distinct spec-level observation: the caching spec requires a `ttlMs` (the server complies) but `0` means "immediately stale", so a client re-fetches a catalog that cannot change. The `MCPServer` constructor accepts `cache_hints`; the server does not pass it.

---

## 3. What is already good

This is a strong implementation, and the report would be misleading without saying so.

**Protocol and transport**
- **Both protocol eras work.** `server/discover` returns `supportedVersions: ["2026-07-28"]`, `resultType: "complete"`, `ttlMs`, `cacheScope` and `_meta.serverInfo`; a legacy client that sends `initialize` first negotiates `2025-11-25`; `initialize` after discovery is correctly refused with `-32022`. This is the versioning model implemented properly ([Versioning](https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning)).
- **STDIO is clean.** stdout carries only JSON-RPC frames for the whole session; all diagnostics go to stderr via `logging.basicConfig(stream=sys.stderr)` (`server.py:185-189`); the process exits `0` promptly when stdin closes. This is exactly the [stdio transport](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/stdio) contract and the [build-server logging guidance](https://modelcontextprotocol.io/docs/2026-07-28/develop/build-server#logging-in-mcp-servers).
- **Capabilities are honest about subscriptions.** `subscriptions=False` is passed deliberately because the catalog is static (`server.py:143-148`), so the server does not advertise `subscriptions/listen` or `listChanged` it cannot honour.
- **Deterministic ordering.** Registration order is fixed, so `tools/list` is stable across requests — the spec's SHOULD for cache-friendliness ([Tools — Capabilities](https://modelcontextprotocol.io/specification/2026-07-28/server/tools#capabilities)).
- **Graceful shutdown.** The lifespan creates exactly one client and closes it in `finally` (`server.py:120-141`); `aclose` is idempotent.

**Tool design**
- **Names are clean and unique.** 152 unique lower-snake_case names, 8–39 characters, enforced by a regex at registration (`tools/__init__.py:108`, `:557-567`) — stricter than the spec's 1–128 and character set.
- **Every tool has a title, a description and both schemas.** 152/152 on all four. Descriptions state what the tool does, when to use it, what it returns and its limits (e.g. `firewall_rule_list_ipv4` documents the page size, the WAF exclusion, the derived `position` and the payload size).
- **Annotations are correct and enforced.** Read tools get `readOnlyHint: true` and are *rejected* if they declare write hints; mutation tools must declare both `destructiveHint` and `idempotentHint` explicitly (`tools/__init__.py:570-599`). The values are right: `delete` → destructive+idempotent, `create` → additive+non-idempotent, `set_enabled` → destructive+idempotent. This is better than most servers in the ecosystem.
- **Read-only mode is real.** `SOPHOS_READ_ONLY_MODE=true` removes the 54 mutation tools from the registry entirely (verified: 98 tools, 0 mutations), not merely hides them — defence in depth on top of a read-only Sophos profile.
- **No raw REST escape hatch.** No tool accepts a URL, path, header, method or arbitrary JSON body; paths are module constants and the client refuses absolute URLs, `//`, `..`, `%2e`, `?`, `#` and control characters (`client.py:270-305`).

**Schemas**
- **Closed inputs.** Root `additionalProperties: false` on all 152, and **zero** open nested objects — every object in every input schema is closed. The SDK's argument model is replaced with a closed subclass so unknown arguments are rejected rather than silently dropped (`tools/__init__.py:432-456`).
- **Object-rooted, typed outputs.** All 152 output schemas are object-rooted with `required` where it matters, and the SDK validates `structuredContent` against the model before returning it.
- **Good use of enums, bounds and defaults.** `page_size` is `1..100` with a documented default of 10 on all 41 paginated tools; `ip_family` is an enum; object names are validated against the documented `sfos-object-name` format (`models/common.py:110-170`).

**Results and errors**
- **Errors are sanitized and actionable.** `tool_error` maps each failure class to a distinct sentence, appends the HTTP status and the operation, strips `<>` and control characters, and bounds the message at 300 characters (`tools/__init__.py:336-379`, `:602-612`). 401 and 403 get different messages because they have different fixes. The API key is scrubbed from every exception (`client.py:409-413`).
- **Argument errors are sanitized too.** The raw Pydantic dump (internal model name, rejected values, docs URL) is replaced with `"invalid arguments: request is required; page is not an accepted argument; accepted arguments are request"` (`tools/__init__.py:492-546`).
- **Writes are never retried.** A transport failure on a write raises `SophosAmbiguousWriteError` with "the write may or may not have been applied; read the object back before retrying" (`client.py:352-358`, `:400-407`). Reads retry at most twice, only for connect/read timeouts and 502/503/504, with jittered backoff.
- **Pagination cannot silently truncate.** `get_page` requires `items`, preserves `pages` when present, and validates `page >= 1` and `1 <= page_size <= 100` before any I/O (`client.py:188-253`). The `Pages` model documents the `total`-vs-`items` trap explicitly.

**Security**
- **Credentials are isolated.** Exactly one of `SOPHOS_API_KEY`/`SOPHOS_API_KEY_FILE`, stored as `SecretStr`, stripped, never in `repr`/`str`/`model_dump_json`/validation errors (`config.py:158-197`, `:96-106`). This matches the [local-server security guidance](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/local-server-security#isolate-credentials).
- **TLS is on by default**, with an optional private CA bundle; `verify_ssl=false` and a CA bundle are mutually exclusive (`config.py:222-229`).
- **No redirects, no inherited proxy.** `follow_redirects=False` so the Bearer token cannot cross origins; `trust_env=False` so `HTTP(S)_PROXY` cannot route it (`client.py:138-148`).
- **The host cannot be re-pointed.** `SOPHOS_HOST` is a bare hostname/IP — no scheme, userinfo, port, path, query or fragment — and the base URL is HTTPS by construction (`config.py:109-155`, `:238-241`).
- **Least privilege is documented.** The README's security model tells operators to use a read-only Sophos administrator profile and `SOPHOS_READ_ONLY_MODE=true` together.

**Repository practice**
- **Tests pin the surface.** 1133 tests, including `tests/test_tool_surface.py`, which asserts the exact 152-tool set, the 54/98 split, the read-only filter, the input snake_case convention at every depth, the output camelCase convention at every depth, and the annotation values. This is the kind of test that catches a regression before a client does.
- **CI is real.** Tests on Python 3.11–3.14 with `uv sync --locked`; flake8 + mypy + black + a coverage-drift check; `pip-audit` on the locked runtime resolution; Semgrep with pinned packs; a separate live workflow; Docker build/publish; Dependabot.
- **Versioning and changelog are disciplined.** `CHANGELOG.md` (386 lines) records every breaking change with the migration path; `docs/release/RELEASE-0.6.0.md` exists; the README states the current release and the breaking changes.
- **Evidence is recorded.** `docs/live-evidence/` contains the live-run records, including what was *not* exercised — an unusual and valuable honesty.

---

## 4. Prioritized roadmap

### Do first (before the next release; all cheap, no breaking change)

| # | Action | Finding | Effort |
|---|---|---|---|
| 1 | Fix `_REQUEST_WRAPPER_NOTE` to derive its example from the tool's own schema (or use a neutral `{"request": {...}}`) | H2 | 1 line |
| 2 | Put the wrapper convention and the "read one of `content`/`structuredContent`" rule in `INSTRUCTIONS` | H2, M1 | 5 lines |
| 3 | Pass `version=`, `title=`, `description=`, `website_url=` to `MCPServer` | M2 | 4 lines |
| 4 | Pass `cache_hints` with a long TTL for the static catalog | H1, L7 | 3 lines |
| 5 | Add descriptions to `page` and `page_total` on the six pagination models | M7 | 6 lines |
| 6 | Document the calling convention and the `tools/list` size in `README.md` | M8 | ~30 lines |
| 7 | Add a test that fails on `M\d+`, `the contract`, `lab appliance`, `issue #`, `live observation` in the published surface | M4 | ~20 lines |

### Do next (one focused change each)

| # | Action | Finding | Effort |
|---|---|---|---|
| 8 | Drop property-level `title` from output models; publish nullable fields as `type: [X, "null"]` | H1, L2 | ~1 day, touches every model |
| 9 | Add `ctx.report_progress` to the audit walk and a latency sentence to the composite descriptions | M6 | ~half day |
| 10 | Register 3–5 resources and 2–3 prompts (contract, coverage, read-only policy; audit/explain/find-unused) | M3 | ~1 day |
| 11 | Add a concurrency semaphore around the shared client | L3 | ~10 lines |
| 12 | Downgrade the `_env_guard` prefix check to a warning | L6 | ~10 lines |

### Consider for a breaking release (0.7/1.0)

| # | Action | Finding | Effort |
|---|---|---|---|
| 13 | Collapse the 40 IPv4/IPv6 pairs behind `ip_family`, matching the audit composites | M5, H1 | large; breaking |
| 14 | Flatten the `request` wrapper if the SDK allows it | H2 | large; breaking |
| 15 | Elicitation for the highest-blast-radius deletes | L4 | medium; optional |
| 16 | Revisit `openWorldHint` per tool | L5 | small; judgment |

### Optional / record-only

- L1 (unknown tool → `-32602`): SDK-owned; document it.
- L7 (`ttlMs: 0`): fixed by #4.

---

## 5. What I could not verify

- **No live appliance.** This environment has no `SOPHOS_HOST`/API key, so I could not exercise a real successful tool call end-to-end. I verified the result shape from the SDK's conversion code (`func_metadata.py:206-226`, `:624-655`) and from the server's own descriptions, not from a live response. The `docs/live-evidence/` records cover what was exercised on SFOS 23.0.0 GA-Build371.
- **Client-specific limits.** I could not verify how Claude Desktop, VS Code, Cursor or Antigravity IDE handle a 950 KB `tools/list` (truncation threshold, frame limit, progressive-discovery support). The 1 MB frame-limit risk in H1 is a reasoned concern, not a measured failure.
- **Concurrency and cancellation.** I did not test two simultaneous tool calls, `notifications/cancelled` mid-audit, or the SDK's behaviour when a client disconnects during a long composite call.
- **The Docker image and the live workflow.** I read `Dockerfile`, `docker-compose.yml` and `.github/workflows/live.yml` but did not build or run them.
- **TLS against a real appliance.** The `verify_ssl`/`ca_bundle` paths are covered by unit tests with mocked transports; I did not handshake with a real SFOS certificate.
- **The `mcp` 2.3.0 private seam.** `tools/__init__.py:397-456` depends on `MCPServer._tool_manager`, `Tool.fn_metadata.arg_model` and `Tool.parameters`. The project pins and tests it, but I cannot predict when the SDK will move it; the failure mode is a `RuntimeError` at registration, which is at least loud.
- **Whether the `request` wrapper can be flattened with `mcp` 2.3.0.** I did not prototype it; the recommendation is conditional on the SDK's `add_tool` capabilities.
- **The `openWorldHint` judgment.** Whether a single-appliance server should be `false` is a design opinion; I recorded the tradeoff rather than a defect.

---

## Appendix A — measured surface (reproducible)

```
tools: 152 (unique 152), names 8..39 chars
annotations:
  (readOnly=True,  destructive=None, idempotent=None, openWorld=True)  x 98
  (readOnly=False, destructive=False, idempotent=False, openWorld=True) x 17
  (readOnly=False, destructive=True,  idempotent=True,  openWorld=True) x 25
  (readOnly=False, destructive=False, idempotent=True,  openWorld=True) x 11
  (readOnly=False, destructive=True,  idempotent=False, openWorld=True) x 1
read-only mode: 98 tools, 0 mutations
tools/list: 950,591 bytes (~238k tokens)
  input schemas 257,348 B | output schemas 598,276 B | descriptions 57,295 B
  largest tool nat_rule_create_ipv4 20,140 B | median 5,170 B
  output 'title' keys 3,486 = 74,892 B | anyOf-null wrappers 1,196 | defaults 2,416
  identical output schemas shared by >1 tool: 23 schemas / 74 tools
  ipv4/ipv6 pairs 40 (12 byte-identical), 308,486 B in paired output schemas
request wrapper: 144/152 tools; 103/144 have no 'page' field (example wrong); 141/144 via $ref
pagination: 41 tools, page_size default 10 on all; page/page_total undescribed
internal markers: 'the contract' 70 schemas/9 descs; 'lab appliance' 13/6; M-IDs 12; 'live observation' 2; 'issue #' 1
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

# protocol probes: server/discover, tools/list, prompts/list, resources/list,
# unknown tool, flat arguments — see section 1.2; the server is spawned with
# `python -m sophos_firewall_mcp.server` and spoken to over stdin/stdout.

# gates
uv run --no-sync pytest -q
uv run --no-sync mypy src
uv run --no-sync flake8 src tests
uv run --no-sync black --check src tests
```

---

*This review did not modify `src/`, `tests/`, `scripts/`, `pyproject.toml`, workflows or any other document. The only write is this file.*
