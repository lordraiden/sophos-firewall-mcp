# ADR-001 — REST client and model-generation strategy

| Field | Value |
|---|---|
| **Status** | Accepted — the repository owner ratified the client decision and the first-release scope on 15 November 2026 (§10) |
| **Date** | 2026-11-15 |
| **Issue** | [#24](https://github.com/lordraiden/sophos-firewall-mcp/issues/24) — audit OpenAPI and define API coverage |
| **Phase** | 1 — REST foundation (`01-PHASE-1-FOUNDATION.md`, step 1 / T1) |
| **Deciders** | `contract` (author), `client` (#25 consumer), Lead, repository owner |
| **Blocks** | #25 (typed REST client), and through it #26–#31 |
| **Related** | [PLAN.md](./sophos-rest-api-redesign/PLAN.md) §5, §6, §12; [REFERENCES.md](./sophos-rest-api-redesign/REFERENCES.md) R13/R13a/R13b/R13c; [INDEPENDENT_REVIEW_REPORT.md](./sophos-rest-api-redesign/INDEPENDENT_REVIEW_REPORT.md) §2, §6, §7 |

This ADR records **what was measured**, not what was assumed. Every count below was produced by parsing
`firewall_config_openapi.yaml` with Python; the 8.9 MB file was never read by eye. The bounded proof of
concept (POC) ran outside the git worktree, added no project dependency, and nothing generated was merged.

---

## 1. Context

The project is being rebuilt as a local STDIO MCP server that administers a Sophos Firewall through its
**Configuration REST API** (`https://<host>:<port>/api/firewall-config/v1`, Bearer API key). The checked-in
OpenAPI document is the implementation contract. #25 must deliver one reusable async client, and #27–#31
must add domain tools without re-deciding transport or models.

The open question was whether to hand-write the HTTP transport and Pydantic models, to use a generated
client (`openapi-python-client` ≥ 0.30.0), or to use a hybrid (generated models behind a thin handwritten
transport). The plan explicitly left this open and required evidence from a bounded POC
(PLAN.md §6, §12.3; issue #24 §6).

---

## 2. Contract baseline (measured from the file itself)

### 2.1 Identity

| Fact | Measured value |
|---|---|
| Path | `firewall_config_openapi.yaml` (repository root) |
| SHA-256 | `58c4bc79ac930ce030202e09835865dcb12fcd44e9132e1f4234a1ed1743b1d5` |
| Git blob SHA | `40fca0b25d4d85866f86b90aec77e5559ae27214` (`git ls-tree HEAD`) |
| Size | 8,934,475 bytes |
| `openapi` | `3.0.0` |
| `info.title` | `Sophos Firewall Configuration API` |
| `info.version` | `1.0.0` |
| `info.description` | 2,667 characters; states the base URL, the Bearer API key, the `sfos-object-name*` formats and the JSON Merge Patch (RFC 7396) default for PATCH |
| `servers` | `https://{firewallHost}/api/firewall-config/v1`, variable `firewallHost` default `172.16.16.16:4444` |
| `securitySchemes` | `apiKey`: `type: http`, `scheme: bearer`, `bearerFormat: API key` |
| Global `security` | `[{apiKey: []}]`; **0** operations override it |

### 2.2 Structure

| Fact | Measured value |
|---|---|
| Paths | **384** |
| HTTP operations | **700** — GET 263, POST 210, PATCH 134, DELETE 93; **0** PUT/HEAD/OPTIONS/TRACE |
| `operationId` | **700 present, 700 unique, 0 missing, 0 duplicate** |
| Tags | **132** distinct tag names (`len(doc["tags"]) == 132`; all 132 are used by the 700 operations) |
| `$ref` occurrences | **76** |
| Unique `$ref` targets | **32**, all local `#/components/schemas/*` |
| External / unresolved `$ref` | **0 / 0** (every local pointer resolved) |
| Component schemas | **32**, all referenced, **0** unreferenced, **0** cycles |
| `schema` keyword sites | **4,981** — 339 request bodies + 3,926 response media types + 706 parameters + 10 response headers (`Location` on the 201 responses) |
| Media-type schema sites | **4,265** (339 request-body + 3,926 response media-type); **162,760** JSON nodes under them (objects, arrays and scalars) — reproduces the independent audit's figures |
| Reachable schema objects | **38,539** = 32 component schemas + **38,507 inline** schema objects (unique schema objects reached through `properties`/`items`/`allOf`/`oneOf`/`anyOf`); 52,850 dict nodes |
| Largest inline schema | **1,148 JSON nodes** (373 dict nodes) — `PATCH /firewall/rules/ipv4/{idOrName}` request body |
| Constructs | `allOf` 2,046 · `oneOf` 1,130 · `anyOf` 0 · `discriminator` 26 · `not` 6 · `nullable` 294 |

> **Counting definitions.** Two reproducible definitions are in play, and both are stated here so the
> coverage matrix can pick one. (1) *Media-type schema sites* — the independent audit's convention (report
> §2.2): 339 request-body + 3,926 response media-type schema sites = **4,265**, and every JSON node under
> them (objects, arrays and scalars) = **162,760**. (2) *Reachable schema objects* — every `schema` site plus
> the component schemas, counting each distinct schema object reached through
> `properties`/`items`/`allOf`/`oneOf`/`anyOf` = **38,539** (38,507 inline + 32 component), with 52,850 dict
> nodes. The 10 `Location` response-header schemas and the 706 parameter schemas are excluded from
> definition (1) and included in the 4,981 total. `docs/API-COVERAGE.md` (#24/T4) must state which
> definition it uses.

### 2.3 Operation surface

| Fact | Measured value |
|---|---|
| Operations with a request body | 339 |
| Request media types | `application/json` × 338; `multipart/form-data` × 1 (`importTrustedMacs`, out of scope) |
| Response media types | `application/json` everywhere a body is declared |
| PATCH operations | **134**, **134/134 declare `application/json`**, **0** declare `application/merge-patch+json`. `info.description` documents the RFC 7396 default; the literal string "merge-patch" appears only twice, in the `updateAlertNotificationSettings` operation and request-body descriptions (the catalog-keyed `notifications[]` exception). |
| Paginated GETs | **83** accept `page` (default 1) / `pageSize` (default 50) / `pageTotal` (default false); **0** accept `limit`/`offset`/`cursor` |
| `pageSize` maximum | 100 on exactly `getUsers`, `getNetworkUsers`, `getAdministrators`; no declared maximum elsewhere |
| Path parameters | 283 total: 248 `sfos-object-name-or-id`, 12 `sfos-object-name-lenient-or-id`, 6 `uuid`, **17 untyped** (10 `{idOrName}`, 6 `{name}`, 1 `{floodAttackType}`); **0** name-only |
| Status codes | 401/403/500 on all 700 · 400 on 636 · 200 on 608 · 404 on 272 · 409 on 217 · 201 on 92 · 503 on 1 (`createIpsCustomSignature`) · **429 on 0** |

The status distribution is operation-specific; there is no universal envelope. `200` appears on 608
operations because the 92 create operations declare `201` instead.

---

## 3. Target firmware/build — unresolved prerequisite

**The target SFOS build is not known and is not declared anywhere in the contract.**

- The Sophos API Reference portal declares only `Version: 1.0.0` — the **contract** version, not an SFOS
  version (REFERENCES.md §B, PLAN.md §2).
- SFOS 23.0 GA Build 371 (4 Nov 2026) is the earliest documented release that ships this API
  (REFERENCES.md R05), but nothing ties the project's appliance to that build.
- The lab appliance exposes no version endpoint; `LAB-ACCESS.md` records `Build SFOS: no determinado`
  (undetermined), and `GET /administration/system-settings` returns only `hostname`, `loginDisclaimer` and
  `updatedAt`.
- Live evidence (15 Nov 2026) proves the API answers and authenticates on the lab unit, but **not** the
  build, and no write was attempted.

**Consequence:** this ADR and #25 are decided on the static contract only. Firmware compatibility remains
an explicit prerequisite for #27–#32 and must be recorded per domain in `docs/live-evidence/<domain>.md`
or deferred in `docs/API-COVERAGE.md` with reason, owner and prerequisite. No claim of firmware support is
made here.

---

## 4. Options considered

| ID | Option | Shape |
|---|---|---|
| **A** | Hand-written async HTTPX transport + Pydantic models | One `httpx.AsyncClient`; per-operation Pydantic request/response models written from the YAML; typed error mapping; explicit pagination helper. |
| **B** | `openapi-python-client` ≥ 0.30.0 generated client | Generate the whole package from the YAML, use its `AuthenticatedClient` and endpoint functions. |
| **C** | Hybrid | Generated models behind a thin handwritten transport/adapter; handwritten MCP DTOs on top. |

`openapi-python-client` is pinned to **≥ 0.30.0** because 0.29.1 fixed GHSA-5293-mq8x-g3xj and 0.29.x is
still affected by GHSA-jg6c-wvfg-fx69 (fixed in 0.30.0) — REFERENCES.md R13a/R13b/R13c.

---

## 5. Bounded POC

### 5.1 Method and bounds

Bounds taken from issue #24 §6 and the phase prompt: full document parsed, both approaches exercised on
the **same five representative operations**, no generated code merged, one working day of effort. The
prompt's additional stop condition was applied: generation must finish within ~10 minutes and produce less
than ~50 MB, otherwise stop and record the measurement.

The five operations:

| # | Role | `operationId` | Method / path |
|---|---|---|---|
| 1 | simple GET | `getDnsProtectionStatus` | `GET /network/dns/protection/status` |
| 2 | paginated list | `getUsers` | `GET /authentication/users` |
| 3 | IPv4 firewall-rule create | `createFirewallRuleIpv4` | `POST /firewall/rules/ipv4` |
| 4 | NAT-rule PATCH | `updateNatRuleIpv4ByIdOrName` | `PATCH /nat/rules/ipv4/{idOrName}` |
| 5 | object with nested references | `getFirewallRuleIpv4` | `GET /firewall/rules/ipv4/{idOrName}` |

Environment: isolated venv (`uv venv`, Python 3.14.4), `openapi-python-client==0.30.0`, `pyyaml==6.0.3`,
`httpx==0.28.1`, `pydantic==2.14.3`. The generated client was exercised with `httpx2==2.16.0`, which its
own generated `pyproject.toml` requires. No network access to the appliance; both approaches were exercised
against in-process mock transports (`httpx.MockTransport` / `httpx2.MockTransport`).

> `/tmp` is a per-command ephemeral mount in the execution sandbox, so the POC actually ran in an untracked
> scratch directory **outside the git worktree** (`.agents/poc-adr` in the parent checkout) and was deleted
> afterwards. The commands in §13 are location-independent.

### 5.2 Option B — generated client, measured

Generation command (full document):

```bash
openapi-python-client generate --path firewall_config_openapi.yaml \
  --output-path gen/sophos_api_client --meta=none
```

| Measurement | Result |
|---|---|
| Exit status | 0 (with warnings) |
| Wall time | **28.5 s** (well inside the 10-minute bound) |
| Peak RSS | 368 MB |
| Generated source | **9,180 `.py` files, 28,781,171 bytes, 976,963 lines** |
| Model modules | **8,366** |
| API modules | 810, across **132** tag packages (one per YAML tag; `api/__init__.py` is not a package) |
| Generator warnings | **48** |
| Endpoints **not generated** | **23** ("Endpoint will not be generated") |
| Success responses **omitted** | **25** ("response will be omitted from generated client") |
| Duplicate-model-name collisions | **17** |
| Declared runtime dependencies | `httpx2>=2.13.1,<3`, `attrs>=22.2.0` — **no Pydantic** |

**The failures hit exactly the first-release core.** Of the **96** operationIds in the first-release scope
as it stood when the POC ran (the owner expanded it to 145 operations / 112 tools on 15 Nov 2026, §10):

| Failure class | Count | Operations |
|---|---|---|
| Endpoint not generated at all | **10** | `createFirewallRuleIpv4`, `createFirewallRuleIpv6`, `updateFirewallRuleIpv4`, `updateFirewallRuleIpv6`, `createNatRuleIpv4`, `createNatRuleIpv6`, `updateNatRuleIpv4ByIdOrName`, `updateNatRuleIpv6ByIdOrName`, `createIpAddress`, `createIpv6Address` |
| Success response omitted (function returns `None` on 200/201) | **13** | `getAllFirewallRulesIpv4/Ipv6`, `getFirewallRuleIpv4/Ipv6`, `getAllNatRulesIpv4/Ipv6`, `getNatRuleIpv4/Ipv6ByIdOrName`, `listIpsecConnectionsIpv4`, `listIpsecPolicyBasedConnectionsIpv4`, `listIpsecRouteBasedConnectionsIpv4`, `getPolicyBasedIpsecConnectionIpv4`, `getRouteBasedIpsecConnectionIpv4` |
| Clean | 73 | — |

**Component schemas:** only **8 of 32** got a model (`Ipv4AddressIp`, `Ipv4AddressIpList`,
`Ipv4AddressIpRange`, `Ipv4AddressNetwork`, and the four IPv6 equivalents). The **24 missing** ones include
`FirewallRuleIpv4Firewall`, `FirewallRuleIpv4Waf`, `FirewallRuleIpv4CreateFirewall`,
`FirewallRuleIpv4CreateWaf`, every `IpsecGatewaySettings*` and `IpsecRemoteAccessVpnSettings*` variant, the
`Ipv4AddressCreate*`/`Ipv6AddressCreate*` variants and `MacAddressMacAddress`/`MacAddressMacList`.

**Root cause (from the generator log):** the firewall/NAT rule bodies and responses are `oneOf` unions
whose branches are `$ref` to component schemas, with a `discriminator` on `ruleType`. The generator rejects
them with `Invalid property in union` and drops the whole endpoint or the success response. This is a
**schema-shape limitation, not a size or name-collision artifact**: regenerating from a filtered
247,264-byte spec containing only the five operations still failed the same three operations
(`createFirewallRuleIpv4`, `updateNatRuleIpv4ByIdOrName`, and the `getFirewallRuleIpv4` 200 response).

**Model quality (measured):**

- Models are `attrs` classes with manual `to_dict`/`from_dict`, not Pydantic. They cannot be reused as MCP
  input/output DTOs without a second conversion layer.
- Format handling is real: `id` is parsed as `uuid.UUID`, timestamps as `datetime`.
- **No constraint enforcement:** a 200-character `name` is accepted even though the contract says
  `maxLength: 50`; `pattern`, `minItems`, `minProperties` and `minimum` are not enforced either.
- **Unknown fields are silently accepted** into a per-model `additional_properties` dict (both at the item
  and root level), so neither schema drift nor unexpected server data is surfaced.
- **No client-side pagination validation:** `getUsers(page=0, page_size=0)` sends
  `?page=0&pageSize=0&pageTotal=false`, which the appliance rejects with `400 invalidPageSizeParam`
  (live evidence, 15 Nov 2026) even though the contract requires `page >= 1`.
- The transport is `httpx2`, a different library from the project's `httpx`; the Bearer header and base URL
  are correct.

### 5.3 Option A — handwritten transport + Pydantic, measured

A bounded implementation of the same five operations (`manual_client.py`, POC only, not merged):

| Measurement | Result |
|---|---|
| Size | **316 lines** total: transport + 6 typed exceptions + 18 Pydantic models + 5 operation methods |
| Operations exercised | **5 / 5** against `httpx.MockTransport` |
| Request correctness | exact method, path, query (`page=2&pageSize=10&pageTotal=true`), `Authorization: Bearer …`, `Accept: application/json`, JSON body |
| PATCH semantics | `model_dump(exclude_unset=True)` sends only the changed fields (`{"enabled": false, "translatedSource": {"masq": true}}`), preserving RFC 7396 merge behavior |
| Validation (measured) | rejects a 200-character `name` (`maxLength: 50`); rejects `page=0`, `pageSize=0` and `pageSize=101` before any I/O |
| Error mapping | 409 → `SophosConflictError`, 403 → `SophosAuthError`, 400/401/404/transport mapped and sanitized |
| Dependencies added | **none** (`httpx` and `pydantic` are already runtime dependencies) |

### 5.4 Option C — hybrid, measured

The hybrid only helps if the generated model layer covers the domains that need models. It does not:
the firewall/NAT rule models are exactly the ones the generator cannot emit, and the same failure occurs on
a five-operation filtered spec. A hybrid would therefore keep **two** model catalogs (generated attrs models
for the easy endpoints, handwritten Pydantic models for the core) plus a conversion layer and two transport
stacks (`httpx2` + `httpx`) — more drift surface, not less.

### 5.5 Comparison

| Criterion | A — handwritten | B — generated | C — hybrid |
|---|---|---|---|
| Operations usable (POC-time 96-op scope) | 96/96 (by construction) | **73/96** (10 missing, 13 without success response) | 73/96 generated + handwritten core |
| Generated/vendored code | none | 28.8 MB, 9,180 files, 976,963 LOC | 28.8 MB + handwritten core |
| Model framework | Pydantic v2 (same as MCP SDK) | attrs + manual converters | attrs + Pydantic + converter |
| Transport | `httpx` (existing) | `httpx2` (new) | `httpx2` + `httpx` |
| Constraint enforcement | yes (Field/Literal) | no | partial |
| MCP DTO reuse | direct | requires conversion | requires conversion |
| Reviewability | 316 LOC for 5 ops | 976,963 LOC | both |
| Drift detection | SHA-gated coverage matrix + contract tests | regenerate & diff | regenerate & diff + manual |
| Effort | bounded, per operation | 28.5 s to generate, then unusable for core | highest |

---

## 6. Decision

**Adopt Option A: a hand-written asynchronous HTTPX transport with hand-written Pydantic v2 models,
derived operation-by-operation from the checked-in YAML.**

Do **not** add `openapi-python-client`, `httpx2` or `attrs` to the project, do **not** vendor generated
code, and do **not** generate MCP tools mechanically from the OpenAPI document.

The decision is evidence-based:

1. The generator cannot produce the core mutation endpoints or the core read responses (23/96 operations of
   the POC-time scope unusable), and the failure is caused by the contract's `oneOf` + `discriminator` +
   `$ref` shape, which the project cannot change.
2. The generated package is 28.8 MB / 9,180 files / 976,963 LOC for 700 operations — far more than the
   first-release surface needs, and unreviewable for security-sensitive transport code.
3. It introduces a parallel stack (`httpx2`, `attrs`) that duplicates and conflicts with the project's
   `httpx` + `pydantic` + MCP SDK Pydantic DTOs.
4. The handwritten POC covers all five representative operations in 316 lines with stricter validation and
   no new dependency.

The YAML remains the source of truth for models; the T4 coverage generator (same issue #24) provides the
SHA-gated, deterministic operation inventory that makes manual modelling auditable.

---

## 7. Consequences

**Positive**

- Full control over the security-critical transport: TLS verification, CA bundle, no cross-origin
  redirects, explicit proxy behavior, timeouts, bounded read retries, and no blind retry of writes.
- Models are Pydantic v2, the same framework the MCP SDK uses, so MCP input/output DTOs can be the client
  models or a thin projection of them — no conversion layer.
- No new runtime dependency; the Docker image and lockfile stay small.
- Every model is readable and reviewable at the operation level, with `extra="forbid"` on requests.
- The coverage matrix (#24/T4) stays the single source of truth; a spec change is detected by SHA and
  requires a reviewed regeneration, not a silent codegen diff.

**Negative / accepted costs**

- Manual modelling effort: the bounded POC took 316 lines for 5 operations, of which ~120 are shared
  transport and typed errors. The **145-operation / 112-tool** first-release scope (§10) is therefore in the
  low thousands of lines (per-operation models dominate) — bounded, reviewable, and split across #25–#31.
  It is still an order of magnitude smaller than the 976,963-line generated package.
- Model drift is possible if the YAML changes without review. Mitigated by the SHA gate in the coverage
  generator, per-operation contract tests (RESPX) and the review protocol.
- More code to write for each new domain than "run the generator"; accepted because the generator cannot
  serve the core domains anyway.

**Neutral**

- The generated-client route can be revisited if `openapi-python-client` fixes `oneOf`/`$ref`/`discriminator`
  handling and emits Pydantic models over `httpx`. The trigger is explicit: re-run the §13 POC and compare
  against this ADR. Until then, the decision stands.

---

## 8. Rejected alternatives

| Alternative | Why rejected |
|---|---|
| **B — full generated client** | In the POC-time scope, 10/96 endpoints were not generated and 13/96 success responses omitted (all firewall/NAT create+update, address create; all firewall/NAT reads and IPsec reads); 24/32 component models missing; 28.8 MB / 9,180 files / 976,963 LOC; adds `httpx2` + `attrs`; no constraint enforcement; no pagination validation. |
| **C — hybrid** | The generated model layer is missing exactly where it is needed (firewall/NAT rules); a 5-operation filtered spec still fails the same operations. It would add a second model catalog, a conversion layer and a second transport for no coverage gain. |
| **Regenerate a subset and vendor it** | Same `oneOf` failure on the subset; vendoring generated code still adds `httpx2`/`attrs` and an unreviewable diff. |
| **Generic HTTP proxy tool** | Violates the non-negotiable "no raw REST" invariant (PLAN.md §1, master prompt §4.2) and the MCP security model. |
| **XML compatibility layer** | Explicitly forbidden; the migration is REST-only. |

---

## 9. Instruction to #25 (`client`) — normative

This section is the contract #25 must implement. #26 consumes it; #27–#31 consume it through their domain
adapters. Do not re-litigate the decision in #25.

### 9.1 Transport

- One `httpx.AsyncClient` per process, created by the MCP lifespan and closed in `finally`.
- `base_url = f"https://{host}:{port}/api/firewall-config/v1"` — fixed, never model-controlled. Host is a
  hostname/IP only (no scheme, userinfo, path, query, fragment); port defaults to 4444.
- `headers={"Authorization": f"Bearer {api_key}", "Accept": "application/json"}`; `Content-Type:
  application/json` on POST/PATCH only (never `application/merge-patch+json`).
- `verify` from settings (default `True`, optional `SOPHOS_CA_BUNDLE`), `timeout` from settings,
  `follow_redirects=False`, `trust_env=False` (no inherited proxy; a proxy is opt-in and documented).
- The API key is a `SecretStr`; it must never appear in logs, exceptions, `repr`, tool output or traces.
- No XML, no `xmltodict`, no username/password, no `SOPHOS_API_VERSION`, no raw-REST tool.

### 9.2 Public interface (exact)

```python
class SophosRestClient:
    def __init__(self, settings: Settings) -> None: ...

    async def get(self, path: str, *, params: Mapping[str, Any] | None = None) -> Any: ...
    async def post(self, path: str, *, json: Any) -> Any: ...
    async def patch(self, path: str, *, json: Any) -> Any: ...
    async def delete(self, path: str) -> None: ...

    async def get_page(
        self,
        path: str,
        *,
        page: int = 1,
        page_size: int = 50,
        page_total: bool = False,
        params: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]: ...

    async def aclose(self) -> None: ...
    async def __aenter__(self) -> "SophosRestClient": ...
    async def __aexit__(self, *exc: object) -> None: ...
```

`path` rules, enforced before any I/O and covered by tests: must be a `str`; must start with exactly one
`/`; must not start with `//`; must not contain `://`, `..`, `\`, `?` or `#` (query goes in `params`).
Absolute URLs, schemes, hosts and path overrides raise `ValueError`. Domain adapters define paths as module
constants; no MCP tool argument ever reaches `path`.

### 9.3 Models

- Hand-written Pydantic v2 models, one module per domain under `src/sophos_firewall_mcp/models/`.
- Requests: `model_config = ConfigDict(extra="forbid")` — the contract is closed, unknown fields are a bug.
- Responses: `extra="ignore"` — forward-compatible with server additions, but unknown fields are never
  echoed to the model or to MCP output.
- Shared primitives: `ObjectRef(name)`, `Pages(current, size, maxSize, total?, items?)`.
- Enums as `Literal[...]`; timestamps as `datetime`; UUIDs as `str` (validate only where the operation
  asserts the format); `sfos-object-name*` constraints implemented in the model (the YAML `pattern` is
  non-assertive — 994/1,085 schemas have none).
- PATCH bodies are partial models serialized with `model_dump(exclude_unset=True)`; omitted fields are not
  sent, explicit `None` is a removal.
- MCP output DTOs are explicit projections (object root, bounded); never return raw Sophos payloads.

### 9.4 Pagination

- Only for the **83** GET operations that declare `page`/`pageSize`/`pageTotal`. Never invent `limit`,
  `offset`, `cursor` or `total`.
- Validate `page >= 1` and `1 <= page_size <= 100` client-side (`pageSize > 100` is rejected by the
  appliance with `400 invalidPageSizeParam` even where the contract declares no maximum — live evidence
  15 Nov 2026).
- Return one page per call and preserve the `pages` metadata exactly. No auto-pagination inside a tool call;
  `get_page` exists so a tool can ask for a specific page and so a bounded internal walk is possible when a
  tool explicitly needs it.
- `getLiveUsers` declares no request pagination: do not add it in v1 (the appliance accepts it — documented
  observation only).

### 9.5 Error mapping and retries

| Condition | Exception |
|---|---|
| 401, 403 | `SophosAuthError` |
| 400 | `SophosValidationError` (sanitized `error` code only) |
| 404 | `SophosNotFoundError` |
| 409 | `SophosConflictError` |
| 5xx, unexpected status | `SophosAPIError` (status + sanitized code; never the raw body) |
| connect/DNS/TLS/timeout on a read | `SophosTransportError` |
| timeout/connection loss after a POST/PATCH/DELETE may have been applied | `SophosAmbiguousWriteError` — **never retried** |

All derive from `SophosAPIError`. Messages include method, path template and status; never headers, key or
raw response body. Reads: at most 2 attempts, only for connect/read timeout and 502/503/504, with jittered
exponential backoff; never for 400/401/403/404/409. No retry of writes; an ambiguous write requires a state
read/reconciliation before any repeat.

### 9.6 What NOT to generate or add

- Do **not** add `openapi-python-client`, `httpx2`, `attrs` or any generated client to the project.
- Do **not** vendor, commit or build generated code; do not add a codegen step to CI or the Docker image.
- Do **not** generate 700 MCP tools, a generic REST tool, or a tool that accepts a path/URL/headers.
- Do **not** use `application/merge-patch+json`; the contract declares `application/json` for all 134
  PATCH operations.
- Do **not** add XML, `xmltodict`, username/password or `SOPHOS_API_VERSION`.
- Do **not** auto-paginate, invent cursors, or return whole configurations.

---

## 10. First-release functional scope

**Scope revision — 15 Nov 2026.** The repository owner superseded the original v1 scope with a broader
first-release surface (issue #24 comment; issues #27/#29/#31/#35). The new surface is **145 operations /
112 MCP tools across 11 domains**. It adds MAC address CRUD, country-group read-only, VLAN-only interface
writes, the network-architecture read surface, the #35 audit tools, and firewall enable/disable + clone
tools. PLAN.md §4's initial per-domain table is superseded by the issues for the first release; this ADR
records the revised scope only and does not re-open the client decision (§6), which is unaffected.

**0.7.0 surface reduction.** The 0.7.0 breaking release collapsed the 40 IPv4/IPv6 tool pairs behind a
required `ip_family` argument, so the tool count fell from 152 to **112** (107 one-to-one tools + 5
composites) without changing the operation scope: the same 145 operationIds are covered, and the
per-domain tool counts below are the 0.7.0 ones. `docs/API-COVERAGE.md` §4 carries the same table.

The 145 operationIds below were verified against the parsed YAML (700 operations): **all present, all
unique, 0 missing, 0 duplicate**. `docs/API-COVERAGE.md` (#24/T4) carries the per-operation detail.

| Domain | Ops | Tools | operationIds |
|---|---|---|---|
| Firewall rules IPv4/IPv6 | 12 | 8 | `getAllFirewallRulesIpv4`, `getAllFirewallRulesIpv6`, `getFirewallRuleIpv4`, `getFirewallRuleIpv6`, `createFirewallRuleIpv4`, `createFirewallRuleIpv6`, `updateFirewallRuleIpv4`, `updateFirewallRuleIpv6`, `deleteFirewallRuleIpv4`, `deleteFirewallRuleIpv6`, `moveFirewallRuleIpv4`, `moveFirewallRuleIpv6` |
| NAT rules IPv4/IPv6 | 12 | 6 | `getAllNatRulesIpv4`, `getAllNatRulesIpv6`, `getNatRuleIpv4ByIdOrName`, `getNatRuleIpv6ByIdOrName`, `createNatRuleIpv4`, `createNatRuleIpv6`, `updateNatRuleIpv4ByIdOrName`, `updateNatRuleIpv6ByIdOrName`, `deleteNatRuleIpv4ByIdOrName`, `deleteNatRuleIpv6ByIdOrName`, `moveNatRuleIpv4`, `moveNatRuleIpv6` |
| Addresses and groups | 37 | 27 | `getAllIpAddresses`, `getIpAddressByIdOrName`, `createIpAddress`, `updateIpAddressByIdOrName`, `deleteIpAddressByIdOrName`, `getAllIpv6Addresses`, `getIpv6AddressByIdOrName`, `createIpv6Address`, `updateIpv6AddressByIdOrName`, `deleteIpv6AddressByIdOrName`, `getAllFqdns`, `getFqdnByIdOrName`, `createFqdn`, `updateFqdnByIdOrName`, `deleteFqdnByIdOrName`, `getAllIpv4AddressGroups`, `getIpv4AddressGroupByIdOrName`, `createIpv4AddressGroup`, `updateIpv4AddressGroupByIdOrName`, `deleteIpv4AddressGroupByIdOrName`, `getAllIpv6AddressGroups`, `getIpv6AddressGroupByIdOrName`, `createIpv6AddressGroup`, `updateIpv6AddressGroupByIdOrName`, `deleteIpv6AddressGroupByIdOrName`, `getAllFqdnGroups`, `getFqdnGroupByIdOrName`, `createFqdnGroup`, `updateFqdnGroupByIdOrName`, `deleteFqdnGroupByIdOrName`, `getAllMacAddresses`, `getMacAddressByIdOrName`, `createMacAddress`, `updateMacAddressByIdOrName`, `deleteMacAddressByIdOrName`, `getAllCountryGroups`, `getCountryGroupByIdOrName` |
| Services and service groups | 10 | 10 | `getAllServices`, `getServiceByIdOrName`, `createService`, `updateServiceByIdOrName`, `deleteServiceByIdOrName`, `getAllServiceGroups`, `getServiceGroupByIdOrName`, `createServiceGroup`, `updateServiceGroupByIdOrName`, `deleteServiceGroupByIdOrName` |
| Users | 6 | 6 | `getUsers`, `getNetworkUsers`, `getNetworkUser`, `createNetworkUser`, `updateNetworkUser`, `deleteNetworkUser` |
| Live users | 2 | 2 | `getLiveUsers`, `disconnectLiveUser` |
| IPsec VPN (read-only) | 11 | 11 | `getProfiles`, `getProfile`, `getFailovergroups`, `getFailovergroup`, `listIpsecConnectionsIpv4`, `listIpsecPolicyBasedConnectionsIpv4`, `getPolicyBasedIpsecConnectionIpv4`, `listIpsecRouteBasedConnectionsIpv4`, `getRouteBasedIpsecConnectionIpv4`, `getIpsecSiteToSiteLiveConnectionsIpv4`, `getIpsecRemoteAccessVpnSettings` |
| SSL VPN (read-only) | 9 | 9 | `getRemoteAccessPolicies`, `getRemoteAccessPolicy`, `listBookmarkGroups`, `getBookmarkGroup`, `getBookmarks`, `getBookmark`, `listClientlessPolicies`, `getClientlessPolicy`, `getSslvpnGlobalSettings` |
| Network architecture | 44 | 28 | **41 reads:** `listNetworkInterfaces`, `getNetworkInterface`, `getAllZones`, `getZone`, `getGatewaysIpv4`, `getWanGatewaysIpv4`, `getWanGatewayIpv4ByIdOrName`, `getCustomGatewaysIpv4`, `getCustomGatewayIpv4ByIdOrName`, `getGatewaysIpv6`, `getWanGatewaysIpv6`, `getWanGatewayIpv6ByIdOrName`, `getCustomGatewaysIpv6`, `getCustomGatewayIpv6ByIdOrName`, `getUnicastRoutesIPv4`, `getUnicastRouteIPv4`, `getUnicastRoutesIPv6`, `getUnicastRouteIPv6`, `listSdwanRoutesIpv4`, `getSdwanRouteIpv4`, `listSdwanRoutesIpv6`, `getSdwanRouteIpv6`, `listDhcpServersIpv4`, `getDhcpServerIpv4`, `listDhcpServersIpv6`, `getDhcpServerIpv6`, `getDhcpLeasesIpv4`, `getDhcpLeasesIpv6`, `getAllDhcpRelayIpv4`, `getDhcpRelayByIdIpv4`, `getAllDhcpRelayIpv6`, `getDhcpRelayByIdIpv6`, `getDnsSettings`, `getAllDnsHostEntries`, `getDnsHostEntryById`, `getAllDnsRequestRoutes`, `getDnsRequestRouteById`, `getAllStaticNeighborIpv4s`, `getStaticNeighborIpv4`, `getAllStaticNeighborIpv6s`, `getStaticNeighborIpv6`. **3 VLAN-only writes:** `createNetworkInterface`, `updateNetworkInterface`, `deleteNetworkInterface` |
| Network status | 2 | 2 | `getDnsProtectionStatus`, `getCellularWanStatus` |
| Audit (#35) | 0 | 3 | No new operations. Composite, read-only tools: `audit_firewall_rules`, `explain_connectivity`, `find_object_usage` |
| **Total** | **145** | **112** | — |

The two extra firewall tools are not separate operations: `firewall_rule_set_enabled` is a
`PATCH enabled` on the matching `updateFirewallRuleIpv4/Ipv6` operation (the required `ip_family`
selects the family), and `firewall_rule_clone` is a `get` + `create` composition. The three audit
tools are pure compositions of read operations already listed above.

**Explicitly out of first-release scope** (classified in `API-COVERAGE.md`, not registered as tools):

- all `bulkDelete*` operations (including MAC bulk delete), and WAF rules (`ruleType: waf`);
- administrator CRUD, user groups, `networkUserLiveLogin`/`networkUserLiveLogout`;
- all IPsec and SSL VPN mutations (the VPN surface is read-only in v1);
- `importTrustedMacs` (the only `multipart/form-data` operation);
- logs (the contract has no log-query endpoint), IPS, and any "firewall health" tool (no such REST
  endpoint);
- mutation operations outside the VLAN-only interface writes: zones, gateways, static unicast routes,
  SD-WAN routes (including move), DHCP servers/relays, DNS settings/host entries/request routes, static
  neighbors, router advertisements, multicast routes, mDNS and neighbor settings, and country-group
  mutations.

**Accepted regression.** System information (firmware version, serial number, uptime) and service status
have no REST endpoint in this contract; they are not migrated and no placeholder tool is advertised.


---

## 11. API and MCP version assumptions

| Item | Assumption | Evidence |
|---|---|---|
| Contract | `openapi: 3.0.0`, `info.version: 1.0.0`, SHA-256 `58c4bc79…b1d5` | §2.1 |
| Base URL | `https://<host>:<port>/api/firewall-config/v1` | YAML `servers`, `info.description` |
| Auth | Bearer API key, inherits the administrator profile's permissions | YAML `securitySchemes`; REFERENCES R01/R04 |
| PATCH | JSON Merge Patch (RFC 7396) by default; `application/json`; four documented array exceptions (`patchMessages`, `updateCentralFirewallReportingLogComponents`, `updateSyslogServerLogs`, `updateAlertNotificationSettings`) — none in first-release scope | YAML `info.description`; PLAN §5 |
| Pagination | `page`/`pageSize`/`pageTotal` only; 83 GETs; `pageSize` max 100 on three operations; live evidence: appliance rejects > 100 everywhere and accepts `page=0` (client must validate) | YAML; live evidence 15 Nov 2026 |
| MCP SDK | `mcp>=2.3.0,<3` (v2.3.0 = latest stable, 2 Oct 2026); `[cli]` extra dev-only | REFERENCES R14/R15 |
| MCP protocol | `2026-07-28` (SDK also serves 2024-11-05…2025-11-25 via handshake); `subscriptions=False`; no manual handshake | REFERENCES R15a/R35/R39 |
| MCP transport | STDIO only; stdout is protocol, logs to stderr; no TTY | PLAN §7 |
| Python / runtime | Python `>=3.11`; CI matrix is 3.11–3.13 today (`.github/workflows/test.yml`), 3.14 is added by #32; `httpx` (current 0.28.1; version pinned by the Lead-owned lockfile); `pydantic>=2`; no new dependencies | `pyproject.toml`; `.github/workflows/test.yml`; POC venv |
| Firmware | **unknown** — prerequisite for live verification, not for this ADR | §3 |

---

## 12. Risks and mitigations

| Risk | Severity | Mitigation |
|---|---|---|
| Target firmware/build unknown; behavior may differ from the contract | High | No compatibility claim; live verification per domain (#24 protocol, `docs/live-evidence/`); defer with reason in `API-COVERAGE.md`. |
| Hand-written models drift from the YAML | Medium | SHA-gated coverage generator (#24/T4); per-operation contract tests (RESPX); review protocol checks operationId/schema/status. |
| Manual modelling errors (wrong field, requiredness, enum) | Medium | Models are written from the parsed operation schema; contract tests assert method/path/query/body/status; #24 coverage matrix is the checklist. |
| PATCH merge semantics over arrays unverified on firmware | Medium | Send partial bodies only; document the four exceptions; never assume array merge; live test deferred until a write key and disposable objects exist. |
| Ambiguous write after timeout | High | `SophosAmbiguousWriteError`, no retry, reconcile by read before repeating. |
| API key leakage | High | `SecretStr`; redaction in errors/logs; no raw bodies in exceptions; tests assert redaction. |
| Scope creep toward raw REST / generated tools | Medium | §9.6 is normative; review protocol checklist enforces it. |
| Revisiting codegen later | Low | Explicit trigger in §7; re-run the §13 POC and supersede this ADR if the generator improves. |

---

## 13. Reproduce this

All commands run outside the git worktree. `UV_CACHE_DIR` is required because `~/.cache/uv` is read-only.

```bash
# 0. isolated environment (no project dependency is touched)
mkdir -p /tmp/adr-poc && cd /tmp/adr-poc
UV_CACHE_DIR=/tmp/dsh-uv-cache uv venv /tmp/adr-poc/venv
UV_CACHE_DIR=/tmp/dsh-uv-cache uv pip install --python /tmp/adr-poc/venv/bin/python \
  openapi-python-client==0.30.0 pyyaml httpx httpx2

# 1. contract identity
sha256sum firewall_config_openapi.yaml
stat -c '%s bytes' firewall_config_openapi.yaml
git ls-tree HEAD firewall_config_openapi.yaml
```

Expected: `58c4bc79ac930ce030202e09835865dcb12fcd44e9132e1f4234a1ed1743b1d5`, `8934475 bytes`,
blob `40fca0b25d4d85866f86b90aec77e5559ae27214`.

```bash
# 2. parse the full document and resolve every local $ref (key facts)
/tmp/adr-poc/venv/bin/python - <<'PY'
import hashlib, yaml
from collections import Counter

raw = open("firewall_config_openapi.yaml", "rb").read()
doc = yaml.safe_load(raw)

def walk(obj, path="$"):
    yield path, obj
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from walk(v, f"{path}/{k}")
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from walk(v, f"{path}/{i}")

def resolve(ref):
    if not ref.startswith("#/"):
        return None
    node = doc
    for part in ref[2:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        if isinstance(node, list):
            node = node[int(part)]
        elif isinstance(node, dict) and part in node:
            node = node[part]
        else:
            return None
    return node

print("sha256", hashlib.sha256(raw).hexdigest(), "bytes", len(raw))
print("openapi", doc["openapi"], "info.version", doc["info"]["version"])
ops = [(p, m, o) for p, item in doc["paths"].items() for m, o in item.items()
       if isinstance(o, dict) and "operationId" in o]
print("paths", len(doc["paths"]), "operations", len(ops),
      "methods", dict(Counter(m.upper() for _, m, _ in ops)))
ids = Counter(o["operationId"] for _, _, o in ops)
print("operationIds", len(ids), "duplicates", [k for k, v in ids.items() if v > 1])
refs = [n["$ref"] for _, n in walk(doc) if isinstance(n, dict) and "$ref" in n]
uniq = sorted(set(refs))
print("refs", len(refs), "unique", len(uniq),
      "external", [r for r in uniq if not r.startswith("#/")],
      "unresolved", [r for r in uniq if resolve(r) is None])
schemas = doc["components"]["schemas"]
print("component_schemas", len(schemas),
      "unreferenced", sorted(set(schemas) - {r.split("/")[-1] for r in uniq}))
patches = [(p, o) for p, m, o in ops if m == "patch"]
print("patch", len(patches), "content_types",
      dict(Counter(ct for _, o in patches for ct in (o.get("requestBody") or {}).get("content") or {})))
paginated = [o for _, m, o in ops if m == "get" and any(
    prm.get("name") in ("page", "pageSize", "pageTotal") for prm in o.get("parameters") or [])]
print("paginated_gets", len(paginated))
print("status", dict(Counter(c for _, _, o in ops for c in (o.get("responses") or {}))))
PY
```

The full analyzer used for §2 is a ~300-line script; its essential checks are: walk every node, collect
`$ref` occurrences, resolve each `#/...` pointer, count component schemas and unreferenced/cyclic ones,
count `schema` keyword sites (request bodies / responses / parameters), count PATCH request content types,
count GETs with `page`/`pageSize`/`pageTotal`, and tally response status codes per operation. Key outputs
recorded in §2:

```text
paths 384 · operations 700 · {"DELETE": 93, "GET": 263, "PATCH": 134, "POST": 210}
operationIds_present 700 · operationIds_unique 700 · operationIds_duplicated {}
ref_occurrences 76 · ref_unique 32 · ref_external [] · ref_unresolved []
component_schemas 32 · component_schemas_unreferenced [] · schema_cycles 0
schema_keyword_occurrences 4981 · schema_objects_inline 38509 · schema_nodes_total 52852
patch_operations 134 · patch_request_content_types {"application/json": 134}
paginated_get_operations 83 · limit_offset_cursor_operations 0
status_distribution {"401": 700, "403": 700, "500": 700, "400": 636, "200": 608,
                     "404": 272, "409": 217, "201": 92, "503": 1}
path_param_formats {"idOrName|sfos-object-name-or-id": 248,
                    "idOrName|sfos-object-name-lenient-or-id": 12,
                    "idOrName|None": 10, "idOrName|uuid": 6, "name|None": 6,
                    "floodAttackType|None": 1}
```

```bash
# 3. generate the client from the full document and measure it
#    YAML=/path/to/sophos-firewall-mcp/firewall_config_openapi.yaml
cd /tmp/adr-poc && mkdir -p gen
/usr/bin/time -v /tmp/adr-poc/venv/bin/openapi-python-client generate \
  --path "$YAML" --output-path gen/sophos_api_client --meta=none 2>&1 | tee gen.log
find gen/sophos_api_client -name '*.py' | wc -l            # 9180
find gen/sophos_api_client -name '*.py' -exec cat {} + | wc -l   # 976963
find gen/sophos_api_client -name '*.py' -printf '%s\n' | awk '{s+=$1} END {print s}'  # 28781171
grep -c '^WARNING' gen.log                                  # 48
grep -c 'Endpoint will not be generated' gen.log            # 23
grep -c 'response will be omitted' gen.log                  # 25
```

Expected wall time ≈ 28.5 s, peak RSS ≈ 368 MB, exit status 0. The generated `pyproject.toml` (with
`--meta=poetry`) declares `httpx2 >=2.13.1,<3` and `attrs >=22.2.0`.

```bash
# 4. exercise the same five operations with both approaches (in-process mocks, no appliance)
cd /tmp/adr-poc
/tmp/adr-poc/venv/bin/python exercise_manual.py            # 5/5 operations
PYTHONPATH=gen /tmp/adr-poc/venv/bin/python exercise_generated.py
```

The exercise harness is small and self-contained; this is its shape (the manual client is §9, the generated
client is imported from `gen/`):

```python
import asyncio, httpx
from manual_client import (AnyNetworks, AnyZones, FirewallRuleCreate, NatRulePatch,
                           SophosRestClient)

seen = []
def handler(request):
    seen.append(request)
    path = request.url.path
    if path.endswith("/network/dns/protection/status"):
        return httpx.Response(200, json={"status": "active", "updatedAt": "2026-11-15T10:00:00Z"})
    if path.endswith("/authentication/users"):
        return httpx.Response(200, json={"items": [], "pages": {"current": 2, "size": 10,
                                                               "maxSize": 100}})
    if path.endswith("/firewall/rules/ipv4") and request.method == "POST":
        return httpx.Response(201, json={"name": "allow-lan-to-wan", "ruleType": "firewall",
                                        "enabled": False})
    if path.endswith("/firewall/rules/ipv4/allow-lan-to-wan"):
        return httpx.Response(200, json={"name": "allow-lan-to-wan", "ruleType": "firewall",
                                        "enabled": False, "sourceZones": {"zones": [{"name": "lan"}]}})
    if path.endswith("/nat/rules/ipv4/snat-web"):
        return httpx.Response(200, json={"name": "snat-web", "enabled": False})
    return httpx.Response(409, json={"error": "conflict"})

async def main():
    c = SophosRestClient("10.10.10.1", 443, "sfos_poc_token",
                         transport=httpx.MockTransport(handler))
    print(await c.get_dns_protection_status())
    print(await c.list_users(page=2, page_size=10, page_total=True))
    print(await c.create_firewall_rule_ipv4(FirewallRuleCreate(
        name="allow-lan-to-wan", enabled=False, sourceZones=AnyZones(any=True),
        destinationZones=AnyZones(any=True), sourceNetworks=AnyNetworks(any=True),
        destinationNetworks=AnyNetworks(any=True), services={"any": True})))
    print(await c.patch_nat_rule_ipv4("snat-web", NatRulePatch(enabled=False,
                                                               translatedSource={"masq": True})))
    print(await c.get_firewall_rule_ipv4("allow-lan-to-wan"))
    await c.aclose()
    print([f"{r.method} {r.url.raw_path.decode()}" for r in seen])

asyncio.run(main())
```

Key outputs:

```text
manual:     1 simple GET -> DnsProtectionStatus active
            2 paginated list -> UsersPage 1 pages: {'current': 2, 'size': 10, 'maxSize': 100, ...}
            3 create rule -> FirewallRule allow-lan-to-wan enabled= False
            4 NAT PATCH -> {'name': 'snat-web', 'enabled': False}
            5 nested refs -> FirewallRule allow-lan-to-wan sourceZones: {'zones': [{'name': 'lan'}]}
            PATCH body: {"enabled": false, "translatedSource": {"masq": true}}

generated:  1 simple GET -> 200 GetDnsProtectionStatusResponse200 active
            2 paginated list -> 200 GetUsersResponse200 items: 1
            2b page=0,pageSize=0 accepted -> ?page=0&pageSize=0&pageTotal=false
            3 create rule -> NOT GENERATED: No module named '...create_firewall_rule_ipv_4'
            4 NAT PATCH -> NOT GENERATED: No module named '...update_nat_rule_ipv_4_by_id_or_name'
            5 nested refs -> 200 parsed: None
```

```bash
# 5. prove the failure is schema-shape-driven, not size-driven: regenerate from the five ops only
#    (build a 247,264-byte spec with the same info/servers/components and only those five paths)
/tmp/adr-poc/venv/bin/openapi-python-client generate \
  --path five_ops.yaml --output-path gen_five/sophos_api_client --meta=none
# -> same warnings: createFirewallRuleIpv4 and updateNatRuleIpv4ByIdOrName not generated,
#    getFirewallRuleIpv4 success response omitted.
```

The POC scripts (`analyze.py`, `manual_client.py`, `exercise_manual.py`, `exercise_generated.py`) are
**not committed** — the constraint for this task is that the ADR is the only repository file written. They
are reproduced by the snippets above; the manual client's shape is normative in §9.

---

## 14. References

- Contract: `firewall_config_openapi.yaml` (SHA-256 `58c4bc79…b1d5`, blob `40fca0b2…7214`).
- [PLAN.md](./sophos-rest-api-redesign/PLAN.md) §5 (contract), §6 (client), §12 (risks).
- [REFERENCES.md](./sophos-rest-api-redesign/REFERENCES.md) R13/R13a/R13b/R13c (openapi-python-client and advisories), R01/R02/R04 (Sophos API), R14/R15/R15a/R35/R39 (MCP SDK and protocol).
- [INDEPENDENT_REVIEW_REPORT.md](./sophos-rest-api-redesign/INDEPENDENT_REVIEW_REPORT.md) §2 (baseline), §6 (architecture), §7 (first-release scope).
- [LAB-ACCESS.md](./sophos-rest-api-redesign/LAB-ACCESS.md) and [`docs/live-evidence/api-smoke-2026-11-15.md`](../live-evidence/api-smoke-2026-11-15.md) (read-only live evidence).
- Issue [#24](https://github.com/lordraiden/sophos-firewall-mcp/issues/24) §6 (POC definition) and [#25](https://github.com/lordraiden/sophos-firewall-mcp/issues/25) (client contract).
