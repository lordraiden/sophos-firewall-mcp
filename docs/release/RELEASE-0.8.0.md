# Release 0.8.0 — confirmations that fail closed, a selectable surface, and a rate limit

**Status:** prepared, **not published** — pending explicit owner approval. **Previous release:** 0.7.1
(the 0.7.0 standards-review findings). **Target appliance:** Sophos Firewall 23, **SFOS 23.0.0
GA-Build371**.

## 1. Release notes

### 1.1 Summary

0.8.0 is a minor release. It closes the 0.8.0 items of the independent MCP standards review of 0.7.0
([`MCP-STANDARDS-REVIEW-0.7.md`](../architecture/sophos-rest-api-redesign/MCP-STANDARDS-REVIEW-0.7.md))
and the follow-up issues filed against it: the destructive deletes now require a client confirmation
and **fail closed**, the published tool surface is selectable by domain, the server enforces its own
invocation rate, and the `tools/list` catalog is a fifth smaller.

- **No tool is renamed and no argument is removed.** The surface stays at **112 tools** (107
  one-to-one + 5 composites): **74 read-only / 38 mutations**, 26 destructive / 12 additive.
- **The wire body is unchanged for every call that already worked.** No request or response payload
  changes. The only input-contract change is the confirmation precondition on four deletes, which is a
  precondition rather than a new argument.
- **Five behaviour changes** (§1.2): the confirmation gate, the exact SDK pin, the JSON-RPC error
  codes, the Compose defaults and the invocation rate limiter. One of them — the confirmation gate — is
  **breaking for a non-interactive client**.
- **The catalog drops 21.3%**, from 627,848 to **493,965 bytes**, with the tool count and every tool
  name unchanged (§1.3).
- **The suite is 1499 passed, 100 skipped** on `main`, with flake8, mypy, black and `uv lock --check`
  clean (§1.5).

The release is a minor bump because the confirmation gate can refuse a call that 0.7.1 allowed. A
client that declares form-mode elicitation keeps working unchanged; a client that cannot answer a
confirmation must stop calling the four gated deletes, or it will be refused.

### 1.2 Behaviour changes

#### B1 — the four gated deletes require a confirmation and fail closed (breaking for non-interactive clients)

`firewall_rule_delete`, `nat_rule_delete`, `network_user_delete` and
`network_interface_delete_vlan` now require the client to answer a confirmation through the SDK's
`Resolve`/`Elicit` mechanism before the appliance is touched.

0.7.1 documented the gate as **best-effort**: it fired on the legacy handshake path, where the
transport can carry a server-initiated request, and was skipped — with a logged `WARNING` — on the
`2026-07-28` per-request path, where `mcp` 2.3.0 refuses a standalone server-to-client request. The
`InputRequiredResult` round trip that makes the question askable on both eras was the deferred 0.8.0
item, and it is now implemented.

The gate is a **precondition, not an affordance**:

- a client that declares form-mode `elicitation` is asked, and a declined or cancelled answer aborts
  the call with a `ToolError` and nothing is deleted;
- a client that **cannot** answer — no `elicitation` capability, a `url`-only client, or a transport
  with no back-channel — is **refused**, and nothing is deleted;
- the other 34 mutations are unaffected.

This is the release's one breaking change. A non-interactive automation client that used to delete
unconfirmed is now refused on these four tools; it must run behind a client that supports form-mode
elicitation. The fail-closed direction is deliberate: a prompt injection or a runaway agent can no
longer delete a firewall rule, a NAT rule, a network user or a VLAN interface by accident.

#### B2 — `mcp` is pinned to exactly `2.3.0` (install-time)

The declared dependency was `mcp>=2.3.0,<3`; it is now `mcp==2.3.0`.

The server depends on four attributes the SDK does not expose publicly — `MCPServer._tool_manager`,
`Tool.fn_metadata.arg_model`, `Tool.parameters` and `MCPServer._lowlevel_server` — because it
publishes flat tool arguments and a closed argument model, and it sets `serverInfo.instructions` after
registration. A different SDK release may rename, move or remove any of them, and the failure would
not be a clean import error: registration would still succeed, but every tool would silently fall back
to the SDK's default `request`-wrapped, open argument model. The declared range is therefore the one
release that was actually tested.

A deployment that pinned a different 2.x release now fails to resolve instead of running untested. The
widening procedure is in [`docs/SDK-COMPATIBILITY.md`](../SDK-COMPATIBILITY.md).

#### B3 — unknown tools and invalid prompt requests return JSON-RPC `-32602` (protocol)

An unknown tool name, an unknown prompt name, missing or invalid prompt arguments, and a
caller-fixable render failure are now reported as **invalid params** (`-32602`) instead of internal
error (`-32603`) or an `isError` result. This matches the specification's error classes and the
existing `resources/read` path.

A genuine renderer failure still returns `-32603`. On the legacy `initialize` handshake path, a
renderer exception previously surfaced as JSON-RPC `code=0` — not a valid error code, and not
classifiable by a client — and is now `-32603` as well (§1.4).

Measured over STDIO: an unknown tool returns `-32602` and an unknown prompt returns `-32602`.

#### B4 — Compose defaults to read-only (deployment)

`docker-compose.yml` now defaults `SOPHOS_READ_ONLY_MODE` to `true`, so the reference deployment
publishes 74 tools and cannot write until an operator sets it to `false` explicitly. It passes
`SOPHOS_MAX_CONCURRENCY` through, and it deliberately declares **no `restart` policy**: the MCP client
owns the process lifecycle, so a restart would only re-spawn a server whose `stdin` is gone.

The supported invocation is one container per session:

```bash
docker compose run --rm -T sophos-firewall-mcp
```

`-T` disables the pseudo-TTY that `docker compose run` allocates by default; a TTY injects carriage
returns into the JSON-RPC stream and breaks the protocol.

#### B5 — the server enforces an invocation rate limit (runtime)

The `2026-07-28` Tools specification, in *Security Considerations*, requires servers to rate limit
tool invocations. 0.7.1 recorded that as a risk acceptance; this release implements it.

A token bucket sits in the **outermost** middleware position and bounds `tools/call` requests:

| Setting | Default | Range | Meaning |
|---|---|---|---|
| `SOPHOS_INVOCATION_RATE_PER_MINUTE` | `60` | 1–6000 | sustained invocation rate |
| `SOPHOS_INVOCATION_BURST` | `10` | 1–1000 | bucket depth |

- A throttled call **fails fast** with an actionable `isError` result naming the limit and the retry
  delay, instead of queueing, so a runaway client cannot build an unbounded backlog.
- A **composite counts as one** invocation, and an **MRTR resume counts as one** too.
- The limiter runs **before** the MRTR replay guard, so a throttled resume does not consume the
  single-use confirmation and the client can retry once the bucket refills.

The policy, the threat model and the concurrency-versus-rate distinction are in
[`docs/SECURITY-RATE-POLICY.md`](../SECURITY-RATE-POLICY.md). `SOPHOS_MAX_CONCURRENCY` bounds
*in-flight* HTTP requests and is not a rate limit; the two controls answer different questions and are
documented as such.

### 1.3 What is new

#### `SOPHOS_TOOL_DOMAINS` — a selectable tool surface

A comma-separated allowlist of `firewall`, `nat`, `objects`, `users`, `network` and `audit`.

- **Unset keeps the complete 112-tool surface**, so an existing deployment is unaffected.
- A set value publishes only the tools of the named domains.
- The value is a **closed allowlist**: an unknown identifier, an empty entry or a duplicate is
  rejected at startup with a message naming the accepted identifiers, never silently ignored.
- Order does not matter — `audit,firewall` and `firewall,audit` publish the same catalog.
- The three audit composites are self-contained, so `SOPHOS_TOOL_DOMAINS=audit` works on its own.

The resources, the prompts and `serverInfo.instructions` now describe the surface that is **actually
registered** instead of the full catalog: a prompt is registered only when every tool its workflow
names is present, and `sophos://api/surface` reports the filtered set.

Measured live in read-only mode: **74** tools with the variable unset, **47** with `network`, and
**4** with `firewall,nat`.

#### A 21.3% smaller catalog

`tools/list` is **493,965 bytes** (was 627,848), roughly 123k tokens at ~4 bytes per token:

| Component | Bytes | Share |
|---|---:|---:|
| Input schemas | 191,630 | 38.8% |
| Output schemas | 242,915 | 49.2% |
| Descriptions | 38,399 | 7.8% |
| Envelope | 21,021 | 4.3% |

The trim removes two JSON Schema annotations from the published `outputSchema` — the repeated model
docstrings and field descriptions (the same `ObjectRef` definition appeared 64 times and `Pages` 33
times) and the response-only `default` — which takes the output schemas from 376,788 to 242,915 bytes
(**−35.5%**).

It is **annotation-only**: `required`, `properties`, `type`, `enum`, `const`, `format`, `$ref`,
`anyOf`/`oneOf`, `additionalProperties`, nullability and aliases are untouched, and the SDK still
validates `structuredContent` against the output model. `Pages` and `FirewallRuleOutput` keep their
field descriptions because they document the `total`/`items` trap and the 1-based position. The tool
count and every tool name are unchanged.

The measurement is reproducible with `scripts/measure_catalog.py`; the method and the before/after
table are in [`docs/CATALOG-SIZE.md`](../CATALOG-SIZE.md).

#### A single-use guard for the sealed MRTR `requestState`

The SDK verifies a resumed state's integrity, envelope, `iat`/`exp`, method/target/args digest,
audience and principal, but it does **not** track consumption: `resolve._restore_outcome` restores the
recorded confirmation on every round, so the same sealed state could be replayed. A client that
retries on timeout would execute the confirmed delete twice, and a captured state could delete a
re-created object of the same name without a fresh confirmation.

`src/sophos_firewall_mcp/mrtr.py` adds the missing check. The first `tools/call` carrying a given
token is recorded and allowed; a second use is refused with `-32602` before the boundary unseals it
and before any handler runs. Only **accepted** states are remembered, so a forged token never consumes
a slot, and the cap **fails closed** rather than evicting a live entry.

#### An executable SDK compatibility contract

`tests/test_sdk_compat.py` fails with a diagnostic naming the attribute that moved when any of the four
private SDK surfaces changes, when the declared dependency is not the exact verified pin, or when the
installed SDK is not the verified release. It also proves the behaviour the seam exists for still
works end to end: flat arguments, a closed argument model, a root union of closed variants, and a real
invocation reaching the handler on all three argument-model branches.

The `test` job gains a `python-version` × `mcp-version` matrix that installs the pinned release
explicitly and verifies the installed version before running the suite, plus a `clean-install` job
that builds the wheel, installs it into a throwaway environment and checks that a clean install
resolves the pinned SDK and still registers a non-empty tool surface.

#### A centralized annotation policy

`destructiveHint` and `idempotentHint` were correct per tool but not governed by a stated policy, so
the same operation class could drift apart again. Every mutation now declares both hints explicitly
through `ADDITIVE_ANNOTATIONS` or `DESTRUCTIVE_ANNOTATIONS`, `_build_annotations` rejects a mutation
that omits either, and a **38-row regression table** pins each tool's pair, failing with a diagnostic
that names the stale row.

The split is **26 destructive / 12 additive**. The read-only tools are unchanged.

#### Model-facing schema improvements

- **Sixteen getter descriptions** now describe the payload the tool returns. The `*_get` tools
  published a description of the *request* and said nothing about the response, so a model had to call
  one to learn its shape.
- **The union tools state which selector field chooses the variant.**
- **`mac_address_create` publishes one message** for its mutually-exclusive `macAddress` /
  `macAddresses` pair instead of two competing ones.
- **Several published input names that had drifted to camelCase are corrected to snake_case.**

#### Documentation and tooling

- [`docs/CATALOG-SIZE.md`](../CATALOG-SIZE.md) — how the catalog is measured, what the trim removes,
  and why `tools/list` is not paginated.
- [`docs/SDK-COMPATIBILITY.md`](../SDK-COMPATIBILITY.md) — the supported SDK range, why it is an exact
  pin, and how to widen it.
- [`docs/SECURITY-RATE-POLICY.md`](../SECURITY-RATE-POLICY.md) — the invocation-rate policy, the
  threat model and the concurrency-versus-rate distinction.
- `scripts/measure_catalog.py` — the reproducible catalog measurement.
- `scripts/docker_stdio_smoke.py` — a real STDIO session that synchronises on protocol responses.

### 1.4 What is fixed

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
- **The published metadata matches the installed package.** The package description no longer embeds a
  tool count — it said "152 typed tools" against a 112-tool surface — and `serverInfo.description` is
  read from the installed distribution instead of being assembled from a stale editable install. A
  drift test compares the published description with `project.description`.
- **The GitHub repository description no longer claims 152 tools.** It matches the package metadata:
  the domains, not a count that goes stale on every surface change.

### 1.5 Verification evidence

Every number below was measured; none is estimated.

**Test suite and static analysis (on `main`, `07b647c`):**

| Gate | Result |
|---|---|
| `pytest -q` | **1499 passed, 100 skipped** |
| `flake8 src/sophos_firewall_mcp tests scripts` | clean |
| `mypy src/sophos_firewall_mcp` | clean (30 files) |
| `black --check src tests scripts` | clean (63 files) |
| `uv lock --check` | clean |

**Catalog (`scripts/measure_catalog.py`, 112 tools):**

- **493,965 bytes** total — input 191,630 / output 242,915 / descriptions 38,399 / envelope 21,021.
- **No `nextCursor`**: the response is a single page.

**Surface:**

- **112 tools** = **74 read-only + 38 mutations**.
- **26 destructive / 12 additive** mutations.

**Live read-only smoke against SFOS 23.0.0 GA-Build371:**

- **74 tools** published in read-only mode.
- `zone_list` returned **5 zones**.
- `firewall_rule_list` returned **2 rules** with `pages` metadata.

**Domain selection, live:**

- **74** tools with `SOPHOS_TOOL_DOMAINS` unset (read-only mode).
- **47** tools with `network`.
- **4** tools with `firewall,nat` plus `SOPHOS_READ_ONLY_MODE=true`.

**JSON-RPC over STDIO:**

- unknown tool → **`-32602`**.
- unknown prompt → **`-32602`**.

**Release-branch gates (this PR):** recorded in §3.

### 1.6 Upgrade notes

1. **Check whether you call the four gated deletes.** `firewall_rule_delete`, `nat_rule_delete`,
   `network_user_delete` and `network_interface_delete_vlan` now require a client that can answer a
   form-mode confirmation. A non-interactive client is refused. If your automation deletes through
   this server, run it behind a client that declares `elicitation` form mode, or keep 0.7.1 for those
   four tools.
2. **Re-resolve the SDK pin.** `mcp` is now `==2.3.0`. If your environment pinned a different 2.x
   release, the install fails instead of running untested. Run `uv sync --locked` (or reinstall) and
   check `docs/SDK-COMPATIBILITY.md` before widening the range.
3. **Expect `-32602` where you used to see `-32603` or `isError`.** An unknown tool or an invalid
   prompt request is now *invalid params*. A client that branched on the old code needs the new one.
4. **Re-check your Compose deployment.** `docker-compose.yml` now defaults `SOPHOS_READ_ONLY_MODE` to
   `true` and declares no `restart` policy. Set `SOPHOS_READ_ONLY_MODE=false` explicitly if you need
   writes, and invoke it as `docker compose run --rm -T sophos-firewall-mcp`.
5. **Size the rate limiter for your workload.** The default is 60 invocations per minute with a burst
   of 10. A batch job that issues more will see fail-fast `isError` results; raise
   `SOPHOS_INVOCATION_RATE_PER_MINUTE` and `SOPHOS_INVOCATION_BURST` deliberately, up to 6000/1000.
6. **Optionally narrow the surface.** `SOPHOS_TOOL_DOMAINS` publishes only the domains you need. Unset
   keeps the full 112-tool surface, so this is opt-in.
7. **No client change is required for anything else.** No tool is renamed, no argument is removed and
   the wire body is unchanged for every call that already worked.

### 1.7 Known limitations

- **The confirmation gate requires a client that can answer it.** A client that declares no
  `elicitation` capability, a `url`-only client, or a transport with no back-channel is refused on the
  four gated deletes. That is the intended fail-closed behaviour, but it means a non-interactive
  automation client cannot use those four tools at all.
- **`tools/list` is one page.** The protocol supports `nextCursor`, but the pinned SDK's `MCPServer`
  accepts `PaginatedRequestParams` and discards it, and exposes no public hook to supply a page. The
  server does not fake partial results; the limitation and the smallest upstream-compatible path are
  documented in [`docs/CATALOG-SIZE.md`](../CATALOG-SIZE.md), and a test pins the single-page
  behaviour so it fails when the SDK grows a supported hook. The mitigations are the cache hint,
  read-only mode, domain selection, the resources and the prompts.
- **Firmware compatibility is limited to the tested build.** The live evidence applies to **SFOS 23.0.0
  GA-Build371** only. The Configuration REST API exposes no version endpoint, so the server cannot
  detect the firmware it is talking to and makes no claim for any other SFOS build, including later
  23.0 maintenance builds and SFOS 24. Verify the behaviour you depend on against your own appliance.
- **Live write validation is limited** to the object kinds exercised on the lab appliance; ambiguous
  write reconciliation, a real `403` denial, bulk delete and interface/VPN mutations remain unverified.
- **Accepted regressions** are unchanged: no system information, no service status and no log query,
  because the Configuration REST API exposes no endpoint for them.
- **Audit tools are configuration analysis, not packet tests**; `explain_connectivity` reports
  `method: config-analysis` and `not-verifiable` when the configuration lacks the evidence.
- **Pagination is one page per call**; the server never fetches every page automatically.

## 2. Rollback to 0.7.1

The server is stateless: rolling back changes no appliance configuration and no stored data.

1. Re-deploy the previous image `ghcr.io/lordraiden/sophos-firewall-mcp:0.7.1`. Use the exact `0.7.1`
   tag, not the `0.7` alias: the alias moves to 0.8.0 when this release is published.
2. If you run from source, check out `v0.7.1` and reinstall.
3. **A client change may be required.** 0.7.1 does not require the confirmation on the four gated
   deletes, so a non-interactive client that 0.8.0 refuses works again after the rollback. A client
   that already answers the confirmation keeps working on both releases.
4. The tool names, the wire body and the output payload are identical in both releases. The
   differences are the confirmation precondition, the SDK pin, the JSON-RPC error codes, the Compose
   defaults, the invocation rate limiter, the catalog size and the descriptions.

## 3. Publication checklist

- [x] `pyproject.toml` says `0.8.0`; `uv.lock` records `sophos-firewall-mcp-server` `0.8.0` (a
      one-line project-version refresh — no dependency changed).
- [x] `CHANGELOG.md` has the `[0.8.0]` entry; `README.md` reflects 0.8.0 (this PR).
- [x] `docs/release/RELEASE-0.8.0.md` is this document.
- [x] Local gates green on this branch — see the gate record below.
- [ ] Independent review **APPROVE**.
- [ ] CI green on the merge commit (tests 3.11–3.14, lint, image build, dependency audit, semgrep).
- [ ] Tag `v0.8.0` on the merge commit; the `release` job publishes `0.8.0`, `0.8` and `latest`.
- [ ] GitHub release with these notes.
- [ ] Post-publish: image tags present; the container build + STDIO smoke test ran green in CI on the
      same commit.

**Gate record (this branch, after the version bump):**

| Gate | Result |
|---|---|
| `uv sync --locked` | clean — installs `sophos-firewall-mcp-server==0.8.0` |
| `uv run --no-sync pytest -q` | **1499 passed, 100 skipped** (304 s) |
| `uv run --no-sync flake8 src/sophos_firewall_mcp tests scripts` | clean |
| `uv run --no-sync mypy src/sophos_firewall_mcp` | clean (30 files) |
| `uv run --no-sync black --check src tests scripts` | clean (63 files) |
| `uv lock --check` | clean |

## 4. Approval record

**Not approved yet.** 0.8.0 is prepared on `release/0.8.0` and must not be tagged, published or
promoted to `latest` without explicit owner approval. The approval is recorded here once given,
together with the independent review verdict.
