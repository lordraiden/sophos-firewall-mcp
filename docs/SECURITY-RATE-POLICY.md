# Invocation-rate policy (MCP 2026-07-28)

**Status:** accepted
**Scope:** Sophos Firewall MCP server, STDIO transport, one MCP client per process
**Related:** issue #63; `docs/architecture/sophos-rest-api-redesign/MCP-STANDARDS-REVIEW-0.7.md` (L8)

## The requirement

The MCP `2026-07-28` Tools specification, in *Security Considerations*, states:

> 1. Servers **MUST**:
>    - Validate all tool inputs
>    - Implement proper access controls
>    - Rate limit tool invocations
>    - Sanitize tool outputs

Source: <https://modelcontextprotocol.io/specification/2026-07-28/server/tools#security-considerations>

The server advertises `2026-07-28` (`tests/test_mcp_e2e.py`, `MODERN_PROTOCOL_VERSION`), so this is
the requirement that applies to it.

## Concurrency is not rate

The two controls answer different questions and must not be described as one another:

| Control | Question it answers | Setting | Default | Ceiling |
|---|---|---|---|---|
| Concurrency semaphore | How many HTTP requests may overlap? | `SOPHOS_MAX_CONCURRENCY` | `4` | `64` |
| Invocation rate | How many tool invocations may a client issue over time? | none | — | — |

`SOPHOS_MAX_CONCURRENCY` bounds *in-flight* requests. It does not bound the number of invocations a
client may issue: a client can make an unbounded number of sequential calls, each of which waits for
a slot and then completes. The comment on `DEFAULT_MAX_CONCURRENCY` and the `SophosRestClient`
docstring say this explicitly; neither calls the semaphore a rate limiter.

## Threat model

**Deployment.** The server is a local STDIO MCP server. The MCP client (Claude Desktop, VS Code,
Cursor, an agent host, …) spawns it as a child process and owns its lifecycle. The server has no
network listener, no HTTP port and no multi-user surface. The only way to invoke a tool is to write
JSON-RPC frames to the process's `stdin`; the only way to read results is its `stdout`.

**Actors.**

1. The local user, who configures the client and the appliance credentials.
2. The MCP client, a trusted local process acting for that user.
3. The language model the client drives. This is the erratic actor: a runaway loop, a prompt
   injection, or a buggy agent can issue many tool calls without the user intending it.
4. Another local process. It cannot normally write to the server's `stdin` pipe without the same
   user's privileges, so it is not a distinct threat boundary here.

**Assets.** The Sophos appliance's management plane (the resource that can be overloaded or
mutated), the API key (held as a `SecretStr`, never logged), and the integrity of the appliance
configuration.

**Impact of rapid repeated calls.**

- *Reads* are idempotent. A burst loads the appliance's management plane and the connection pool;
  the semaphore caps the overlap at `SOPHOS_MAX_CONCURRENCY`, and the appliance enforces its own
  rate limits.
- *Writes* are the dangerous class. A runaway loop that mutates rules or NAT entries is bounded by
  read-only mode (mutation tools are not registered at all when `SOPHOS_READ_ONLY_MODE=true`), by
  the Sophos administrator profile behind the API key (the actual authorization boundary), and by
  the fact that writes are never retried.
- *The server itself* has no unbounded queue or per-call allocation that a rate limiter would
  protect: each call is one HTTP request plus a JSON decode, and the semaphore prevents
  connection-pool exhaustion.

**Existing controls.**

- The STDIO transport limits access to the one local client that spawned the process. The MCP
  security guidance itself recommends STDIO for local servers precisely to "limit access to just
  the MCP client".
- The concurrency semaphore bounds the load a fan-out can place on the appliance.
- The appliance rate-limits on its own side and returns errors the server surfaces as sanitized
  `ToolError`s.
- Read-only mode removes mutation tools entirely; the administrator profile is the authorization
  boundary.
- Writes are never retried, so a timeout cannot duplicate a mutation.

## Decision

**This server does not implement a server-side invocation-rate limiter.** The MCP `2026-07-28`
Tools specification says servers **MUST** "Rate limit tool invocations"; this server does not, and
this document records that as an **accepted residual risk** for the local-STDIO,
one-client-per-process deployment model. It does **not** discharge the MUST, and it is not a claim
that the requirement is met.

The risk is accepted because the following controls bound the exposure in this deployment:

1. The STDIO transport restricts callers to the one local MCP client that owns the process.
2. The concurrency semaphore bounds the simultaneous load on the appliance.
3. The appliance enforces its own rate limits, and the server surfaces those errors.
4. The client/host owns the model's call rate (timeouts, loop detection, user confirmation).

Points 1–3 are access-control, concurrency and downstream controls, not server-side invocation-rate
limiting. Point 4 delegates to the client, and the relevant client-side guidance is a **SHOULD**
("Implement timeouts for tool calls", "Prompt for user confirmation on sensitive operations"), not a
MUST. None of the four is the server rate-limiting invocations, so the MUST remains unmet by design.

The semaphore is a concurrency bound and is never described as a rate limiter. This is a deliberate,
recorded judgment, not an oversight; the conditions under which the acceptance no longer holds are
listed below.

## Why not at the HTTP client layer

If a limiter were required, the HTTP client layer would be the wrong place for it. A tool invocation
is not an HTTP request: the composite tools (`audit_firewall_rules`, `explain_connectivity`,
`find_object_usage`) perform many bounded internal reads — up to 80 pages per tool call — through
the same `get`/`get_page` primitives as a single-resource tool. A limiter wrapped around `_send`
would count each of those reads as a separate invocation, so a legitimate composite would consume
dozens of tokens and be delayed or rejected, while a single-resource tool would consume one. That
would break the tools the limit is supposed to protect.

A correct tool-invocation limiter therefore belongs at the tool dispatch layer, where one
`tools/call` is one invocation regardless of how many adapter reads it performs. That layer is
outside this change's scope (it is owned by the concurrent protocol work), and the deployment model
does not require it today.

## Residual risk

- **A runaway model loop can issue many sequential calls.** The server will not stop it; the
  semaphore only bounds overlap. The appliance may throttle or return errors, and the client/host
  may time out. This is the accepted residual risk, and it is the risk the MUST is meant to reduce.
- **The client-side obligation is a SHOULD, not a MUST.** The MCP client guidance says clients
  *SHOULD* implement timeouts for tool calls and *SHOULD* prompt for confirmation on sensitive
  operations. A client that does neither leaves the loop unbounded; the server does not compensate.
- **Practical ceiling of a runaway loop.** The semaphore allows `C` concurrent requests, so with an
  appliance round trip of `L` seconds the sustained ceiling is roughly `C / L` requests per second
  (ignoring client and server overhead). With the default `C = 4` and a 50–200 ms round trip that is
  about **20–80 requests/second**; a purely sequential loop is about `1 / L`, or **5–20/second**.
  At the `SOPHOS_MAX_CONCURRENCY` ceiling of 64 the same arithmetic gives roughly **320–1280
  requests/second**. These are order-of-magnitude estimates, not measurements; they show that the
  semaphore does not make a sustained loop cheap.
- **The appliance's own rate limiting is the backstop.** If it is disabled or generous, a sustained
  sequential loop can load the management plane for longer than the semaphore alone would suggest.
- **A future HTTP transport or shared multi-client process invalidates this decision.** The STDIO
  single-client assumption is load-bearing; without it, the transport no longer restricts callers
  and a tool-invocation limiter becomes necessary.

## Conditions that would change the decision

Add a process-local, tool-invocation limiter (token bucket or sliding window, cancellation-safe,
configurable, with a sanitized actionable error) at the tool dispatch layer if any of these becomes
true:

- the server gains an HTTP/SSE transport or is shared by more than one client per process;
- the deployment model stops treating the MCP client as trusted to bound its own model;
- the appliance's rate limiting is removed or shown to be insufficient for a sustained sequential
  loop.

## What is tested

- `tests/test_client.py::test_sequential_http_requests_are_not_rate_limited` guards the HTTP client
  layer: many sequential requests all succeed, so there is no hidden limiter there.
- `tests/test_mcp_e2e.py::test_tool_calls_are_not_rate_limited_through_the_mcp_client` guards the
  tool-invocation layer the policy is about: 50 `tools/call` requests through the real SDK `Client`
  all succeed.
- `tests/test_client.py::test_concurrent_requests_are_bounded_by_the_semaphore` (existing) proves
  the concurrency bound is real and configurable.
- `tests/test_config.py` asserts the `DEFAULT_MAX_CONCURRENCY` comment describes concurrency, not a
  rate limiter, and that this decision record and the README section exist and stay consistent.
