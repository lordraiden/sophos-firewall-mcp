# Invocation-rate policy (MCP 2026-07-28)

**Status:** enforced
**Scope:** Sophos Firewall MCP server, STDIO transport, one MCP client per process
**Related:** issues #63 (initial risk acceptance) and #77 (implementation); `docs/architecture/sophos-rest-api-redesign/MCP-STANDARDS-REVIEW-0.7.md` (L8)

## The requirement

The MCP `2026-07-28` Tools specification, in *Security Considerations*, states:

> 1. Servers **MUST**:
>    - Validate all tool inputs
>    - Implement proper access controls
>    - Rate limit tool invocations
>    - Sanitize tool outputs

Source: <https://modelcontextprotocol.io/specification/2026-07-28/server/tools#security-considerations>

The server advertises `2026-07-28` (`tests/test_mcp_e2e.py`, `MODERN_PROTOCOL_VERSION`), so this is
the requirement that applies to it. It is now **implemented**, not accepted as a residual risk.

## Concurrency is not rate

The two controls answer different questions and must not be described as one another:

| Control | Question it answers | Setting | Default | Ceiling |
|---|---|---|---|---|
| Concurrency semaphore | How many HTTP requests may overlap? | `SOPHOS_MAX_CONCURRENCY` | `4` | `64` |
| Invocation rate | How many `tools/call` requests may a client issue over time? | `SOPHOS_INVOCATION_RATE_PER_MINUTE` / `SOPHOS_INVOCATION_BURST` | `60`/min, burst `10` | `6000`/min, burst `1000` |

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
  the semaphore caps the overlap at `SOPHOS_MAX_CONCURRENCY`, and the invocation limiter caps the
  sustained rate.
- *Writes* are the dangerous class. A runaway loop that mutates rules or NAT entries is bounded by
  the invocation limiter, by read-only mode (mutation tools are not registered at all when
  `SOPHOS_READ_ONLY_MODE=true`), by the Sophos administrator profile behind the API key (the actual
  authorization boundary), and by the fact that writes are never retried.
- *The server itself* has no unbounded queue or per-call allocation that the limiter would protect:
  each call is one HTTP request plus a JSON decode, and the semaphore prevents connection-pool
  exhaustion.

**Controls.**

- The STDIO transport limits access to the one local client that spawned the process. The MCP
  security guidance itself recommends STDIO for local servers precisely to "limit access to just
  the MCP client".
- The invocation-rate limiter bounds the sustained `tools/call` rate (this document).
- The concurrency semaphore bounds the load a fan-out can place on the appliance.
- The appliance rate-limits on its own side and returns errors the server surfaces as sanitized
  `ToolError`s.
- Read-only mode removes mutation tools entirely; the administrator profile is the authorization
  boundary.
- Writes are never retried, so a timeout cannot duplicate a mutation.

## Decision

**The server enforces a process-local invocation-rate limit at the MCP tool-dispatch boundary.** It
is a `ServerMiddleware` (`src/sophos_firewall_mcp/ratelimit.py`) registered in `create_server`, so it
sees every `tools/call` request before any handler runs.

**Algorithm: token bucket.** `SOPHOS_INVOCATION_RATE_PER_MINUTE` tokens are added per minute, up to
`SOPHOS_INVOCATION_BURST`; each `tools/call` consumes one token. The bucket uses `time.monotonic`, so
a wall-clock step cannot grant or withhold tokens unexpectedly.

**Defaults: 60 invocations per minute, burst 10.** A firewall management API is not a
high-throughput data plane: a human-driven session rarely exceeds a few calls per minute, and an
agent that needs more can still make one call per second. Ten back-to-back invocations cover a short
fan-out (a model listing several collections, or a composite plus a few follow-up reads) without
letting a runaway loop empty a large bucket at once. Both values are configurable and validated;
zero, negative or absurd values fail startup, and there is no unlimited/off default. A blank value
(`SOPHOS_INVOCATION_RATE_PER_MINUTE=` or `SOPHOS_INVOCATION_BURST=`) is treated as unset and falls
back to the default, consistent with `SOPHOS_TIMEOUT` and `SOPHOS_MAX_CONCURRENCY`: that is
fail-safe — the limiter stays on — but an operator who writes a blank value gets the default rather
than an error.

**One invocation per `tools/call`.** A composite tool (`audit_firewall_rules`,
`explain_connectivity`, `find_object_usage`) consumes one token, not one per internal adapter read,
because the limiter sits above the handler rather than around the HTTP client. This is the reason
the limiter is not in `SophosRestClient._send`: that layer would count each internal read of a
composite as a separate invocation and throttle the tools it is meant to protect.

**MRTR accounting: every incoming `tools/call` consumes one token, including a resume.** A resume
that carries `requestState` is a new request and is charged as one. The alternative — charging a
resume to its originating call — would need cross-request state and would let a client mint repeated
resumes without paying for them. Charging every request is conservative and cannot be bypassed by
repeated resumes; the replay guard independently makes a sealed state single-use, so a replayed
resume is refused even when it has a token.

**Ordering: outermost, before the MRTR replay guard.** A throttled call is rejected before the
replay guard reserves the single-use confirmation, so a throttled MRTR resume does not consume the
confirmation state; the client can retry the resume after the limit resets. The limiter also runs
before the SDK's `RequestStateBoundary`, so it counts the request even when the boundary later
rejects a malformed state — a request is a request.

**Fail fast, no waiter queue.** When the bucket is empty the call returns an `isError` tool result
that names the configured rate, burst and retry delay. Nothing waits for a token, so a throttled
call cannot block shutdown, grow memory, or be cancelled while holding a slot. A cancelled call has
already consumed its token, which is the safe direction.

**Sanitized, actionable error.** The result is a normal MCP tool execution error (`isError: true`
with `resultType: "complete"`), not a JSON-RPC protocol error, because the model can self-correct by
waiting and retrying. The message exposes only the configured policy and the retry delay; it never
includes arguments, credentials, appliance data or internal bucket state.

**Observability.** A throttled call logs one `WARNING` naming the tool and the retry delay. The tool
name is a public catalog identifier; arguments, credentials and appliance data are never logged.

## Residual risk

- **The bucket is process-local.** A client that restarts the server (or a deployment that runs
  several processes) gets a fresh bucket per process. This is consistent with the STDIO model, where
  one client owns one process, and with the SDK's process-local request-state key.
- **The limiter is not an authorization boundary.** It bounds the rate, not what a caller may do;
  the Sophos administrator profile behind the API key remains the authorization boundary.
- **A sustained loop is slowed, not stopped.** At the default rate a runaway loop can still make one
  call per second after the burst; the appliance's own rate limiting and the client/host's timeouts
  remain the backstop for a long-running loop.
- **A future HTTP transport or shared multi-client process needs a shared limiter.** The current
  bucket is per process; a multi-process deployment would need a shared store to enforce one global
  rate.

## What is tested

- `tests/test_ratelimit.py` drives the token bucket with a fake monotonic clock and proves the burst,
  refill, partial-refill and capacity boundaries, the rejection wait, concurrent calls consuming
  exactly the burst, cancellation leaving the bucket consistent, fail-fast rejection without a
  waiter queue, the MRTR resume consuming a token, and the limiter being the outermost middleware.
- `tests/test_mcp_e2e.py::test_a_rate_limited_tool_call_returns_an_iserror_result` proves the
  sanitized `isError` result over the real SDK `Client` wire path.
- `tests/test_mcp_e2e.py::test_tool_calls_within_the_configured_rate_are_accepted` proves the limiter
  does not throttle a caller inside the configured policy.
- `tests/test_config.py` proves the defaults are finite and non-zero, the settings are read from the
  environment, and zero, negative, absurd and non-integer values fail startup.
- `tests/test_client.py::test_concurrent_requests_are_bounded_by_the_semaphore` (existing) proves the
  concurrency bound is independent and still enforced.
