"""Process-local invocation-rate limiter at the MCP tool-dispatch boundary.

The MCP ``2026-07-28`` Tools specification lists "Rate limit tool invocations" among the
server's Security Considerations. This module implements that control as a
:class:`~mcp.server.context.ServerMiddleware` that counts every ``tools/call`` request:

* a composite tool (``audit_firewall_rules``, ``explain_connectivity``,
  ``find_object_usage``) consumes **one** invocation, however many adapter reads it performs,
  because the middleware sits above the handler rather than around the HTTP client;
* an MRTR resume is a new ``tools/call`` and consumes one invocation too (see below).

Algorithm
---------
A token bucket. ``rate_per_minute`` tokens are added per minute, up to ``burst`` tokens; each
``tools/call`` consumes one token. When the bucket is empty the call **fails fast** with an
``isError`` tool result that names the configured policy and a retry delay. There is no
waiter queue, so a throttled call cannot block shutdown, grow memory, or be cancelled while
holding a slot.

The bucket is not locked: the middleware runs on the event loop and
:meth:`TokenBucket.try_acquire` is synchronous, so a check-and-consume cannot be interleaved
with another coroutine. A cancelled call has already consumed its token, which is the safe
direction (a cancelled call still counts against the rate).

Ordering
--------
The limiter is the **outermost** middleware, before :func:`~sophos_firewall_mcp.mrtr.mrtr_replay_guard`
and the SDK's ``RequestStateBoundary``. A throttled call is therefore rejected before the
replay guard reserves the single-use confirmation, so a throttled MRTR resume does not
consume the confirmation state; the client can retry the resume after the limit resets.

MRTR accounting
---------------
Every incoming ``tools/call`` consumes one token, including a resume that carries
``requestState``. A resume is a new request and is charged as one. The alternative -- charging
a resume to its originating call -- would need cross-request state and would let a client
mint repeated resumes without paying for them. Charging every request is conservative and
cannot be bypassed by repeated resumes; the replay guard independently makes a sealed state
single-use, so a replayed resume is refused even when it has a token.

Observability
-------------
A throttled call logs one ``WARNING`` naming the tool and the retry delay. The tool name is a
public catalog identifier; arguments, credentials and appliance data are never logged.
"""

from __future__ import annotations

import logging
import math
import time
from collections.abc import Callable
from typing import Any

from mcp.server.context import CallNext, HandlerResult, ServerRequestContext

__all__ = [
    "DEFAULT_INVOCATION_BURST",
    "DEFAULT_INVOCATION_RATE_PER_MINUTE",
    "MAX_INVOCATION_BURST",
    "MAX_INVOCATION_RATE_PER_MINUTE",
    "InvocationRateLimiter",
    "TokenBucket",
]

logger = logging.getLogger(__name__)

#: Default sustained invocation rate, in tool invocations per minute.
#:
#: A firewall management API is not a high-throughput data plane: a human-driven session
#: rarely exceeds a few calls per minute, and an agent that needs more can still make one
#: call per second. Sixty per minute is generous for interactive use while bounding a
#: runaway loop to a rate the appliance's management plane can absorb.
DEFAULT_INVOCATION_RATE_PER_MINUTE = 60

#: Default burst capacity: how many invocations may run back-to-back before the rate applies.
#:
#: Ten covers a short fan-out (a model listing several collections, or a composite plus a
#: few follow-up reads) without letting a runaway loop empty a large bucket at once. The
#: concurrency semaphore (``SOPHOS_MAX_CONCURRENCY``, default 4) still bounds how many of
#: those invocations overlap on the wire.
DEFAULT_INVOCATION_BURST = 10

#: Upper bound for the sustained rate (100 invocations per second).
MAX_INVOCATION_RATE_PER_MINUTE = 6000

#: Upper bound for the burst capacity.
MAX_INVOCATION_BURST = 1000


class TokenBucket:
    """A monotonic-clock token bucket with no waiters.

    Args:
        rate_per_minute: Tokens added per minute.
        burst: Bucket capacity, in tokens.
        clock: Monotonic clock, injectable so tests can advance time deterministically.
    """

    def __init__(
        self,
        *,
        rate_per_minute: int,
        burst: int,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._rate_per_second = rate_per_minute / 60.0
        self._burst = float(burst)
        self._tokens = float(burst)
        self._clock = clock
        self._last = clock()

    def try_acquire(self) -> float | None:
        """Consume one token.

        Returns:
            ``None`` when a token was available and consumed; otherwise the number of seconds
            until one token will be available (always positive).
        """
        now = self._clock()
        elapsed = now - self._last
        if elapsed > 0:
            self._tokens = min(self._burst, self._tokens + elapsed * self._rate_per_second)
            self._last = now
        if self._tokens >= 1.0:
            self._tokens -= 1.0
            return None
        return (1.0 - self._tokens) / self._rate_per_second


class InvocationRateLimiter:
    """A ``ServerMiddleware`` that rate-limits ``tools/call`` requests.

    Every other method (``tools/list``, ``resources/read``, ``prompts/get``, ``initialize``,
    notifications) passes through untouched: the requirement is about tool invocations, and
    discovery is not a tool invocation.
    """

    def __init__(
        self,
        *,
        rate_per_minute: int = DEFAULT_INVOCATION_RATE_PER_MINUTE,
        burst: int = DEFAULT_INVOCATION_BURST,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._rate_per_minute = rate_per_minute
        self._burst = burst
        self._bucket = TokenBucket(rate_per_minute=rate_per_minute, burst=burst, clock=clock)

    def try_acquire(self) -> float | None:
        """Consume one invocation allowance. Test and diagnostic seam."""
        return self._bucket.try_acquire()

    async def __call__(
        self, ctx: ServerRequestContext[Any, Any], call_next: CallNext
    ) -> HandlerResult:
        if ctx.method != "tools/call":
            return await call_next(ctx)
        wait = self._bucket.try_acquire()
        if wait is None:
            return await call_next(ctx)
        retry_after = max(1, math.ceil(wait))
        tool = (ctx.params or {}).get("name")
        logger.warning(
            "rate limit exceeded for tools/call (tool=%r); retry after %ss",
            tool,
            retry_after,
        )
        return {
            "content": [
                {
                    "type": "text",
                    "text": (
                        f"Rate limit exceeded: this server allows {self._rate_per_minute} tool "
                        f"invocations per minute with a burst of {self._burst}. "
                        f"Retry after {retry_after} second"
                        f"{'s' if retry_after != 1 else ''}."
                    ),
                }
            ],
            "isError": True,
            # The modern 2026-07-28 protocol requires ``resultType`` on every result; the
            # legacy revisions drop it as a later-revision field, so it is safe on both.
            "resultType": "complete",
        }
