"""Tests for the MCP tool-invocation rate limiter (``sophos_firewall_mcp.ratelimit``).

The token bucket is driven by a fake monotonic clock, so burst, refill and rejection
boundaries are deterministic. The middleware is driven with a minimal
:class:`~mcp.server.context.ServerRequestContext` and a fake ``call_next``, so the tests
prove the dispatch-boundary behaviour without a transport.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

import httpx
import pytest
import respx

from mcp import Client, types
from mcp.server.context import ServerRequestContext

from sophos_firewall_mcp.config import Settings
from sophos_firewall_mcp.mrtr import (
    consumed_state_count,
    mrtr_replay_guard,
    reset_consumed_states,
)
from sophos_firewall_mcp.ratelimit import (
    DEFAULT_INVOCATION_BURST,
    DEFAULT_INVOCATION_RATE_PER_MINUTE,
    InvocationRateLimiter,
    TokenBucket,
)
from sophos_firewall_mcp.server import create_server

HOST = "fw.example.com"
KEY = "sfos_test_key_0123456789abcdef"
BASE = f"https://{HOST}:4444/api/firewall-config/v1"


class FakeClock:
    """A monotonic clock the test advances explicitly."""

    def __init__(self, now: float = 1000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def make_ctx(
    method: str = "tools/call", params: dict[str, Any] | None = None
) -> ServerRequestContext[Any, Any]:
    """A minimal request context: the middleware only reads ``method`` and ``params``."""
    return ServerRequestContext(
        session=None,  # type: ignore[arg-type]
        lifespan_context=None,
        protocol_version="2025-11-25",
        method=method,
        params=params,
    )


async def accept(ctx: ServerRequestContext[Any, Any]) -> dict[str, Any]:
    """A ``call_next`` that records nothing and succeeds."""
    return {"ok": True}


# -- Token bucket ------------------------------------------------------------


def test_burst_allows_exactly_the_capacity() -> None:
    bucket = TokenBucket(rate_per_minute=60, burst=3, clock=FakeClock())

    assert [bucket.try_acquire() for _ in range(3)] == [None, None, None]
    assert bucket.try_acquire() == pytest.approx(1.0)


def test_refill_grants_one_token_per_interval() -> None:
    clock = FakeClock()
    bucket = TokenBucket(rate_per_minute=60, burst=1, clock=clock)

    assert bucket.try_acquire() is None
    assert bucket.try_acquire() is not None
    clock.advance(1.0)
    assert bucket.try_acquire() is None


def test_a_partial_interval_does_not_grant_a_token() -> None:
    clock = FakeClock()
    bucket = TokenBucket(rate_per_minute=60, burst=1, clock=clock)

    assert bucket.try_acquire() is None
    clock.advance(0.5)
    assert bucket.try_acquire() is not None
    clock.advance(0.5)
    assert bucket.try_acquire() is None


def test_the_bucket_never_exceeds_the_burst() -> None:
    clock = FakeClock()
    bucket = TokenBucket(rate_per_minute=60, burst=2, clock=clock)

    clock.advance(3600)
    assert bucket.try_acquire() is None
    assert bucket.try_acquire() is None
    assert bucket.try_acquire() is not None


def test_the_rejection_wait_is_the_time_to_one_token() -> None:
    clock = FakeClock()
    bucket = TokenBucket(rate_per_minute=120, burst=1, clock=clock)

    assert bucket.try_acquire() is None
    # 120/min is 2/s, so one token takes 0.5 s.
    assert bucket.try_acquire() == pytest.approx(0.5)


# -- Middleware --------------------------------------------------------------


async def test_non_tool_calls_do_not_consume_tokens() -> None:
    limiter = InvocationRateLimiter(rate_per_minute=60, burst=1, clock=FakeClock())

    assert await limiter(make_ctx("tools/list"), accept) == {"ok": True}
    assert await limiter(make_ctx("resources/read"), accept) == {"ok": True}
    # The bucket is still full, so the first tools/call succeeds.
    assert await limiter(make_ctx(), accept) == {"ok": True}


async def test_a_throttled_call_returns_an_iserror_result() -> None:
    limiter = InvocationRateLimiter(rate_per_minute=60, burst=1, clock=FakeClock())

    assert await limiter(make_ctx(), accept) == {"ok": True}
    result = await limiter(make_ctx(), accept)

    assert result["isError"] is True
    assert result["resultType"] == "complete"
    assert result["content"][0]["type"] == "text"
    text = result["content"][0]["text"]
    assert "Rate limit exceeded" in text
    assert "60 tool invocations per minute" in text
    assert "burst of 1" in text
    assert "Retry after 1 second." in text


async def test_an_mrtr_resume_consumes_a_token() -> None:
    """A resume is a new tools/call and is charged as one: no bypass through resumes."""
    limiter = InvocationRateLimiter(rate_per_minute=60, burst=1, clock=FakeClock())

    assert await limiter(make_ctx(params={"name": "x"}), accept) == {"ok": True}
    resume = make_ctx(
        params={"name": "x", "requestState": "sealed", "inputResponses": {"confirm": True}}
    )
    result = await limiter(resume, accept)

    assert result["isError"] is True


async def test_concurrent_calls_consume_exactly_the_burst() -> None:
    limiter = InvocationRateLimiter(rate_per_minute=60, burst=5, clock=FakeClock())

    results = await asyncio.gather(*(limiter(make_ctx(), accept) for _ in range(20)))

    accepted = [result for result in results if result.get("ok") is True]
    rejected = [result for result in results if result.get("isError") is True]
    assert len(accepted) == 5
    assert len(rejected) == 15


async def test_a_cancelled_call_does_not_corrupt_the_bucket() -> None:
    clock = FakeClock()
    limiter = InvocationRateLimiter(rate_per_minute=60, burst=1, clock=clock)
    started = asyncio.Event()

    async def slow(ctx: ServerRequestContext[Any, Any]) -> dict[str, Any]:
        started.set()
        await asyncio.sleep(30)
        return {"ok": True}

    task = asyncio.create_task(limiter(make_ctx(), slow))
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    # The token was consumed before the handler; the bucket is empty but consistent.
    assert limiter.try_acquire() is not None
    clock.advance(1.0)
    assert limiter.try_acquire() is None


async def test_a_throttled_call_fails_fast_without_a_waiter_queue() -> None:
    limiter = InvocationRateLimiter(rate_per_minute=1, burst=1, clock=FakeClock())

    assert await limiter(make_ctx(), accept) == {"ok": True}
    start = time.monotonic()
    results = await asyncio.gather(*(limiter(make_ctx(), accept) for _ in range(100)))
    elapsed = time.monotonic() - start

    assert all(result["isError"] is True for result in results)
    # Fail-fast: 100 rejections complete without waiting for a token.
    assert elapsed < 1.0


# -- Registration and ordering ----------------------------------------------


def test_the_limiter_is_the_outermost_middleware() -> None:
    """A throttled call must be rejected before the replay guard reserves the confirmation."""
    server = create_server(Settings(host="fw.example.com", api_key="k"), domains=[])

    assert isinstance(server.middleware[0], InvocationRateLimiter)
    assert server.middleware[1] is mrtr_replay_guard


def test_the_defaults_are_finite_and_non_zero() -> None:
    assert DEFAULT_INVOCATION_RATE_PER_MINUTE == 60
    assert DEFAULT_INVOCATION_BURST == 10


async def test_a_throttled_mrtr_resume_does_not_consume_the_confirmation() -> None:
    """The ordering rationale, behaviourally: a throttled resume leaves the state unconsumed.

    The limiter is outermost, so a throttled resume is rejected before ``mrtr_replay_guard``
    reserves the single-use confirmation. After the bucket refills, the same resume succeeds
    and consumes the confirmation exactly once.
    """
    reset_consumed_states()
    clock = FakeClock()
    server = create_server(
        Settings(
            host=HOST,
            api_key=KEY,
            invocation_rate_per_minute=60,
            invocation_burst=1,
        )
    )
    # Replace the server's limiter with one on the fake clock so the refill is deterministic.
    server.middleware[0] = InvocationRateLimiter(rate_per_minute=60, burst=1, clock=clock)

    name = "firewall_rule_delete"
    args = {"ip_family": "ipv4", "id_or_name": "allow-lan-to-wan"}

    async def accept(context: Any, params: types.ElicitRequestParams) -> types.ElicitResult:
        return types.ElicitResult(action="accept", content={"confirm": True})

    try:
        with respx.mock(assert_all_called=False) as router:
            router.delete(f"{BASE}/firewall/rules/ipv4/allow-lan-to-wan").mock(
                return_value=httpx.Response(200, json={"deleted": True})
            )
            async with Client(server, elicitation_callback=accept) as client:
                first = await client.session.call_tool(name, args, allow_input_required=True)
                assert isinstance(first, types.InputRequiredResult)
                key = next(iter(first.input_requests or {}))
                answer = types.ElicitResult(action="accept", content={"confirm": True})

                # The initial round consumed the only token, so the resume is throttled.
                throttled = await client.session.call_tool(
                    name,
                    args,
                    allow_input_required=True,
                    input_responses={key: answer},
                    request_state=first.request_state,
                )
                assert isinstance(throttled, types.CallToolResult)
                assert throttled.is_error is True
                assert "Rate limit exceeded" in throttled.content[0].text
                # The replay guard never saw the throttled resume: the confirmation is intact.
                assert consumed_state_count() == 0

                # After the refill the same resume succeeds and consumes the confirmation.
                clock.advance(1.0)
                resumed = await client.session.call_tool(
                    name,
                    args,
                    allow_input_required=True,
                    input_responses={key: answer},
                    request_state=first.request_state,
                )
                assert isinstance(resumed, types.CallToolResult)
                assert resumed.is_error is False
                assert consumed_state_count() == 1
    finally:
        reset_consumed_states()
