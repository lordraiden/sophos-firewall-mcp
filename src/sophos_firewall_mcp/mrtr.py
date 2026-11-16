"""Single-use guard for the sealed MRTR ``requestState`` (issue #54).

The MCP SDK's ``RequestStateBoundary`` verifies a resumed ``requestState`` -- codec
integrity, envelope version, ``iat``/``exp``, method/target/args digest, audience and
principal -- but it does not track consumption. ``resolve._restore_outcome`` restores the
recorded confirmation on every round, so the same sealed state can be replayed: a client
that retries on timeout would execute the confirmed delete twice, and a captured state
could delete a re-created object of the same name without a fresh confirmation.

This module adds the missing single-use check. It is a context-tier middleware inserted
**before** the SDK's ``RequestStateBoundary`` (``MCPServer.middleware`` is outermost-first
and the boundary is appended in ``MCPServer.__init__``), so it sees the raw sealed token
the client sent. The first ``tools/call`` carrying a given token is recorded and allowed; a
second use of the same token is refused with ``-32602`` before the boundary unseals it and
before any handler runs.

The consumed set is process-local and bounded: entries older than the SDK's request-state
TTL (600 s) are evicted on every call, and a hard size cap evicts the oldest entries first.
A multi-worker deployment is already protected by the SDK's per-process ephemeral key -- a
state minted by one worker is rejected by another -- so a process-local set is consistent
with the SDK's default security model.
"""

from __future__ import annotations

import hashlib
import time
from collections import OrderedDict
from typing import Any

from mcp.server.context import CallNext, HandlerResult, ServerRequestContext
from mcp.shared.exceptions import MCPError
from mcp.types import INVALID_PARAMS

#: The SDK's default request-state TTL (``RequestStateSecurity.ephemeral``). A token older
#: than this is rejected by the boundary anyway, so it no longer needs remembering.
STATE_TTL_SECONDS = 600.0

#: Hard cap on remembered tokens, so a flood cannot grow the set without bound.
MAX_CONSUMED_STATES = 10_000

#: Digest of every sealed ``requestState`` already used, oldest first, with its monotonic
#: first-use time. Process-local by design; see the module docstring.
_consumed: OrderedDict[str, float] = OrderedDict()


def _digest(state: str) -> str:
    """Return the stable digest stored for one sealed state.

    The token itself is not kept: the digest is enough to recognise a replay and keeps the
    opaque state out of the process's memory.
    """
    return hashlib.sha256(state.encode("utf-8")).hexdigest()


def _evict(now: float) -> None:
    """Drop expired entries, then the oldest ones while over the size cap."""
    cutoff = now - STATE_TTL_SECONDS
    while _consumed:
        _, seen = next(iter(_consumed.items()))
        if seen >= cutoff and len(_consumed) <= MAX_CONSUMED_STATES:
            break
        _consumed.popitem(last=False)


def reset_consumed_states() -> None:
    """Forget every consumed state. Test isolation only; never called by the server."""
    _consumed.clear()


async def mrtr_replay_guard(
    ctx: ServerRequestContext[Any, Any], call_next: CallNext
) -> HandlerResult:
    """Refuse a second use of the same sealed MRTR ``requestState``.

    Only ``tools/call`` requests that carry a non-empty ``requestState`` are affected: the
    first round of an MRTR flow has no state, and every non-MRTR call passes through
    untouched. The check-and-record is synchronous, so two concurrent requests carrying the
    same token cannot both pass it on one event loop.
    """
    state = (ctx.params or {}).get("requestState")
    if ctx.method != "tools/call" or not isinstance(state, str) or not state:
        return await call_next(ctx)

    now = time.monotonic()
    _evict(now)
    digest = _digest(state)
    if digest in _consumed:
        raise MCPError(
            code=INVALID_PARAMS,
            message="this confirmation was already used; re-issue the call to confirm again",
        )
    _consumed[digest] = now
    return await call_next(ctx)
