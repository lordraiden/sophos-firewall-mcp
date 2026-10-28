"""Make every tool failure name itself.

The MCP SDK formats a tool failure as ``Error executing tool <name>: <exc>``. When ``str(exc)`` is empty --
a bare ``TimeoutError()``, a swallowed cancellation -- the model receives a colon and nothing else, which
is indistinguishable from a crashed server. That cost a multi-day misdiagnosis of this server: the failure
was read as "the process died", then as "the appliance is slow", and both were wrong.

Upstream traced the same symptom through Hermes and concluded (NousResearch/hermes-agent#145923) that the
empty text is born **here, in the server**, not in the client: the client's tool deadline is 300 s, its
keepalive refuses to run while a call is in flight, and what reaches the model is the SDK wrapping a
server-side exception whose ``str()`` is empty.

So the fix belongs here: no exception leaves a tool without a name, and the ones that were previously
invisible leave a traceback in the server log. When it happens again, the log says which exception it was
instead of asking the question a third time.
"""

import asyncio
import functools
import inspect
import logging
import time
from typing import Any, Callable, Iterable

from sophos_firewall_mcp.client import SophosAPIError

logger = logging.getLogger(__name__)

# Exceptions that must keep propagating untouched: converting a cancellation would hide it from the SDK
# and from the client, and turning SystemExit/KeyboardInterrupt into a tool error would trap shutdown.
_PASSTHROUGH = (asyncio.CancelledError, KeyboardInterrupt, SystemExit)


def _describe(exc: BaseException) -> str:
    """Exception name plus its own text, never the empty string."""
    text = str(exc).strip()
    if not text:
        text = "<the exception carried no message>"
    return f"{type(exc).__name__}: {text}"


def guard_tool(fn: Callable[..., Any]) -> Callable[..., Any]:
    """Wrap a tool function so no failure escapes unnamed."""
    if getattr(fn, "__sophos_guarded__", False):
        return fn

    is_async = inspect.iscoroutinefunction(fn)

    @functools.wraps(fn)
    async def _async_wrapper(*args: Any, **kwargs: Any) -> Any:
        started = time.monotonic()
        try:
            return await fn(*args, **kwargs)
        except _PASSTHROUGH:
            raise
        except SophosAPIError:
            # Ours always carry a message and the right classification; wrapping them again would nest
            # two prefixes. Anything else -- including a bare KeyError or ValueError, whose str() can be
            # empty -- is named below: no exception leaves a tool without one.
            raise
        except BaseException as exc:               # noqa: BLE001 - the point is to name anything
            elapsed = time.monotonic() - started
            logger.exception(
                "tool %s failed unexpectedly after %.2fs: %s (this traceback is the diagnosis; "
                "without it the client only sees an empty error)", fn.__name__, elapsed, _describe(exc),
            )
            raise SophosAPIError(
                f"{fn.__name__} failed after {elapsed:.1f}s with {_describe(exc)}"
            ) from exc

    @functools.wraps(fn)
    def _sync_wrapper(*args: Any, **kwargs: Any) -> Any:
        started = time.monotonic()
        try:
            return fn(*args, **kwargs)
        except _PASSTHROUGH:
            raise
        except SophosAPIError:
            raise
        except BaseException as exc:               # noqa: BLE001
            elapsed = time.monotonic() - started
            logger.exception(
                "tool %s failed unexpectedly after %.2fs: %s", fn.__name__, elapsed, _describe(exc),
            )
            raise SophosAPIError(
                f"{fn.__name__} failed after {elapsed:.1f}s with {_describe(exc)}"
            ) from exc

    wrapper = _async_wrapper if is_async else _sync_wrapper
    setattr(wrapper, "__sophos_guarded__", True)   # marker read by guard_tool / the wiring test
    return wrapper


def guard_module_tools(modules: Iterable[Any], prefix: str = "sophos_") -> int:
    """Guard every ``sophos_*`` function of the given modules, in place.

    Wrapping the module attribute is what makes the 41 registration lines in ``server.py`` pick the
    guarded version without repeating a decorator 41 times -- and without touching the private registry
    of the SDK.
    """
    count = 0
    for module in modules:
        for name in dir(module):
            if not name.startswith(prefix):
                continue
            fn = getattr(module, name)
            if not callable(fn):
                continue
            setattr(module, name, guard_tool(fn))
            count += 1
    return count
