"""Refuse to start when ``mcp`` resolves outside this server's own environment.

The dependency is pinned to ``mcp<2`` because ``mcp.server.fastmcp`` was removed in 2.0. That pin protects
the *install*, not the *run*: a parent process that exports ``PYTHONPATH`` pointing at another
site-packages shadows the venv, the import raises, and the process dies before it can answer a single
JSON-RPC frame. The MCP client on the other side sees no message at all -- just an empty error -- which is
how this failure gets misdiagnosed as bad credentials or bad networking.

This module turns that into one actionable sentence on stderr and a non-zero exit, before the server
pretends to be alive.
"""

import sys
from pathlib import Path

_MESSAGE = """sophos-firewall-mcp: cannot start.

  reason            : {reason}
  mcp imported from : {where}
  this environment  : {prefix}

  Fix: run the server with a clean interpreter environment -- this server needs `mcp<2`:

      env -u PYTHONPATH -u PYTHONHOME ./venv/bin/sophos-firewall-mcp-server

  and install it the same way, otherwise pip treats the parent's packages as already satisfied
  and skips real dependencies:

      env -u PYTHONPATH -u PYTHONHOME ./venv/bin/pip install .
"""


def mcp_location() -> Path | None:
    """Filesystem path the ``mcp`` package was imported from, or None when it is not importable."""
    try:
        import mcp
    except ModuleNotFoundError:
        return None
    location = getattr(mcp, "__file__", None)
    return Path(location).resolve() if location else None


def has_fastmcp() -> bool:
    """Whether the installed ``mcp`` still provides ``mcp.server.fastmcp`` (mcp < 2).

    Imports the module rather than a symbol from it: that is exactly what the server does, and mcp 2.x
    ships a shim that raises ``ModuleNotFoundError`` on import to explain the rename.
    """
    try:
        import mcp.server.fastmcp  # noqa: F401
    except ModuleNotFoundError:
        return False
    return True


def _fail(reason: str, where: str, prefix: str) -> None:
    sys.stderr.write(_MESSAGE.format(reason=reason, where=where, prefix=prefix))
    sys.stderr.flush()
    raise SystemExit(2)


def verify_local_mcp() -> None:
    """Exit with a diagnosable message when the interpreter environment is not usable.

    Two distinct failures, two distinct reasons, because they have different fixes:

    * ``mcp`` imported from outside ``sys.prefix`` -- a ``PYTHONPATH`` is shadowing the venv.
    * ``mcp`` is local but is version 2.x -- ``mcp.server.fastmcp`` no longer exists.
    """
    prefix = str(Path(sys.prefix).resolve())
    location = mcp_location()

    if location is None:
        return  # nothing installed to inspect; the real import reports its own error

    if not str(location).startswith(prefix):
        _fail(
            "'mcp' resolved outside this server's environment -- a PYTHONPATH is shadowing the venv",
            str(location),
            prefix,
        )

    if not has_fastmcp():
        _fail(
            "this server requires mcp<2: 'mcp.server.fastmcp' was removed in mcp 2.x",
            str(location),
            prefix,
        )
