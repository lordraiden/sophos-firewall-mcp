"""Refuse to start when ``mcp`` resolves outside this server's own environment.

The dependency is pinned to ``mcp>=2`` because ``mcp.server.fastmcp`` was removed in 2.0 and replaced by ``mcp.server.mcpserver``. That pin protects
the *install*, not the *run*: a parent process that exports ``PYTHONPATH`` pointing at another
site-packages shadows the venv, the import raises, and the process dies before it can answer a single
JSON-RPC frame. The MCP client on the other side sees no message at all -- just an empty error -- which is
how this failure gets misdiagnosed as bad credentials or bad networking.

This module turns that into one actionable sentence on stderr before the server pretends to be
alive. The response depends on how unambiguous the evidence is:

* ``mcp`` imported from outside ``sys.prefix`` is a *warning*: the string-prefix test also fires in
  legitimate layouts (a ``--system-site-packages`` virtualenv, a ``pipx``/``uv tool`` install, a
  container whose package prefix is not the interpreter's ``sys.prefix``), so a hard exit would turn
  a working install into "cannot start". The real import decides.
* ``mcp`` is importable but has no ``mcp.server.mcpserver`` is a *hard exit*: that one is
  unambiguous, and the server cannot serve a single frame without it.
"""

import sys
from pathlib import Path

_MESSAGE = """sophos-firewall-mcp: cannot start.

  reason            : {reason}
  mcp imported from : {where}
  this environment  : {prefix}

  Fix: run the server with a clean interpreter environment -- this server needs `mcp>=2`:

      env -u PYTHONPATH -u PYTHONHOME ./venv/bin/sophos-firewall-mcp-server

  and install it the same way, otherwise pip treats the parent's packages as already satisfied
  and skips real dependencies:

      env -u PYTHONPATH -u PYTHONHOME ./venv/bin/pip install .
"""


_WARNING = """sophos-firewall-mcp: warning: 'mcp' resolved outside this server's environment.

  mcp imported from : {where}
  this environment  : {prefix}

  This is expected for a virtualenv created with --system-site-packages, a pipx/uv tool install
  whose dependency environment is not the interpreter's sys.prefix, or a container that installs
  the package into a different prefix. The server continues and the import decides.

  If it then fails to import 'mcp.server.mcpserver', run it with a clean interpreter environment:

      env -u PYTHONPATH -u PYTHONHOME ./venv/bin/sophos-firewall-mcp-server
"""


def mcp_location() -> Path | None:
    """Filesystem path the ``mcp`` package was imported from, or None when it is not importable."""
    try:
        import mcp
    except ModuleNotFoundError:
        return None
    location = getattr(mcp, "__file__", None)
    return Path(location).resolve() if location else None


def has_mcpserver() -> bool:
    """Whether the installed ``mcp`` provides ``mcp.server.mcpserver`` (mcp >= 2).

    Imports the module rather than a symbol from it: that is exactly what the server does, and on mcp 1.x
    the module simply does not exist.
    """
    try:
        import mcp.server.mcpserver  # noqa: F401
    except ModuleNotFoundError:
        return False
    return True


def _warn(where: str, prefix: str) -> None:
    """Report a suspicious but not necessarily broken layout, and keep going."""
    sys.stderr.write(_WARNING.format(where=where, prefix=prefix))
    sys.stderr.flush()


def _fail(reason: str, where: str, prefix: str) -> None:
    sys.stderr.write(_MESSAGE.format(reason=reason, where=where, prefix=prefix))
    sys.stderr.flush()
    raise SystemExit(2)


def verify_local_mcp() -> None:
    """Warn or exit when the interpreter environment looks unusable.

    Two distinct failures, two distinct responses, because they have different fixes:

    * ``mcp`` imported from outside ``sys.prefix`` -- a ``PYTHONPATH`` may be shadowing the venv,
      but the same prefix test also fires in legitimate layouts, so this only warns.
    * ``mcp`` is local but is version 1.x -- ``mcp.server.mcpserver`` does not exist yet, and no
      layout makes that work: this exits.
    """
    prefix = str(Path(sys.prefix).resolve())
    location = mcp_location()

    if location is None:
        return  # nothing installed to inspect; the real import reports its own error

    if not str(location).startswith(prefix):
        _warn(str(location), prefix)

    if not has_mcpserver():
        _fail(
            "this server requires mcp>=2: 'mcp.server.mcpserver' is missing (mcp 1.x installed)",
            str(location),
            prefix,
        )
