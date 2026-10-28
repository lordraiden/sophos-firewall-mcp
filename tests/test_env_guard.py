"""Tests for the startup environment guard (issue #8).

The guard exists because an unusable interpreter environment killed the server before it could say why,
and the MCP client only ever saw an empty error. Each branch here is one of the two failures that cost a
real investigation: a shadowed venv, and an mcp too new to have ``mcp.server.fastmcp``.
"""

import sys
from pathlib import Path

import pytest

from sophos_firewall_mcp import _env_guard


def test_real_environment_passes():
    """The install the tests run against must be usable, or every other test is meaningless."""
    _env_guard.verify_local_mcp()


def test_exits_when_mcp_resolves_outside_the_environment(monkeypatch, tmp_path):
    outside = tmp_path / "someone-elses-venv" / "mcp" / "__init__.py"
    outside.parent.mkdir(parents=True)
    outside.write_text("")

    monkeypatch.setattr(_env_guard, "mcp_location", lambda: outside)

    with pytest.raises(SystemExit) as exc:
        _env_guard.verify_local_mcp()
    assert exc.value.code == 2


def test_shadowed_message_is_actionable(monkeypatch, tmp_path, capsys):
    """The message must name the cause, the guilty path and the fix -- that is the whole point."""
    outside = tmp_path / "elsewhere" / "__init__.py"
    outside.parent.mkdir(parents=True)
    outside.write_text("")

    monkeypatch.setattr(_env_guard, "mcp_location", lambda: outside)

    with pytest.raises(SystemExit):
        _env_guard.verify_local_mcp()
    err = capsys.readouterr().err

    assert "shadowing the venv" in err
    assert "PYTHONPATH" in err
    assert str(outside) in err
    assert "env -u PYTHONPATH" in err


def test_exits_when_fastmcp_is_gone(monkeypatch, capsys):
    """mcp >= 2 removed mcp.server.fastmcp: the second distinct failure, with its own reason."""
    local = Path(sys.prefix) / "lib" / "site-packages" / "mcp" / "__init__.py"

    monkeypatch.setattr(_env_guard, "mcp_location", lambda: local)
    monkeypatch.setattr(_env_guard, "has_fastmcp", lambda: False)

    with pytest.raises(SystemExit) as exc:
        _env_guard.verify_local_mcp()
    assert exc.value.code == 2
    assert "mcp<2" in capsys.readouterr().err


def test_tolerates_missing_mcp(monkeypatch):
    """Nothing installed to inspect: stay out of the way and let the real import report itself."""
    monkeypatch.setattr(_env_guard, "mcp_location", lambda: None)
    _env_guard.verify_local_mcp()


def test_has_fastmcp_true_in_this_environment():
    assert _env_guard.has_fastmcp() is True
