"""Tests for the startup environment guard (issue #8, finding L6).

The guard exists because an unusable interpreter environment killed the server before it could say why,
and the MCP client only ever saw an empty error. The prefix check is a warning (a legitimate layout can
trip it); the missing ``mcp.server.mcpserver`` check is still a hard exit.
"""

import sys
from pathlib import Path

import pytest

from sophos_firewall_mcp import _env_guard


def test_real_environment_passes():
    """The install the tests run against must be usable, or every other test is meaningless."""
    _env_guard.verify_local_mcp()


def test_warns_but_starts_when_mcp_resolves_outside_the_environment(monkeypatch, tmp_path, capsys):
    """L6: a legitimate layout (system-site-packages, pipx, container) must start with a warning."""
    outside = tmp_path / "someone-elses-venv" / "mcp" / "__init__.py"
    outside.parent.mkdir(parents=True)
    outside.write_text("")

    monkeypatch.setattr(_env_guard, "mcp_location", lambda: outside)
    monkeypatch.setattr(_env_guard, "has_mcpserver", lambda: True)

    _env_guard.verify_local_mcp()  # must not raise: the real import decides

    err = capsys.readouterr().err
    assert "warning" in err.lower()
    assert str(outside) in err


def test_shadowed_warning_is_actionable(monkeypatch, tmp_path, capsys):
    """The message must name the cause, the guilty path and the fix -- that is the whole point."""
    outside = tmp_path / "elsewhere" / "__init__.py"
    outside.parent.mkdir(parents=True)
    outside.write_text("")

    monkeypatch.setattr(_env_guard, "mcp_location", lambda: outside)
    monkeypatch.setattr(_env_guard, "has_mcpserver", lambda: True)

    _env_guard.verify_local_mcp()
    err = capsys.readouterr().err

    assert "PYTHONPATH" in err
    assert str(outside) in err
    assert str(Path(sys.prefix).resolve()) in err
    assert "env -u PYTHONPATH" in err


def test_a_shadowed_mcp_still_exits_when_mcpserver_is_missing(monkeypatch, tmp_path, capsys):
    """The warning must not swallow the unambiguous failure: mcp 1.x still aborts."""
    outside = tmp_path / "elsewhere" / "__init__.py"
    outside.parent.mkdir(parents=True)
    outside.write_text("")

    monkeypatch.setattr(_env_guard, "mcp_location", lambda: outside)
    monkeypatch.setattr(_env_guard, "has_mcpserver", lambda: False)

    with pytest.raises(SystemExit) as exc:
        _env_guard.verify_local_mcp()
    assert exc.value.code == 2

    err = capsys.readouterr().err
    assert "warning" in err.lower()
    assert "mcp>=2" in err


def test_exits_when_mcpserver_is_missing(monkeypatch, capsys):
    """mcp 1.x has no mcp.server.mcpserver: the second distinct failure, with its own reason."""
    local = Path(sys.prefix) / "lib" / "site-packages" / "mcp" / "__init__.py"

    monkeypatch.setattr(_env_guard, "mcp_location", lambda: local)
    monkeypatch.setattr(_env_guard, "has_mcpserver", lambda: False)

    with pytest.raises(SystemExit) as exc:
        _env_guard.verify_local_mcp()
    assert exc.value.code == 2
    assert "mcp>=2" in capsys.readouterr().err


def test_a_local_mcp_does_not_warn(monkeypatch, capsys):
    """The normal path stays silent: no warning when mcp resolves inside this environment."""
    local = Path(sys.prefix) / "lib" / "site-packages" / "mcp" / "__init__.py"

    monkeypatch.setattr(_env_guard, "mcp_location", lambda: local)
    monkeypatch.setattr(_env_guard, "has_mcpserver", lambda: True)

    _env_guard.verify_local_mcp()

    assert capsys.readouterr().err == ""


def test_tolerates_missing_mcp(monkeypatch):
    """Nothing installed to inspect: stay out of the way and let the real import report itself."""
    monkeypatch.setattr(_env_guard, "mcp_location", lambda: None)
    _env_guard.verify_local_mcp()


def test_has_mcpserver_true_in_this_environment():
    assert _env_guard.has_mcpserver() is True
