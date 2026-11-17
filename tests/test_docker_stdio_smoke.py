"""Tests for the protocol-synchronised Docker STDIO smoke driver.

Docker is not installed on the development host, so the driver's synchronisation logic is
exercised against an in-process fake process that emits frames on demand, stalls, or dies.
The fake implements the same small process interface as ``subprocess.Popen`` (``stdin``,
``stdout``, ``stderr``, ``poll``, ``terminate``, ``kill``, ``wait``), so these tests prove the
driver's behaviour without a container:

* the happy path sends each message only after the previous response arrived;
* a missing response times out with a useful diagnostic;
* a malformed frame fails with the frame in the diagnostic;
* a stalled process is terminated and reaped;
* a process that dies before responding fails with its stderr;
* an unexpected response id and a wrong tool count fail;
* the command keeps ``-i``, no ``-t`` and ``--network none``.
"""

from __future__ import annotations

import importlib.util
import json
import queue
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
DRIVER_PATH = ROOT / "scripts" / "docker_stdio_smoke.py"


def _load_driver() -> Any:
    spec = importlib.util.spec_from_file_location("docker_stdio_smoke", DRIVER_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


driver = _load_driver()


# -- Fake process ------------------------------------------------------------


class FakeStdout:
    """A blocking line source the test can feed on demand and close to signal EOF."""

    def __init__(self) -> None:
        self._queue: queue.Queue[bytes | None] = queue.Queue()

    def feed(self, line: bytes) -> None:
        self._queue.put(line)

    def close(self) -> None:
        self._queue.put(None)

    def readline(self) -> bytes:
        item = self._queue.get()
        return b"" if item is None else item


class FakeStderr:
    """A finite stderr stream; the collector drains it and finishes."""

    def __init__(self, text: str = "") -> None:
        self._lines = [line.encode("utf-8") + b"\n" for line in text.splitlines()]

    def __iter__(self) -> Any:
        return iter(self._lines)


class FakeStdin:
    """A stdin that records writes and lets the fake process answer them synchronously."""

    def __init__(self, process: "FakeProcess") -> None:
        self._process = process
        self.writes: list[bytes] = []
        self.closed = False

    def write(self, data: bytes) -> int:
        self.writes.append(data)
        self._process.on_write(data)
        return len(data)

    def flush(self) -> None:
        pass

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        self._process.timeline.append("close:stdin")
        if self._process.returncode is None:
            self._process.returncode = 0


class FakeProcess:
    """An in-process stand-in for ``subprocess.Popen``.

    ``mode`` selects the behaviour: ``happy`` answers both requests, ``stall`` never answers,
    ``die`` closes stdout on the first write, ``malformed`` emits a non-JSON frame,
    ``unexpected-id`` answers ``initialize`` with the wrong id, and ``notification-first``
    emits a notification before the initialize response.
    """

    def __init__(
        self,
        *,
        mode: str = "happy",
        stderr: str = "",
        tool_count: int = 112,
        unkillable: bool = False,
    ) -> None:
        self.stdout = FakeStdout()
        self.stderr = FakeStderr(stderr)
        self.stdin = FakeStdin(self)
        self.returncode: int | None = None
        self.terminated = False
        self.killed = False
        self.timeline: list[str] = []
        self._mode = mode
        self._tool_count = tool_count
        self._unkillable = unkillable
        self._initialize_responded = False

    def on_write(self, data: bytes) -> None:
        for line in data.decode("utf-8").splitlines():
            if not line.strip():
                continue
            message = json.loads(line)
            method = message.get("method")
            self.timeline.append(f"write:{method}")
            if self._mode == "die":
                self.stdout.close()
                self.returncode = 1
                return
            if self._mode == "stall":
                return
            if method == "initialize":
                self._answer_initialize()
                self._initialize_responded = True
                self.timeline.append("response:1")
            elif method == "tools/list":
                if not self._initialize_responded:
                    self.timeline.append("ordering-violation")
                tools = [{"name": f"tool_{index}"} for index in range(self._tool_count)]
                self.stdout.feed(
                    self._frame({"jsonrpc": "2.0", "id": 2, "result": {"tools": tools}})
                )
                self.timeline.append("response:2")

    def _answer_initialize(self) -> None:
        if self._mode == "malformed":
            self.stdout.feed(b"{not json}\n")
            return
        if self._mode == "unexpected-id":
            self.stdout.feed(self._frame({"jsonrpc": "2.0", "id": 99, "result": {}}))
            return
        if self._mode == "unsupported-version":
            self.stdout.feed(
                self._frame(
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "result": {"protocolVersion": "1999-01-01"},
                    }
                )
            )
            return
        if self._mode == "notification-first":
            self.stdout.feed(
                self._frame(
                    {
                        "jsonrpc": "2.0",
                        "method": "notifications/message",
                        "params": {"level": "info", "data": "starting"},
                    }
                )
            )
        self.stdout.feed(
            self._frame(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {
                        # The real server negotiates the latest handshake revision it
                        # supports (2025-11-25 with mcp 2.3.0); 2026-07-28 is a per-request
                        # envelope, never an initialize response value.
                        "protocolVersion": "2025-11-25",
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "sophos-firewall-mcp", "version": "0.0.0"},
                    },
                }
            )
        )

    @staticmethod
    def _frame(message: dict[str, Any]) -> bytes:
        return json.dumps(message).encode("utf-8") + b"\n"

    def poll(self) -> int | None:
        return self.returncode

    def terminate(self) -> None:
        self.terminated = True
        self.timeline.append("terminate")
        if self.returncode is None:
            self.returncode = -15
        self.stdout.close()

    def kill(self) -> None:
        self.killed = True
        self.timeline.append("kill")
        if self.returncode is None:
            self.returncode = -9
        self.stdout.close()

    def wait(self, timeout: float | None = None) -> int:
        if self._unkillable or self.returncode is None:
            raise subprocess.TimeoutExpired(cmd="fake", timeout=timeout or 0)
        return self.returncode


def make_driver(process: FakeProcess, **overrides: Any) -> Any:
    options: dict[str, Any] = {"timeout": 0.2, "reap_timeout": 0.2}
    options.update(overrides)
    return driver.StdioDriver(process, **options)


# -- Happy path --------------------------------------------------------------


def test_happy_path_waits_for_each_response_before_sending_the_next_message() -> None:
    process = FakeProcess()

    result = make_driver(process).run()

    assert result.protocol_version == "2025-11-25"
    assert len(result.tools) == 112
    assert process.stdin.closed is True
    assert "ordering-violation" not in process.timeline
    # The initialize response must arrive before tools/list is sent, and the tools/list
    # response must arrive before stdin is closed.
    assert process.timeline.index("response:1") < process.timeline.index("write:tools/list")
    assert process.timeline.index("response:2") < process.timeline.index("close:stdin")


def test_a_notification_before_the_response_is_ignored() -> None:
    process = FakeProcess(mode="notification-first")

    result = make_driver(process).run()

    assert result.protocol_version == "2025-11-25"
    assert len(result.tools) == 112


# -- Failure modes -----------------------------------------------------------


def test_a_missing_response_times_out_with_a_useful_diagnostic() -> None:
    process = FakeProcess(mode="stall", stderr="server is stuck")

    with pytest.raises(driver.SmokeFailure) as excinfo:
        make_driver(process).run()

    message = str(excinfo.value)
    assert "timed out" in message
    assert "request id 1" in message
    assert "server is stuck" in message


def test_a_malformed_frame_fails_with_the_frame_in_the_diagnostic() -> None:
    process = FakeProcess(mode="malformed")

    with pytest.raises(driver.SmokeFailure) as excinfo:
        make_driver(process).run()

    message = str(excinfo.value)
    assert "malformed JSON-RPC frame" in message
    assert "{not json}" in message


def test_a_stalled_process_is_terminated_and_reaped() -> None:
    process = FakeProcess(mode="stall")

    with pytest.raises(driver.SmokeFailure):
        make_driver(process).run()

    assert process.terminated is True
    assert process.killed is False
    assert process.poll() is not None
    assert "terminate" in process.timeline


def test_an_unkillable_process_does_not_replace_the_protocol_diagnostic() -> None:
    """A reaping timeout must not mask the protocol failure that triggered the cleanup."""
    process = FakeProcess(mode="stall", unkillable=True)

    with pytest.raises(driver.SmokeFailure) as excinfo:
        make_driver(process).run()

    message = str(excinfo.value)
    assert "timed out" in message
    assert "request id 1" in message
    assert process.terminated is True
    assert process.killed is True


def test_a_process_that_dies_before_responding_fails_with_its_stderr() -> None:
    process = FakeProcess(mode="die", stderr="container exited 1")

    with pytest.raises(driver.SmokeFailure) as excinfo:
        make_driver(process).run()

    message = str(excinfo.value)
    assert "stdout closed" in message
    assert "container exited 1" in message


def test_an_unexpected_response_id_fails() -> None:
    process = FakeProcess(mode="unexpected-id")

    with pytest.raises(driver.SmokeFailure) as excinfo:
        make_driver(process).run()

    assert "unexpected response id 99" in str(excinfo.value)


def test_an_unsupported_negotiated_version_fails() -> None:
    process = FakeProcess(mode="unsupported-version")

    with pytest.raises(driver.SmokeFailure) as excinfo:
        make_driver(process).run()

    message = str(excinfo.value)
    assert "unsupported handshake revision" in message
    assert "1999-01-01" in message


def test_the_wrong_tool_count_fails() -> None:
    process = FakeProcess(tool_count=1)

    with pytest.raises(driver.SmokeFailure) as excinfo:
        make_driver(process).run()

    assert "expected 112 tools, got 1" in str(excinfo.value)


# -- Command construction ----------------------------------------------------


def test_build_command_keeps_no_tty_and_no_network() -> None:
    args = driver.parse_args(["--image", "example:test"])

    command = driver.build_command(args)

    assert "-i" in command
    assert "-t" not in command
    assert command[command.index("--network") + 1] == "none"
    assert "example:test" in command
    assert "SOPHOS_HOST=192.0.2.10" in command


def test_repeat_must_be_positive() -> None:
    with pytest.raises(SystemExit):
        driver.parse_args(["--repeat", "0"])
