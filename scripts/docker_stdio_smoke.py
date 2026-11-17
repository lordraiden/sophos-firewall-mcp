#!/usr/bin/env python3
"""Protocol-synchronised STDIO smoke test for the Docker image.

The previous CI step piped three JSON-RPC lines from ``printf`` into ``docker run -i`` and
closed stdin immediately. The server could exit before flushing the ``tools/list`` response,
so the job was timing-dependent (measured at 1/20 on the base and 3/20 after the MRTR
changes). This driver owns the container's stdin/stdout instead and advances only on protocol
boundaries:

1. send ``initialize`` and wait for the response with ``id: 1``;
2. send ``notifications/initialized`` and ``tools/list``;
3. wait for the response with ``id: 2``, validate the catalog, and only then close stdin.

Every wait has an explicit timeout. On any failure the container is terminated and reaped,
its stderr is captured, and the diagnostic is printed to stderr. stdout carries protocol
frames only; the driver never writes anything else there.

The synchronisation logic is deliberately independent of Docker: :class:`StdioDriver` takes
any process-like object with ``stdin``/``stdout``/``stderr`` pipes and ``poll``/``terminate``/
``kill``/``wait`` methods, so ``tests/test_docker_stdio_smoke.py`` can drive it with an
in-process fake that emits frames on demand, stalls, or dies.

Usage::

    python3 scripts/docker_stdio_smoke.py --image sophos-firewall-mcp:pr
    python3 scripts/docker_stdio_smoke.py --image sophos-firewall-mcp:pr --repeat 20
"""

from __future__ import annotations

import argparse
import json
import queue
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from typing import Any, Protocol

#: The protocol revision the server advertises; the driver validates the negotiated value.
PROTOCOL_VERSION = "2026-07-28"

#: The default tool surface of a writable server (read-only mode publishes 74).
DEFAULT_EXPECTED_TOOLS = 112

#: Default seconds to wait for one protocol response.
DEFAULT_TIMEOUT = 30.0

#: Default seconds to wait for the container to exit after stdin is closed or it is terminated.
DEFAULT_REAP_TIMEOUT = 10.0

#: Seconds to wait for the stderr collector to drain after the container exits.
_STDERR_JOIN_TIMEOUT = 1.0


class SmokeFailure(RuntimeError):
    """A protocol-level failure, with the container's stderr attached when available."""

    def __init__(self, message: str, *, stderr: str = "") -> None:
        super().__init__(message)
        self.message = message
        self.stderr = stderr

    def __str__(self) -> str:
        if self.stderr:
            return f"{self.message}\n--- container stderr ---\n{self.stderr}"
        return self.message


@dataclass(frozen=True)
class SmokeResult:
    """What a successful exchange proved."""

    protocol_version: str
    tools: list[dict[str, Any]]


class Process(Protocol):
    """The subset of ``subprocess.Popen`` the driver needs; a fake can implement it."""

    stdin: Any
    stdout: Any
    stderr: Any

    def poll(self) -> int | None: ...

    def terminate(self) -> None: ...

    def kill(self) -> None: ...

    def wait(self, timeout: float | None = None) -> int: ...


class _LineCollector(threading.Thread):
    """Read stdout lines on a thread so the driver can wait with a timeout."""

    def __init__(self, stream: Any) -> None:
        super().__init__(name="stdio-smoke-stdout", daemon=True)
        self._stream = stream
        self._queue: queue.Queue[bytes | None] = queue.Queue()

    def run(self) -> None:
        try:
            while True:
                line = self._stream.readline()
                if not line:
                    break
                self._queue.put(line)
        except Exception:  # pragma: no cover - a closed pipe is an EOF, not a crash
            pass
        finally:
            self._queue.put(None)

    def get(self, timeout: float) -> bytes | None:
        """Return the next line, ``None`` on EOF, or raise :class:`queue.Empty` on timeout."""
        return self._queue.get(timeout=timeout)


class _StderrCollector(threading.Thread):
    """Drain stderr on a thread so a stalled container cannot block the diagnostic."""

    def __init__(self, stream: Any) -> None:
        super().__init__(name="stdio-smoke-stderr", daemon=True)
        self._stream = stream
        self._lines: list[str] = []
        self._lock = threading.Lock()

    def run(self) -> None:
        try:
            for line in self._stream:
                with self._lock:
                    self._lines.append(line.decode("utf-8", "replace").rstrip("\n"))
        except Exception:  # pragma: no cover - a closed pipe is an EOF, not a crash
            pass

    def text(self) -> str:
        with self._lock:
            return "\n".join(self._lines)


class StdioDriver:
    """Drive one MCP STDIO exchange over a process-like object.

    The driver is single-use: it starts its reader threads in :meth:`run` and closes stdin
    when the exchange finishes. It never sleeps to synchronise; it waits for the matching
    response id, with a timeout.
    """

    def __init__(
        self,
        process: Process,
        *,
        timeout: float = DEFAULT_TIMEOUT,
        reap_timeout: float = DEFAULT_REAP_TIMEOUT,
        expected_tools: int = DEFAULT_EXPECTED_TOOLS,
    ) -> None:
        if process.stdin is None or process.stdout is None or process.stderr is None:
            raise ValueError("the process must be created with stdin, stdout and stderr pipes")
        self._process = process
        self._stdin = process.stdin
        self._timeout = timeout
        self._reap_timeout = reap_timeout
        self._expected_tools = expected_tools
        self._stdout = _LineCollector(process.stdout)
        self._stderr = _StderrCollector(process.stderr)

    def run(self) -> SmokeResult:
        """Run the exchange and return the validated result, or raise :class:`SmokeFailure`."""
        self._stdout.start()
        self._stderr.start()
        try:
            self._send(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": PROTOCOL_VERSION,
                        "capabilities": {},
                        "clientInfo": {"name": "docker-stdio-smoke", "version": "1"},
                    },
                }
            )
            initialize = self._await_response(1)
            protocol_version = self._validate_initialize(initialize)

            self._send({"jsonrpc": "2.0", "method": "notifications/initialized"})
            self._send({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
            listing = self._await_response(2)
            tools = self._validate_tools(listing)

            return SmokeResult(protocol_version=protocol_version, tools=tools)
        except SmokeFailure as exc:
            self._terminate_and_reap()
            exc.stderr = self._stderr_text()
            raise
        finally:
            self._close_stdin()
            self._reap()

    # -- Protocol ------------------------------------------------------------

    def _send(self, message: dict[str, Any]) -> None:
        line = json.dumps(message, separators=(",", ":")) + "\n"
        self._stdin.write(line.encode("utf-8"))
        self._stdin.flush()

    def _await_response(self, request_id: int) -> dict[str, Any]:
        deadline = time.monotonic() + self._timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise SmokeFailure(
                    f"timed out after {self._timeout:.1f}s waiting for the response to "
                    f"request id {request_id}"
                )
            try:
                line = self._stdout.get(remaining)
            except queue.Empty:
                raise SmokeFailure(
                    f"timed out after {self._timeout:.1f}s waiting for the response to "
                    f"request id {request_id}"
                ) from None
            if line is None:
                raise SmokeFailure(
                    f"stdout closed before the response to request id {request_id} arrived"
                )
            message = self._parse(line)
            if message.get("id") == request_id:
                return message
            if "id" in message:
                raise SmokeFailure(
                    f"unexpected response id {message['id']!r} while waiting for "
                    f"request id {request_id}"
                )
            # A notification (no id) is not the response; keep waiting for the matching id.

    @staticmethod
    def _parse(line: bytes) -> dict[str, Any]:
        text = line.decode("utf-8", "replace").strip()
        if not text:
            raise SmokeFailure("received an empty line on stdout")
        try:
            message = json.loads(text)
        except json.JSONDecodeError as exc:
            raise SmokeFailure(
                f"malformed JSON-RPC frame on stdout: {text[:200]!r} ({exc})"
            ) from exc
        if not isinstance(message, dict):
            raise SmokeFailure(f"stdout frame is not a JSON object: {text[:200]!r}")
        if message.get("jsonrpc") != "2.0":
            raise SmokeFailure(f"stdout frame is not JSON-RPC 2.0: {text[:200]!r}")
        return message

    @staticmethod
    def _validate_initialize(message: dict[str, Any]) -> str:
        if "error" in message:
            raise SmokeFailure(f"initialize returned an error: {message['error']!r}")
        result = message.get("result")
        if not isinstance(result, dict):
            raise SmokeFailure("initialize response has no result object")
        version = result.get("protocolVersion")
        if not isinstance(version, str) or not version:
            raise SmokeFailure("initialize response has no protocolVersion")
        return version

    def _validate_tools(self, message: dict[str, Any]) -> list[dict[str, Any]]:
        if "error" in message:
            raise SmokeFailure(f"tools/list returned an error: {message['error']!r}")
        result = message.get("result")
        if not isinstance(result, dict):
            raise SmokeFailure("tools/list response has no result object")
        tools = result.get("tools")
        if not isinstance(tools, list):
            raise SmokeFailure("tools/list response has no tools list")
        if len(tools) != self._expected_tools:
            raise SmokeFailure(f"expected {self._expected_tools} tools, got {len(tools)}")
        for tool in tools:
            if not isinstance(tool, dict) or not isinstance(tool.get("name"), str):
                raise SmokeFailure("tools/list returned a tool without a name")
            if not tool["name"]:
                raise SmokeFailure("tools/list returned a tool with an empty name")
        return tools

    # -- Process lifecycle ---------------------------------------------------

    def _close_stdin(self) -> None:
        try:
            self._stdin.close()
        except Exception:  # pragma: no cover - closing an already-closed pipe is harmless
            pass

    def _reap(self) -> None:
        if self._process.poll() is not None:
            return
        try:
            self._process.wait(timeout=self._reap_timeout)
        except subprocess.TimeoutExpired:
            self._terminate_and_reap()

    def _terminate_and_reap(self) -> None:
        if self._process.poll() is not None:
            return
        self._process.terminate()
        try:
            self._process.wait(timeout=self._reap_timeout)
        except subprocess.TimeoutExpired:
            self._process.kill()
            self._process.wait(timeout=self._reap_timeout)

    def _stderr_text(self) -> str:
        self._stderr.join(timeout=_STDERR_JOIN_TIMEOUT)
        return self._stderr.text()


def build_command(args: argparse.Namespace) -> list[str]:
    """Build the container command: STDIO, no TTY, no network, no writable host state."""
    return [
        args.command,
        "run",
        "--rm",
        "-i",
        "--network",
        "none",
        "-e",
        f"SOPHOS_HOST={args.host}",
        "-e",
        f"SOPHOS_PORT={args.port}",
        "-e",
        f"SOPHOS_API_KEY={args.api_key}",
        args.image,
    ]


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default="sophos-firewall-mcp:pr")
    parser.add_argument("--command", default="docker", help="Container runtime (docker or podman).")
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help="Seconds to wait for one protocol response.",
    )
    parser.add_argument(
        "--reap-timeout",
        type=float,
        default=DEFAULT_REAP_TIMEOUT,
        help="Seconds to wait for the container to exit.",
    )
    parser.add_argument(
        "--expected-tools",
        type=int,
        default=DEFAULT_EXPECTED_TOOLS,
        help="Expected number of tools in the default surface.",
    )
    parser.add_argument(
        "--repeat",
        type=int,
        default=1,
        help="Run the exchange this many times (the CI repeatability check uses 20).",
    )
    parser.add_argument("--host", default="192.0.2.10")
    parser.add_argument("--port", default="4444")
    parser.add_argument("--api-key", default="ci-not-a-real-key")
    args = parser.parse_args(argv)
    if args.repeat < 1:
        parser.error("--repeat must be at least 1")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    for attempt in range(1, args.repeat + 1):
        try:
            process = subprocess.Popen(
                build_command(args),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except OSError as exc:
            print(
                f"attempt {attempt}/{args.repeat} failed to start {args.command!r}: {exc}",
                file=sys.stderr,
            )
            return 1
        driver = StdioDriver(
            process,
            timeout=args.timeout,
            reap_timeout=args.reap_timeout,
            expected_tools=args.expected_tools,
        )
        try:
            result = driver.run()
        except SmokeFailure as exc:
            print(f"attempt {attempt}/{args.repeat} failed: {exc}", file=sys.stderr)
            return 1
        print(
            f"attempt {attempt}/{args.repeat}: protocol {result.protocol_version}, "
            f"{len(result.tools)} tools"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
