#!/bin/sh
# STDIO entrypoint for the Sophos Firewall MCP server.
#
# `exec` replaces the shell with the server so it becomes PID 1: SIGTERM/SIGINT from the
# container runtime reach it directly and the MCP session shuts down in order. The server
# validates its configuration at startup and writes diagnostics to stderr only; stdout is
# reserved for the MCP protocol.
set -eu

exec sophos-firewall-mcp-server "$@"
