"""Reproducible STDIO smoke test for the Sophos Firewall MCP server.

The live evidence in ``docs/live-evidence/`` was produced with ad-hoc drivers; this script
makes the method reproducible. It launches the server over STDIO with the official MCP SDK
``Client``, prints the negotiated protocol and the tool surface, and optionally calls one
tool.

Examples::

    # List the surface (read-only mode is the safest default)
    SOPHOS_HOST=10.10.10.1 SOPHOS_PORT=443 SOPHOS_API_KEY_FILE=/run/secrets/key \
    SOPHOS_VERIFY_SSL=false SOPHOS_READ_ONLY_MODE=true \
    python scripts/mcp_smoke_test.py --list

    # Call a read-only tool
    ... python scripts/mcp_smoke_test.py --call network_status_dns_protection

    # Call a tool with arguments (JSON)
    ... python scripts/mcp_smoke_test.py --call firewall_rule_list_ipv4 \
        --args '{"page": 1, "page_size": 5}'

The server command defaults to ``python -m sophos_firewall_mcp.server``; pass
``--command`` to use an installed binary or a container wrapper. The script never writes to
the appliance unless you explicitly call a mutation tool, and it prints no secrets.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys

from mcp import Client, StdioServerParameters


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--command",
        default=sys.executable,
        help="Server executable (default: the current Python interpreter).",
    )
    parser.add_argument(
        "--server-arg",
        action="append",
        default=None,
        help="Argument for the server command; repeatable (default: -m sophos_firewall_mcp.server).",
    )
    parser.add_argument("--list", action="store_true", help="Print the tool surface.")
    parser.add_argument("--call", metavar="TOOL", help="Call one tool by name.")
    parser.add_argument(
        "--args",
        default="{}",
        help="JSON object with the tool arguments (default: {}).",
    )
    return parser.parse_args(argv)


async def run(args: argparse.Namespace) -> int:
    server_args = args.server_arg or ["-m", "sophos_firewall_mcp.server"]
    # The SDK does not inherit the parent environment by default; pass it so the
    # SOPHOS_* configuration reaches the server.
    params = StdioServerParameters(command=args.command, args=server_args, env=dict(os.environ))

    async with Client(params) as client:
        print(f"protocol: {client.protocol_version}")
        listed = await client.list_tools()
        tools = listed[0] if isinstance(listed, tuple) else listed.tools
        names = sorted(tool.name for tool in tools)
        mutations = sum(
            1
            for tool in tools
            if tool.annotations is not None and tool.annotations.read_only_hint is False
        )
        print(f"tools: {len(names)} (mutations: {mutations})")

        if args.list:
            for name in names:
                print(f"  {name}")

        if args.call:
            arguments = json.loads(args.args)
            result = await client.call_tool(args.call, arguments)
            print(f"call {args.call}: is_error={result.is_error}")
            for item in result.content:
                text = getattr(item, "text", None)
                if text is not None:
                    print(text)
    return 0


def main(argv: list[str] | None = None) -> int:
    return asyncio.run(run(parse_args(argv)))


if __name__ == "__main__":
    raise SystemExit(main())
