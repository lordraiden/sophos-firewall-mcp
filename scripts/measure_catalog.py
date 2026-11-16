#!/usr/bin/env python3
"""Measure the published ``tools/list`` payload and its four-way split.

The catalog is the largest thing a client loads, so a change to it is measured, not
guessed. This script builds the real server (all domains, write mode), serializes the
tools the way the wire does, and reports:

* **input schemas** -- the published ``inputSchema`` bytes;
* **output schemas** -- the published ``outputSchema`` bytes;
* **descriptions** -- the tool ``description`` bytes;
* **envelope** -- names, titles, annotations and the JSON-RPC/result wrapper, computed as
  the remainder of the total wire line.

The total is the raw JSON-RPC ``tools/list`` response line, including the trailing
newline, which is what a STDIO client receives. The serialization is compact, sorted and
UTF-8, so two runs on the same commit produce the same numbers.

Run it before and after a catalog change:

    UV_CACHE_DIR=/tmp/dsh-uv-cache uv run --no-sync python scripts/measure_catalog.py
    UV_CACHE_DIR=/tmp/dsh-uv-cache uv run --no-sync python scripts/measure_catalog.py --json

The server never contacts the appliance to build the catalog, so the dummy settings below
are enough; they are fixed so the measurement is reproducible.
"""

from __future__ import annotations

import argparse
import asyncio
import json
from typing import Any

from mcp.types import ListToolsResult

from sophos_firewall_mcp.config import Settings
from sophos_firewall_mcp.server import create_server

#: The fixed settings the measurement uses. The catalog is built from the registered
#: tools, not from the appliance, so any valid settings produce the same numbers.
_MEASUREMENT_SETTINGS = Settings(
    host="fw.example.com",
    port=443,
    api_key="sfos_test_key_0123456789abcdef",
    verify_ssl=False,
    timeout=5.0,
    read_only_mode=False,
)


def _compact(value: Any) -> str:
    """Serialize ``value`` the way the wire does: compact, sorted and UTF-8."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


async def measure() -> dict[str, int]:
    """Return the four-way split and the total wire size of the published catalog."""
    server = create_server(_MEASUREMENT_SETTINGS)
    tools = list(await server.list_tools())
    input_bytes = sum(len(_compact(tool.input_schema)) for tool in tools)
    output_bytes = sum(len(_compact(tool.output_schema)) for tool in tools)
    description_bytes = sum(len(tool.description or "") for tool in tools)
    result = ListToolsResult(tools=tools)
    result_json = result.model_dump_json(by_alias=True, exclude_none=True)
    wire = '{"jsonrpc":"2.0","id":1,"result":' + result_json + "}\n"
    total = len(wire.encode("utf-8"))
    return {
        "tools": len(tools),
        "input": input_bytes,
        "output": output_bytes,
        "descriptions": description_bytes,
        "envelope": total - input_bytes - output_bytes - description_bytes,
        "total": total,
        "next_cursor": 1 if result.next_cursor is not None else 0,
    }


def main() -> None:
    """Print the measurement as a table or as JSON."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    args = parser.parse_args()
    metrics = asyncio.run(measure())
    if args.json:
        print(json.dumps(metrics, indent=2, sort_keys=True))
        return
    print(f"tools: {metrics['tools']}")
    print(f"input schemas: {metrics['input']:,} bytes")
    print(f"output schemas: {metrics['output']:,} bytes")
    print(f"descriptions: {metrics['descriptions']:,} bytes")
    print(f"envelope: {metrics['envelope']:,} bytes")
    print(f"total wire line: {metrics['total']:,} bytes")
    print(f"nextCursor: {'present' if metrics['next_cursor'] else 'absent'}")


if __name__ == "__main__":
    main()
