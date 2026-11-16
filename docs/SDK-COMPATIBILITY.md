# Supported MCP SDK range

**Declared dependency:** `mcp==2.3.0` (exact pin, not a range).
**Verified against:** `mcp` 2.3.0 only.
**Enforced by:** `tests/test_sdk_compat.py` and the `mcp-version` matrix in
`.github/workflows/test.yml`.

## Why the dependency is pinned

The server publishes **flat tool arguments** and a **closed, sanitized argument model** for
every one of its tools, and it sets `serverInfo.instructions` after registration. The MCP SDK
does not offer either behaviour publicly, so the package reaches into four attributes that are
not public API:

| Private surface | Used for | Read by |
|---|---|---|
| `MCPServer._tool_manager` | the only route to the registered `Tool` objects | `_tool_manager()` |
| `Tool.fn_metadata.arg_model` | the model a call is validated against | `Tool.run` → `FuncMetadata.validate_arguments` |
| `Tool.parameters` | the published `inputSchema` | `MCPServer.list_tools` |
| `MCPServer._lowlevel_server` | `serverInfo.instructions` after registration (the description is passed to the constructor) | `create_server` (`server.py`) |

A different SDK release may rename, move or remove any of them. The failure would not be a
clean import error: registration would still succeed, but every tool would silently fall
back to the SDK's default `request`-wrapped, open argument model, or validation would
break at call time. That is why the declared range is the one release that was actually
tested, not an open `>=2.3.0,<3`.

## Why a public API is not used

mcp 2.3.0 exposes no public equivalent. Verified against the installed 2.3.0 distribution:

- `MCPServer.add_tool()` returns `None`, so the `Tool` it built is not handed back.
- `MCPServer.list_tools()` returns wire `MCPTool` objects: they carry the JSON schema but
  not the pydantic argument model, and they are read-only.
- `MCPServer` has no public `get_tool()`; `ToolManager` is not exported in
  `mcp.server.mcpserver.__all__`.
- `Tool.from_function()` accepts no argument-model override.
- `MCPServer.__init__(tools=[...])` accepts pre-built `Tool` objects, but building one
  still goes through `Tool.from_function()`, so the argument-model mutation would still be
  required — and the server factory registers tools after construction.

The tool-registry access is confined to one seam in
`src/sophos_firewall_mcp/tools/__init__.py`: `_tool_manager()`, `_registered_tool()`,
`registered_tool_count()`, `registered_tool_names()`, `registered_read_only_tool_names()`
and `_flatten_arguments()`. The server-identity access is confined to `create_server` in
`src/sophos_firewall_mcp/server.py`. `tests/test_sdk_compat.py` parses both modules and
fails if any private attribute is touched outside its seam.

## What the compatibility test proves

`tests/test_sdk_compat.py` fails with a diagnostic naming the attribute that moved when:

- `MCPServer._tool_manager` is missing;
- `Tool.fn_metadata` or `Tool.fn_metadata.arg_model` is missing;
- `Tool.parameters` is missing;
- `MCPServer._lowlevel_server` or its `description` is missing;
- the declared dependency is not the exact verified pin;
- the installed SDK is not the verified release;
- `_env_guard.py` drifts from the pin or the old `mcp>=2` range reappears.

It also proves the behaviour the seam exists for still works end to end:

- flat arguments are published (no `request` wrapper) and the schema is closed
  (`additionalProperties: false`);
- a union request still publishes a root union of closed variants;
- a no-argument tool still rejects unknown arguments;
- unknown arguments are rejected with a sanitized message (no pydantic dump, no model
  name, no documentation URL);
- a real tool invocation still reaches the handler for all three argument-model branches.

## Startup guard

`src/sophos_firewall_mcp/_env_guard.py` runs before the server starts and refuses to start
when `mcp.server.mcpserver` is missing. Its messages name the same exact pin
(`REQUIRED_MCP_REQUIREMENT`), and `tests/test_sdk_compat.py` fails if the guard, the
declared dependency and `SUPPORTED_MCP_SDK_VERSION` disagree, or if the old `mcp>=2` range
reappears anywhere in the guard.

## CI

The `test` job runs a `python-version` × `mcp-version` matrix. The `mcp-version` list is
the verified set and must match `pyproject.toml`; each job installs that release
explicitly (`uv pip install --python .venv/bin/python "mcp==<version>"`) and verifies the
installed version before running the suite, so a lock refresh cannot hide an untested
declared version. The `clean-install` job builds the wheel, installs it into a throwaway
environment and checks that a clean install resolves the pinned SDK and still registers a
non-empty tool surface (the exact count is pinned by `tests/test_tool_surface.py`).

## Widening the range

1. Run `tests/test_sdk_compat.py` against the new release in a throwaway environment.
2. If it passes, add the release to the `mcp-version` matrix in
   `.github/workflows/test.yml`.
3. Update `SUPPORTED_MCP_SDK_VERSION` in `src/sophos_firewall_mcp/tools/__init__.py` and
   the pin in `pyproject.toml`, then run `uv lock`.
4. If it fails, keep the pin and fix the seam first. Do not widen the range to "make the
   install work": that trades a loud, tested failure for a silent one on every tool call.

## Related

- Issue #59 — bound the supported MCP SDK range around private SDK dependencies.
- `src/sophos_firewall_mcp/tools/__init__.py` — the seam note above `_tool_manager()`.
- `tests/test_sdk_compat.py` — the executable compatibility contract.
