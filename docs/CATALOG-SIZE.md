# Catalog size and discovery behaviour

`tools/list` is the largest thing a client loads from this server. This document records
how the payload is measured, what the catalog trim removes, and why `tools/list` is not
paginated.

## How to measure

`scripts/measure_catalog.py` builds the real server (all domains, write mode), serializes
the tools the way the wire does, and prints the four-way split:

```bash
UV_CACHE_DIR=/tmp/dsh-uv-cache uv run --no-sync python scripts/measure_catalog.py
UV_CACHE_DIR=/tmp/dsh-uv-cache uv run --no-sync python scripts/measure_catalog.py --json
```

The total is the raw JSON-RPC `tools/list` response line over STDIO, including the
trailing newline. The serialization is compact, sorted and UTF-8, so two runs on the same
commit produce the same numbers. The server never contacts the appliance to build the
catalog, so the script's fixed dummy settings are enough.

The four components are:

| Component | What it counts |
|---|---|
| Input schemas | the published `inputSchema` bytes |
| Output schemas | the published `outputSchema` bytes |
| Descriptions | the tool `description` bytes |
| Envelope | names, titles, annotations and the JSON-RPC/result wrapper, as the remainder |

## Before and after

Measured on the commit that introduced the trim, against its parent:

| Component | Before | After | Change |
|---|---:|---:|---:|
| Input schemas | 191,630 | 191,630 | 0 |
| Output schemas | 376,788 | 242,915 | **−133,873 (−35.5%)** |
| Descriptions | 38,399 | 38,399 | 0 |
| Envelope | 21,031 | 21,021 | −10 |
| **Total wire line** | **627,848** | **493,965** | **−133,883 (−21.3%)** |

The output schemas were 60.0% of the payload and are now 49.2%. The tool count (112) and
every tool name are unchanged.

## What the trim removes

The SDK derives each tool's `outputSchema` from its return annotation at registration.
`server._trim_published_output_schemas` walks the registry after every domain has
registered and applies `models.common.trim_published_output_schema` to a copy of each
schema. The SDK reads `FuncMetadata.output_schema` live, so the published schema changes
without touching the output model the SDK validates results against.

Two JSON Schema annotations are removed:

- **`description`** — the same model docstring and field descriptions repeat in every tool
  that embeds the model. `ObjectRef` appeared 64 times and `Pages` 33 times; the 429
  `$defs` occurrences carried about 91,000 characters of description. The tool description
  and the property names, types and enums carry the interpretation.
- **`default`** — a response always carries the field (or `null`), so a default is never
  applied to an output.

Two models keep their field annotations because they document a distinction a model needs
to interpret a response, and existing tests pin them:

- **`Pages`** — `total` counts PAGES and `items` counts ITEMS; the two are easy to confuse.
- **`FirewallRuleOutput`** — `position` is the 1-based evaluation position.

Their model-level docstrings are still dropped; only the field descriptions and defaults
stay.

The trim is annotation-only. `required`, `properties`, `type`, `enum`, `const`, `format`,
`$ref`, `anyOf`/`oneOf`, `additionalProperties`, nullability and aliases are untouched.
`tests/test_catalog_size.py` proves this by reconstructing the untrimmed schema from the
output model, applying the trim, and asserting the result equals the published schema; it
also strips the annotations from both and asserts the structural schemas are identical,
and validates a representative instance against every published schema.

## Why `tools/list` is not paginated

The MCP protocol supports pagination: `ListToolsResult` carries `next_cursor` and
`PaginatedRequestParams` carries `cursor`. The pinned SDK's low-level `Server` passes
`PaginatedRequestParams` to the `tools/list` handler, but the `MCPServer` wrapper discards
it:

```python
async def _handle_list_tools(
    self, ctx: ServerRequestContext[LifespanResultT], params: PaginatedRequestParams | None
) -> ListToolsResult:
    return ListToolsResult(tools=await self.list_tools())
```

`MCPServer` exposes no public hook to supply a page. `_handle_list_tools` and
`_lowlevel_server` are private; `MCPServer.list_tools()` returns the whole list and takes
no cursor. The only public interception point is `ServerMiddleware`, which is a generic
request wrapper, not native pagination: using it would mean re-implementing the
`tools/list` result shape outside the SDK and changing what a non-paginating client sees.
That is a workaround, not a supported path, so this server does not fake partial results.

**Upstream-compatible path.** Give `MCPServer` a public pagination hook — for example a
`list_tools_page(cursor: str | None, page_size: int)` method that returns
`ListToolsResult(tools=..., next_cursor=...)`, with `_handle_list_tools` passing
`params.cursor` through. The server would then slice the registry and emit an opaque
cursor. Until that exists, the catalog is one page and the mitigations are the cache hint,
read-only mode, domain selection, the resources and the prompts.

`tests/test_catalog_size.py` pins the single-page behaviour and will fail when the SDK
grows a supported hook, which is the signal to implement pagination.

## Discovery guidance

The catalog is static for the process lifetime, so a client should:

1. Call `tools/list` once per session and cache it; the server advertises a long
   `ttlMs` for `tools/list`.
2. Prefer progressive discovery when the client supports it: load a subset of tools on
   demand instead of every definition up front. The MCP client guidance puts the threshold
   at 1–5% of the context window.
3. Use `SOPHOS_READ_ONLY_MODE=true` to publish 74 tools instead of 112 when the deployment
   only inspects.
4. Use `SOPHOS_TOOL_DOMAINS` to publish only the domains the deployment needs.
5. Read `sophos://conventions` and the analysis prompts instead of loading the whole
   catalog when the client only needs the calling convention or a workflow.
