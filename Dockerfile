# syntax=docker/dockerfile:1

# REST-only runtime image for the Sophos Firewall MCP server.
#
# The server is a local STDIO MCP server: it has no HTTP listener, no health endpoint and
# no TTY. The image therefore contains only the Python runtime, the locked dependencies and
# the package itself. There is no FastEmbed model download, no `.[router]` extra and no
# curl: nothing in the runtime needs them.
#
# Build:  docker build -t sophos-firewall-mcp .
# Run:    docker run --rm -i -e SOPHOS_HOST=... -e SOPHOS_API_KEY_FILE=/run/secrets/key \
#             -v "$PWD/key:/run/secrets/key:ro" sophos-firewall-mcp
#         (`-i` keeps stdin open for the STDIO session; never pass `-t`.)

FROM python:3.13-slim AS runtime

# uv is the only build tool: pyproject.toml + uv.lock are the single dependency source.
COPY --from=ghcr.io/astral-sh/uv:0.13.8 /uv /uvx /bin/

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/app/.venv \
    PATH="/app/.venv/bin:$PATH"

WORKDIR /app

# Dependency layer first: a source change does not invalidate the locked install.
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --locked --no-dev --no-install-project

# Then the package itself.
COPY src/ ./src
RUN uv sync --locked --no-dev

COPY entrypoint.sh /entrypoint.sh
RUN chmod 0755 /entrypoint.sh

# Non-root: the server only needs to read its configuration and write to stdout/stderr.
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin mcp
USER 10001:10001

# STDIO entrypoint: `exec` in the script makes the server PID 1, so SIGTERM/SIGINT reach it
# directly and shutdown is orderly. No TTY is required or expected.
ENTRYPOINT ["/entrypoint.sh"]
