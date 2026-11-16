"""Compatibility contract for the pinned MCP SDK private seam (issue #59).

``sophos_firewall_mcp.tools`` closes every tool's argument model and publishes flat
arguments through three attributes of the MCP SDK that are not public API:

* ``MCPServer._tool_manager`` -- the only route to the registered ``Tool`` objects;
* ``Tool.fn_metadata.arg_model`` -- the model ``Tool.run`` validates a call against;
* ``Tool.parameters`` -- the schema ``MCPServer.list_tools`` publishes.

mcp 2.3.0 exposes no public equivalent: ``MCPServer.add_tool`` returns ``None``,
``MCPServer.list_tools`` returns wire ``MCPTool`` objects, ``MCPServer`` has no
``get_tool``, and ``Tool.from_function`` accepts no argument-model override. The seam is
therefore necessary, and it is confined to one accessor in the tools module.

This module is the executable statement of which SDK release that seam was verified
against. It fails with a diagnostic naming the attribute that moved when the SDK changes,
and it proves the behaviour the seam exists for -- flat arguments, closed input schemas,
sanitized validation and a real tool invocation -- still works. The declared dependency is
an exact pin (``mcp==2.3.0``) for the same reason: a range would let a package installation
select a release this module never ran against.
"""

from __future__ import annotations

import ast
import importlib.metadata
import re
import tomllib
from pathlib import Path
from typing import Annotated, Literal, Union

import pytest
from mcp import Client
from mcp.server.mcpserver import Context, MCPServer
from pydantic import BaseModel, ConfigDict, Field

from sophos_firewall_mcp import _env_guard
from sophos_firewall_mcp.config import Settings
from sophos_firewall_mcp.context import AppContext
from sophos_firewall_mcp.server import create_server
from sophos_firewall_mcp.tools import (
    SUPPORTED_MCP_SDK_VERSION,
    ToolKind,
    register_tool,
)

ROOT = Path(__file__).resolve().parents[1]
PYPROJECT_PATH = ROOT / "pyproject.toml"
TOOLS_MODULE_PATH = ROOT / "src" / "sophos_firewall_mcp" / "tools" / "__init__.py"
ENV_GUARD_PATH = ROOT / "src" / "sophos_firewall_mcp" / "_env_guard.py"

#: The private SDK attributes the seam depends on. A move in any of them breaks argument
#: handling for every tool, so each is named in a diagnostic rather than a bare assert.
PRIVATE_SDK_ATTRIBUTES = ("_tool_manager", "fn_metadata", "parameters")

#: The functions allowed to touch the private surface: the accessor, its two callers and
#: the one function that mutates the registered tool.
SEAM_FUNCTIONS = frozenset(
    {"_tool_manager", "_registered_tool", "registered_tool_count", "_flatten_arguments"}
)

FLAT_TOOL = "sophos_sdk_compat_echo"
UNION_TOOL = "sophos_sdk_compat_union"
NO_ARGUMENT_TOOL = "sophos_sdk_compat_no_arguments"


# -- Synthetic domain (module level so the SDK can resolve the annotations) ------------


class EchoInput(BaseModel):
    """Closed flat input contract: unknown fields are rejected."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=64)


class EchoOutput(BaseModel):
    """Object-rooted structured output."""

    name: str


class Ipv4EchoInput(BaseModel):
    """One variant of the discriminated union request."""

    model_config = ConfigDict(extra="forbid")

    ip_family: Literal["ipv4"]
    address: str


class Ipv6EchoInput(BaseModel):
    """The other variant of the discriminated union request."""

    model_config = ConfigDict(extra="forbid")

    ip_family: Literal["ipv6"]
    address: str


EchoRequest = Annotated[Union[Ipv4EchoInput, Ipv6EchoInput], Field(discriminator="ip_family")]


class AddressOutput(BaseModel):
    """Object-rooted output for the union tool."""

    ip_family: str
    address: str


class EmptyOutput(BaseModel):
    """Object-rooted output for the no-argument tool."""

    value: str


def register_compat_tools(server: MCPServer[AppContext], *, read_only: bool) -> None:
    """Register one tool per argument-model branch the private seam handles."""

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.READ,
        name=FLAT_TOOL,
        title="SDK compatibility echo",
        description=(
            "Read-only synthetic tool used by the SDK compatibility tests. It echoes the "
            "name and never contacts the appliance."
        ),
    )
    async def echo(request: EchoInput, ctx: Context[AppContext]) -> EchoOutput:
        return EchoOutput(name=request.name)

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.READ,
        name=UNION_TOOL,
        title="SDK compatibility union echo",
        description=(
            "Read-only synthetic tool used by the SDK compatibility tests. It echoes the "
            "selected union variant and never contacts the appliance."
        ),
    )
    async def union_echo(request: EchoRequest) -> AddressOutput:
        return AddressOutput(ip_family=request.ip_family, address=request.address)

    @register_tool(
        server,
        read_only=read_only,
        kind=ToolKind.READ,
        name=NO_ARGUMENT_TOOL,
        title="SDK compatibility no-argument tool",
        description=(
            "Read-only synthetic tool used by the SDK compatibility tests. It takes no "
            "arguments and never contacts the appliance."
        ),
    )
    async def no_arguments() -> EmptyOutput:
        return EmptyOutput(value="ok")


def make_settings() -> Settings:
    """Build valid settings without touching the process environment."""
    return Settings(
        host="192.0.2.10",
        port=4444,
        api_key="test-api-key",
        verify_ssl=False,
        timeout=5.0,
        read_only_mode=False,
    )


def make_server() -> MCPServer[AppContext]:
    """Build a server whose only tools are the synthetic compatibility tools."""
    return create_server(make_settings(), domains=[register_compat_tools])


# -- Declared and installed SDK version ------------------------------------------------


def _declared_mcp_requirement() -> str:
    """Return the ``mcp`` requirement string declared in ``pyproject.toml``."""
    data = tomllib.loads(PYPROJECT_PATH.read_text(encoding="utf-8"))
    requirements = [
        dependency
        for dependency in data["project"]["dependencies"]
        if re.match(r"^mcp(?:\s|\[|[<>=!~]|$)", dependency)
    ]
    assert (
        len(requirements) == 1
    ), f"pyproject.toml must declare exactly one mcp dependency; found {requirements!r}"
    return requirements[0]


def _declared_mcp_specifier() -> str:
    """Return the version specifier of the declared ``mcp`` requirement."""
    return _declared_mcp_requirement()[len("mcp") :].strip()


def test_the_declared_mcp_dependency_is_an_exact_pin() -> None:
    """A range would let an installation select an SDK release the seam never ran on."""
    specifier = _declared_mcp_specifier()
    expected = f"=={SUPPORTED_MCP_SDK_VERSION}"

    assert specifier == expected, (
        f"pyproject.toml must pin mcp to the one release the private SDK seam was "
        f"verified against ({expected}); found 'mcp{specifier}'. An open range lets a "
        f"package installation select an SDK release tests/test_sdk_compat.py never ran "
        f"against. Widen the pin only after this module passes against the new release "
        f"and that release is added to the CI matrix."
    )


def test_the_installed_mcp_sdk_is_the_verified_release() -> None:
    """The environment running the tests must be the environment the seam was verified on."""
    installed = importlib.metadata.version("mcp")

    assert installed == SUPPORTED_MCP_SDK_VERSION, (
        f"the installed MCP SDK is {installed}, but the private seam in "
        f"sophos_firewall_mcp.tools was verified against {SUPPORTED_MCP_SDK_VERSION}. "
        f"Install mcp=={SUPPORTED_MCP_SDK_VERSION} (uv sync --locked), or re-verify the "
        f"seam and update SUPPORTED_MCP_SDK_VERSION, pyproject.toml and the CI matrix."
    )


def test_the_environment_guard_declares_the_same_pin() -> None:
    """The startup guard must not advertise a range the package does not install."""
    assert _env_guard.REQUIRED_MCP_VERSION == SUPPORTED_MCP_SDK_VERSION, (
        f"the startup guard requires mcp {_env_guard.REQUIRED_MCP_VERSION}, but the "
        f"private seam was verified against {SUPPORTED_MCP_SDK_VERSION}; align "
        f"_env_guard.REQUIRED_MCP_VERSION with pyproject.toml."
    )
    assert _env_guard.REQUIRED_MCP_REQUIREMENT == f"mcp=={SUPPORTED_MCP_SDK_VERSION}", (
        f"the startup guard advertises {_env_guard.REQUIRED_MCP_REQUIREMENT!r}, but the "
        f"package pins mcp=={SUPPORTED_MCP_SDK_VERSION}."
    )
    assert "{required}" in _env_guard._MESSAGE, (
        "the guard's failure message no longer interpolates the required SDK version, so "
        "it can drift from pyproject.toml again."
    )
    source = ENV_GUARD_PATH.read_text(encoding="utf-8")
    assert "mcp>=2" not in source, (
        "the startup guard still advertises the old mcp>=2 range; align every message and "
        "docstring with the exact pin."
    )


# -- Private SDK structure -------------------------------------------------------------


def test_the_private_seam_attributes_still_exist() -> None:
    """Fail with the moved attribute named, not with an AttributeError deep in a call."""
    server = make_server()
    installed = importlib.metadata.version("mcp")

    manager = getattr(server, "_tool_manager", None)
    assert manager is not None, (
        f"MCPServer._tool_manager is missing in mcp {installed}: the private SDK seam "
        f"moved (verified against {SUPPORTED_MCP_SDK_VERSION}). Every tool's flat "
        f"arguments and closed argument model depend on it; update "
        f"sophos_firewall_mcp.tools._tool_manager and re-verify."
    )

    tool = manager.get_tool(FLAT_TOOL)
    assert tool is not None, (
        f"the SDK tool manager no longer returns the registered tool {FLAT_TOOL!r} in "
        f"mcp {installed}; the private seam moved."
    )

    fn_metadata = getattr(tool, "fn_metadata", None)
    assert fn_metadata is not None, (
        f"Tool.fn_metadata is missing in mcp {installed}: the private SDK seam moved "
        f"(verified against {SUPPORTED_MCP_SDK_VERSION}). Tool.run validates every call "
        f"through fn_metadata.arg_model."
    )
    assert hasattr(fn_metadata, "arg_model"), (
        f"Tool.fn_metadata.arg_model is missing in mcp {installed}: the private SDK seam "
        f"moved (verified against {SUPPORTED_MCP_SDK_VERSION}). The flat argument model "
        f"is installed there."
    )
    assert hasattr(tool, "parameters"), (
        f"Tool.parameters is missing in mcp {installed}: the private SDK seam moved "
        f"(verified against {SUPPORTED_MCP_SDK_VERSION}). MCPServer.list_tools publishes "
        f"it as the input schema."
    )


def test_the_private_sdk_surface_is_confined_to_the_seam() -> None:
    """The private attributes must stay inside the seam, not spread into domain modules."""
    tree = ast.parse(TOOLS_MODULE_PATH.read_text(encoding="utf-8"))
    defined = {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    missing = SEAM_FUNCTIONS - defined
    assert not missing, (
        f"the seam functions {sorted(missing)} are missing from "
        f"{TOOLS_MODULE_PATH.relative_to(ROOT)}; the private SDK seam was renamed or "
        f"removed."
    )

    offenders: list[str] = []
    for function in ast.walk(tree):
        if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if function.name in SEAM_FUNCTIONS:
            continue
        for node in ast.walk(function):
            if isinstance(node, ast.Attribute) and node.attr in PRIVATE_SDK_ATTRIBUTES:
                offenders.append(f"{function.name}:{node.lineno} .{node.attr}")
            elif isinstance(node, ast.Constant) and node.value in PRIVATE_SDK_ATTRIBUTES:
                offenders.append(f"{function.name}:{node.lineno} {node.value!r}")

    assert not offenders, (
        f"the private SDK surface {sorted(PRIVATE_SDK_ATTRIBUTES)} must stay inside the "
        f"seam functions {sorted(SEAM_FUNCTIONS)}; found {offenders}. A private attribute "
        f"outside the seam turns one SDK move into a hunt instead of a one-line fix."
    )


# -- Behaviour the seam exists for -----------------------------------------------------


async def test_flat_arguments_are_published_and_closed() -> None:
    """The published schema is flat and closed, not a ``request`` wrapper."""
    server = make_server()

    async with Client(server) as client:
        tools = (await client.list_tools()).tools

    schema = next(tool for tool in tools if tool.name == FLAT_TOOL).input_schema

    assert "request" not in schema.get("properties", {}), (
        "the flat-argument seam regressed: the published input schema wraps the request "
        f"model again ({schema.get('properties')})."
    )
    assert set(schema.get("properties", {})) == {"name"}, schema
    assert schema.get("required") == ["name"], schema
    assert schema.get("additionalProperties") is False, (
        "the closed-argument seam regressed: the published input schema accepts unknown "
        f"arguments ({schema})."
    )


async def test_a_union_request_still_publishes_its_variants() -> None:
    """A union request keeps a root union of closed variants, not a flattened object."""
    server = make_server()

    async with Client(server) as client:
        tools = (await client.list_tools()).tools

    schema = next(tool for tool in tools if tool.name == UNION_TOOL).input_schema
    branches = schema.get("oneOf") or schema.get("anyOf")

    assert branches, f"the union-argument seam regressed: no root union in {schema}."
    assert len(branches) == 2, schema
    for branch in branches:
        target = schema["$defs"][branch["$ref"].rsplit("/", 1)[-1]]
        assert target.get("additionalProperties") is False, target
        assert target.get("required"), target


async def test_a_no_argument_tool_still_rejects_unknown_arguments() -> None:
    """The no-argument branch of the seam still closes the argument model."""
    server = make_server()

    async with Client(server) as client:
        tools = (await client.list_tools()).tools
        result = await client.call_tool(NO_ARGUMENT_TOOL, {"bogus": 1})

    schema = next(tool for tool in tools if tool.name == NO_ARGUMENT_TOOL).input_schema
    assert schema.get("additionalProperties") is False, schema
    assert result.is_error is True
    assert "bogus is not an accepted argument" in result.content[0].text


async def test_unknown_arguments_are_rejected_with_a_sanitized_message() -> None:
    """The sanitized validation the seam installs still reaches the model."""
    server = make_server()

    async with Client(server) as client:
        result = await client.call_tool(FLAT_TOOL, {"name": "x", "bogus": 1})

    assert result.is_error is True
    text = result.content[0].text
    assert "bogus is not an accepted argument" in text, text
    assert "accepted arguments are name" in text, text
    # Nothing from the raw pydantic dump may reach the model.
    assert "validation error for" not in text, text
    assert "https://" not in text, text
    assert "input_value" not in text, text


async def test_a_real_tool_invocation_still_works() -> None:
    """The seam must not only publish a schema: the SDK must still run the handler."""
    server = make_server()

    async with Client(server) as client:
        flat = await client.call_tool(FLAT_TOOL, {"name": "flat"})
        union = await client.call_tool(UNION_TOOL, {"ip_family": "ipv4", "address": "192.0.2.1"})
        no_arguments = await client.call_tool(NO_ARGUMENT_TOOL, {})

    assert flat.is_error is False, flat.content
    assert flat.structured_content == {"name": "flat"}
    assert union.is_error is False, union.content
    assert union.structured_content == {"ip_family": "ipv4", "address": "192.0.2.1"}
    assert no_arguments.is_error is False, no_arguments.content
    assert no_arguments.structured_content == {"value": "ok"}


@pytest.mark.parametrize("attribute", PRIVATE_SDK_ATTRIBUTES)
def test_the_seam_diagnostic_names_the_moved_attribute(attribute: str) -> None:
    """The seam's own failure message must name the attribute and the verified release."""
    source = TOOLS_MODULE_PATH.read_text(encoding="utf-8")

    assert attribute in source, (
        f"the seam no longer mentions {attribute!r}; update the seam note and this test "
        f"together."
    )
    assert SUPPORTED_MCP_SDK_VERSION in source, (
        f"the seam no longer names the verified SDK release "
        f"{SUPPORTED_MCP_SDK_VERSION}; the diagnostic cannot tell an operator which "
        f"release to install."
    )
