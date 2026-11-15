"""Pydantic models for the Sophos Firewall Configuration REST API.

One module per domain (``firewall``, ``nat``, ``objects``, ``users``, ``network``,
``vpn``, ``audit``) plus :mod:`sophos_firewall_mcp.models.common` for the primitives every
domain shares. Domain adapters project Sophos payloads into these models; MCP output DTOs
are explicit, bounded projections of them, never raw payloads.
"""

from sophos_firewall_mcp.models.common import (
    ListPage,
    ObjectName,
    ObjectRef,
    Pages,
    validate_object_name,
)

__all__ = [
    "ListPage",
    "ObjectName",
    "ObjectRef",
    "Pages",
    "validate_object_name",
]
