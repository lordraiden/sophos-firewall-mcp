#!/usr/bin/env python3
"""Generate docs/API-COVERAGE.md from firewall_config_openapi.yaml.

The generator parses the complete checked-in OpenAPI contract with PyYAML,
resolves every local ``$ref``, validates the operation inventory, merges the
curated decisions from ``scripts/coverage_curated.yaml`` and writes a
deterministic Markdown coverage matrix.

Determinism: the output depends only on the specification and the curated
file. There are no timestamps, environment values or unordered collections in
the document, so the same inputs produce byte-identical output.

Safety: the specification SHA-256 is embedded below. If the file changes, the
generator refuses to write anything unless ``--accept-sha`` is passed
explicitly; that flag records the new SHA in this script so the change is
visible in review.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence

import yaml

# ---------------------------------------------------------------------------
# Embedded contract facts. Update only through an explicitly reviewed
# regeneration (``--accept-sha``), never by hand.
# ---------------------------------------------------------------------------
EXPECTED_SPEC_SHA256 = "58c4bc79ac930ce030202e09835865dcb12fcd44e9132e1f4234a1ed1743b1d5"
EXPECTED_SPEC_SIZE = 8_934_475
EXPECTED_OPENAPI = "3.0.0"
EXPECTED_INFO_TITLE = "Sophos Firewall Configuration API"
EXPECTED_INFO_VERSION = "1.0.0"
EXPECTED_PATH_COUNT = 384
EXPECTED_OPERATION_COUNT = 700
EXPECTED_UNIQUE_OPERATION_IDS = 700
EXPECTED_COMPONENT_SCHEMA_COUNT = 32
EXPECTED_REF_OCCURRENCES = 76
EXPECTED_UNIQUE_REFS = 32

SCRIPT_PATH = Path(__file__).resolve()
SCRIPT_DIR = SCRIPT_PATH.parent
REPO_ROOT = SCRIPT_DIR.parent
DEFAULT_SPEC = REPO_ROOT / "firewall_config_openapi.yaml"
DEFAULT_CURATED = SCRIPT_DIR / "coverage_curated.yaml"
DEFAULT_OUTPUT = REPO_ROOT / "docs" / "API-COVERAGE.md"

HTTP_METHODS: tuple[str, ...] = ("get", "post", "patch", "delete")
METHOD_ORDER: dict[str, int] = {method: index for index, method in enumerate(HTTP_METHODS)}
METHOD_LABELS: dict[str, str] = {method: method.upper() for method in HTTP_METHODS}

PAGINATION_PARAMETERS: tuple[str, ...] = ("page", "pageSize", "pageTotal")
IDENTIFIER_FORMATS: dict[str, str] = {
    "sfos-object-name-or-id": "sfos-object-name-or-id",
    "sfos-object-name-lenient-or-id": "lenient",
    "uuid": "uuid",
}
SCHEMA_PREFIX = "#/components/schemas/"
FINGERPRINT_IGNORED_KEYS = frozenset({"description", "example", "examples"})

ROW_RE = re.compile(r"^\| `([A-Za-z][A-Za-z0-9]*)` \| (GET|POST|PATCH|DELETE) \| `([^`]+)` \|")
SHA_CONSTANT_RE = re.compile(r'^EXPECTED_SPEC_SHA256 = "[0-9a-f]{64}"$', re.MULTILINE)

YAML_LOADER = getattr(yaml, "CSafeLoader", yaml.SafeLoader)


class SpecError(RuntimeError):
    """Raised when the specification or the curated file cannot be used."""


# ---------------------------------------------------------------------------
# Domain mapping: derived from the path only, first matching rule wins.
# The order of this list is the canonical section order of the document.
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class DomainRule:
    key: str
    title: str
    rule: str
    match: Callable[[str], bool]


DOMAIN_RULES: tuple[DomainRule, ...] = (
    DomainRule(
        "firewall_rules",
        "Firewall rules",
        "path starts with `/firewall/rules/`",
        lambda path: path.startswith("/firewall/rules/"),
    ),
    DomainRule(
        "nat_rules",
        "NAT rules",
        "path starts with `/nat/rules/`",
        lambda path: path.startswith("/nat/rules/"),
    ),
    DomainRule(
        "addresses",
        "Addresses and address groups",
        "path starts with `/network/addresses/` or `/network/address-groups/`",
        lambda path: path.startswith("/network/addresses/")
        or path.startswith("/network/address-groups/"),
    ),
    DomainRule(
        "services",
        "Services and service groups",
        "path starts with `/network/services` or `/network/service-groups`",
        lambda path: path.startswith("/network/services")
        or path.startswith("/network/service-groups"),
    ),
    DomainRule(
        "auth_users",
        "Authentication users, administrators and groups",
        "path is `/authentication/users` or `/authentication/user-groups`, or starts with "
        "`/authentication/users/`, `/authentication/user-groups/` or "
        "`/authentication/admin-user/`",
        lambda path: path == "/authentication/users"
        or path.startswith("/authentication/users/")
        or path == "/authentication/user-groups"
        or path.startswith("/authentication/user-groups/")
        or path.startswith("/authentication/admin-user/"),
    ),
    DomainRule(
        "live_users",
        "Live users",
        "path starts with `/authentication/live-users`",
        lambda path: path.startswith("/authentication/live-users"),
    ),
    DomainRule(
        "ipsec_vpn",
        "IPsec VPN",
        "path starts with `/ipsec-vpn/`",
        lambda path: path.startswith("/ipsec-vpn/"),
    ),
    DomainRule(
        "ssl_vpn",
        "SSL VPN",
        "path starts with `/ssl-vpn/`",
        lambda path: path.startswith("/ssl-vpn/"),
    ),
    DomainRule(
        "network_status",
        "Network status",
        "path is exactly `/network/dns/protection/status` or "
        "`/network/cellular-wan/modem-status`; evaluated before `network`",
        lambda path: path
        in ("/network/dns/protection/status", "/network/cellular-wan/modem-status"),
    ),
    DomainRule(
        "network",
        "Network",
        "path starts with `/network/interfaces/`, `/network/zones`, "
        "`/routing/gateways/`, `/routing/static-unicast-routes/`, `/sd-wan/routes/`, "
        "`/network/dhcp/`, `/network/dns/` or `/network/neighbors/`",
        lambda path: path.startswith("/network/interfaces/")
        or path.startswith("/network/zones")
        or path.startswith("/routing/gateways/")
        or path.startswith("/routing/static-unicast-routes/")
        or path.startswith("/sd-wan/routes/")
        or path.startswith("/network/dhcp/")
        or path.startswith("/network/dns/")
        or path.startswith("/network/neighbors/"),
    ),
    DomainRule(
        "audit",
        "Audit (composite)",
        "never matches: this domain has no Sophos operation and is provided by "
        "composite tools only",
        lambda path: False,
    ),
    DomainRule(
        "admin_system",
        "Administration and system",
        "path starts with `/administration/`, `/notification/` or `/system/`",
        lambda path: path.startswith("/administration/")
        or path.startswith("/notification/")
        or path.startswith("/system/"),
    ),
    DomainRule(
        "other",
        "Other catalog",
        "everything not matched above",
        lambda path: True,
    ),
)

DOMAIN_ORDER: tuple[str, ...] = tuple(rule.key for rule in DOMAIN_RULES)
DOMAIN_TITLES: dict[str, str] = {rule.key: rule.title for rule in DOMAIN_RULES}


def domain_for_path(path: str) -> str:
    """Return the canonical domain key for a path."""
    for rule in DOMAIN_RULES:
        if rule.match(path):
            return rule.key
    raise SpecError(f"no domain rule matched path {path!r}")  # pragma: no cover


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Operation:
    operation_id: str
    method: str
    path: str
    domain: str
    request_content_type: str
    request_schema: str
    response_statuses: str
    response_schema: str
    pagination: str
    other_query: str
    identifier: str
    kind: str
    risk: str


@dataclass(frozen=True)
class Record:
    operation: Operation
    mcp: str


@dataclass(frozen=True)
class SpecFacts:
    sha256: str
    size: int
    openapi: str
    title: str
    version: str
    servers: str
    security: str
    path_count: int
    operation_count: int
    method_counts: Mapping[str, int]
    unique_operation_ids: int
    component_schema_count: int
    ref_occurrences: int
    unique_refs: int
    request_body_counts: Mapping[str, int]
    patch_count: int
    patch_merge_patch_count: int
    paginated_get_count: int
    identifier_counts: Mapping[str, int]
    name_format_counts: Mapping[str, int]
    name_pattern_counts: Mapping[str, Mapping[str, int]]
    error_response_count: int
    error_schema_fingerprint: str


class Curated:
    """Curated decisions loaded from scripts/coverage_curated.yaml."""

    def __init__(self, data: Mapping[str, Any]) -> None:
        self.data = data
        self.release: Mapping[str, Any] = _mapping(data.get("release"), "release")
        self.domains: Mapping[str, Any] = _mapping(data.get("domains"), "domains")
        self.tool_map: Mapping[str, str] = _string_mapping(data.get("tool_map"), "tool_map")
        self.tool_notes: Mapping[str, str] = _string_mapping(
            data.get("tool_notes") or {}, "tool_notes"
        )
        self.exclusion_rules: Sequence[Mapping[str, Any]] = _mapping_sequence(
            data.get("exclusion_rules"), "exclusion_rules"
        )
        self.composite_tools: Sequence[Mapping[str, Any]] = _mapping_sequence(
            data.get("composite_tools") or [], "composite_tools"
        )
        self.regressions: Sequence[Mapping[str, Any]] = _mapping_sequence(
            data.get("regressions") or [], "regressions"
        )
        self.risk: Mapping[str, Any] = _mapping(data.get("risk"), "risk")
        self.patch: Mapping[str, Any] = _mapping(data.get("patch"), "patch")
        self.pagination: Mapping[str, Any] = _mapping(data.get("pagination"), "pagination")
        self.identifiers: Mapping[str, Any] = _mapping(data.get("identifiers"), "identifiers")
        self.errors: Mapping[str, Any] = _mapping(data.get("errors"), "errors")
        self.security: Mapping[str, Any] = _mapping(data.get("security"), "security")
        self.live_observations: Sequence[Mapping[str, Any]] = _mapping_sequence(
            data.get("live_observations"), "live_observations"
        )
        self.firmware: Mapping[str, Any] = _mapping(data.get("firmware"), "firmware")

    @property
    def network_affecting(self) -> frozenset[str]:
        raw = self.risk.get("network_affecting") or []
        if not isinstance(raw, list) or not all(isinstance(item, str) for item in raw):
            raise SpecError("risk.network_affecting must be a list of operationIds")
        return frozenset(raw)

    @property
    def patch_exceptions(self) -> Sequence[Mapping[str, Any]]:
        return _mapping_sequence(self.patch.get("exceptions"), "patch.exceptions")


def _mapping(value: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise SpecError(f"curated key {name!r} must be a mapping")
    return value


def _string_mapping(value: Any, name: str) -> Mapping[str, str]:
    mapping = _mapping(value, name)
    for key, item in mapping.items():
        if not isinstance(key, str) or not isinstance(item, str) or not item:
            raise SpecError(f"curated key {name!r} must map non-empty strings to strings")
    return mapping


def _mapping_sequence(value: Any, name: str) -> Sequence[Mapping[str, Any]]:
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise SpecError(f"curated key {name!r} must be a list of mappings")
    return value


# ---------------------------------------------------------------------------
# Loading and reference resolution
# ---------------------------------------------------------------------------
def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_yaml(path: Path) -> Any:
    try:
        with path.open("rb") as handle:
            return yaml.load(handle, Loader=YAML_LOADER)
    except OSError as exc:
        raise SpecError(f"cannot read {path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise SpecError(f"cannot parse {path}: {exc}") from exc


def collect_refs(node: Any, refs: list[str]) -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "$ref" and isinstance(value, str):
                refs.append(value)
            else:
                collect_refs(value, refs)
    elif isinstance(node, list):
        for item in node:
            collect_refs(item, refs)


def resolve_pointer(document: Any, ref: str) -> Any:
    if not ref.startswith(SCHEMA_PREFIX):
        raise SpecError(f"non-local or unsupported $ref: {ref!r}")
    current = document
    for part in ref[len("#/") :].split("/"):
        if not isinstance(current, dict) or part not in current:
            raise SpecError(f"unresolved $ref: {ref!r}")
        current = current[part]
    return current


def resolve_schema(node: Any, document: Any, stack: tuple[str, ...] = ()) -> Any:
    """Return a deep copy of ``node`` with every local $ref resolved."""
    if isinstance(node, dict):
        ref = node.get("$ref")
        if isinstance(ref, str):
            if ref in stack:
                raise SpecError(f"cyclic $ref detected: {' -> '.join(stack + (ref,))}")
            return resolve_schema(resolve_pointer(document, ref), document, stack + (ref,))
        return {key: resolve_schema(value, document, stack) for key, value in node.items()}
    if isinstance(node, list):
        return [resolve_schema(item, document, stack) for item in node]
    return node


def normalize_schema(node: Any) -> Any:
    """Drop prose/examples so fingerprints track structure, not wording."""
    if isinstance(node, dict):
        return {
            key: normalize_schema(value)
            for key, value in node.items()
            if key not in FINGERPRINT_IGNORED_KEYS
        }
    if isinstance(node, list):
        return [normalize_schema(item) for item in node]
    return node


def schema_fingerprint(schema: Any) -> str:
    canonical = json.dumps(
        normalize_schema(schema),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:8]


def schema_shape(schema: Any) -> str:
    if not isinstance(schema, dict):
        return "schema"
    for keyword in ("oneOf", "allOf", "anyOf"):
        branches = schema.get(keyword)
        if isinstance(branches, list):
            return f"{keyword}[{len(branches)}]"
    schema_type = schema.get("type")
    if schema_type == "array":
        return f"array<{schema_shape(schema.get('items') or {})}>"
    if schema_type == "object" or "properties" in schema:
        return "object"
    if isinstance(schema_type, str):
        return schema_type
    return "schema"


def schema_label(schema: Any, document: Any) -> str:
    """Return a stable label: component name or inline shape + fingerprint."""
    if not isinstance(schema, dict) or not schema:
        return "none"
    ref = schema.get("$ref")
    if isinstance(ref, str):
        return ref.rsplit("/", 1)[-1]
    resolved = resolve_schema(schema, document)
    shape = schema_shape(resolved)
    hint = ""
    if shape == "object":
        properties = resolved.get("properties") if isinstance(resolved, dict) else None
        names = sorted(properties) if isinstance(properties, dict) else []
        if 0 < len(names) <= 5:
            hint = "{" + ",".join(names) + "}"
        else:
            hint = f"[{len(names)}]"
    return f"inline:{shape}{hint}#{schema_fingerprint(resolved)}"


# ---------------------------------------------------------------------------
# Operation extraction
# ---------------------------------------------------------------------------
def merge_parameters(
    path_parameters: Sequence[Any], operation_parameters: Sequence[Any]
) -> list[Mapping[str, Any]]:
    merged: dict[tuple[str, str], Mapping[str, Any]] = {}
    for parameter in list(path_parameters) + list(operation_parameters):
        if not isinstance(parameter, dict):
            continue
        name = parameter.get("name")
        location = parameter.get("in")
        if isinstance(name, str) and isinstance(location, str):
            merged[(name, location)] = parameter
    return list(merged.values())


def _query_parameter_names(parameters: Sequence[Mapping[str, Any]]) -> list[str]:
    return [
        parameter["name"]
        for parameter in parameters
        if parameter.get("in") == "query" and isinstance(parameter.get("name"), str)
    ]


def _identifier(parameters: Sequence[Mapping[str, Any]]) -> str:
    path_parameters = [parameter for parameter in parameters if parameter.get("in") == "path"]
    if not path_parameters:
        return "none"
    forms: list[str] = []
    for parameter in path_parameters:
        schema = parameter.get("schema")
        schema_format = schema.get("format") if isinstance(schema, dict) else None
        if isinstance(schema_format, str):
            forms.append(IDENTIFIER_FORMATS.get(schema_format, "untyped"))
        else:
            forms.append("untyped")
    return "+".join(forms)


def _request_details(raw: Mapping[str, Any], document: Any) -> tuple[str, str]:
    body = raw.get("requestBody")
    if not isinstance(body, dict):
        return "none", "none"
    content = body.get("content")
    if not isinstance(content, dict) or not content:
        return "none", "none"
    content_types = sorted(content)
    chosen = "application/json" if "application/json" in content else content_types[0]
    media = content.get(chosen)
    schema = media.get("schema") if isinstance(media, dict) else None
    return ",".join(content_types), schema_label(schema, document)


def _response_details(raw: Mapping[str, Any], document: Any) -> tuple[str, str]:
    responses = raw.get("responses")
    if not isinstance(responses, dict) or not responses:
        return "none", "none"
    statuses = sorted(responses, key=_status_sort_key)
    success = [status for status in responses if isinstance(status, str) and status.startswith("2")]
    if not success:
        return ",".join(statuses), "none"
    chosen = min(success, key=int)
    response = responses.get(chosen)
    content = response.get("content") if isinstance(response, dict) else None
    if not isinstance(content, dict) or not content:
        return ",".join(statuses), "none"
    content_types = sorted(content)
    media_type = "application/json" if "application/json" in content else content_types[0]
    media = content.get(media_type)
    schema = media.get("schema") if isinstance(media, dict) else None
    return ",".join(statuses), schema_label(schema, document)


def _status_sort_key(status: str) -> tuple[int, int, str]:
    if status.isdigit():
        return (0, int(status), status)
    return (1, 0, status)


def extract_operations(document: Any) -> list[Operation]:
    paths = document.get("paths")
    if not isinstance(paths, dict):
        raise SpecError("the specification has no paths object")
    operations: list[Operation] = []
    for path in sorted(paths):
        path_item = paths[path]
        if not isinstance(path_item, dict):
            raise SpecError(f"path item for {path!r} is not an object")
        path_parameters = path_item.get("parameters") or []
        for method in HTTP_METHODS:
            raw = path_item.get(method)
            if not isinstance(raw, dict):
                continue
            operation_id = raw.get("operationId")
            if not isinstance(operation_id, str) or not operation_id:
                raise SpecError(f"missing operationId for {method.upper()} {path}")
            parameters = merge_parameters(path_parameters, raw.get("parameters") or [])
            query_names = _query_parameter_names(parameters)
            pagination = [name for name in PAGINATION_PARAMETERS if name in query_names]
            other_query = sorted(name for name in query_names if name not in PAGINATION_PARAMETERS)
            request_content_type, request_schema = _request_details(raw, document)
            response_statuses, response_schema = _response_details(raw, document)
            operations.append(
                Operation(
                    operation_id=operation_id,
                    method=METHOD_LABELS[method],
                    path=path,
                    domain=domain_for_path(path),
                    request_content_type=request_content_type,
                    request_schema=request_schema,
                    response_statuses=response_statuses,
                    response_schema=response_schema,
                    pagination=",".join(pagination) if pagination else "none",
                    other_query=",".join(other_query) if other_query else "none",
                    identifier=_identifier(parameters),
                    kind="read" if method == "get" else "mutation",
                    risk="",
                )
            )
    return operations


# ---------------------------------------------------------------------------
# Facts
# ---------------------------------------------------------------------------
def _walk_schema_formats(
    node: Any,
    format_counts: Counter[str],
    pattern_counts: dict[str, Counter[str]],
) -> None:
    if isinstance(node, dict):
        schema_format = node.get("format")
        if isinstance(schema_format, str) and schema_format.startswith("sfos-object-name"):
            format_counts[schema_format] += 1
            bucket = pattern_counts.setdefault(schema_format, Counter())
            pattern = node.get("pattern")
            if pattern is None:
                bucket["none"] += 1
            elif pattern == "^[^,]*$":
                bucket["comma_only"] += 1
            else:
                bucket["other"] += 1
        for value in node.values():
            _walk_schema_formats(value, format_counts, pattern_counts)
    elif isinstance(node, list):
        for item in node:
            _walk_schema_formats(item, format_counts, pattern_counts)


def assert_all_refs_resolved(document: Any) -> None:
    """Resolve the whole document once and prove that no ``$ref`` remains."""
    resolved = resolve_schema(document, document)
    remaining: list[str] = []
    collect_refs(resolved, remaining)
    if remaining:
        raise SpecError(f"unresolved $refs after resolution: {sorted(set(remaining))}")


def compute_facts(document: Any, spec_path: Path, sha256: str) -> SpecFacts:
    operations = extract_operations(document)
    method_counts = Counter(operation.method for operation in operations)
    request_body_counts: Counter[str] = Counter()
    patch_count = 0
    patch_merge_patch_count = 0
    paginated_get_count = 0
    identifier_counts: Counter[str] = Counter()
    for operation in operations:
        request_body_counts[operation.request_content_type] += 1
        identifier_counts[operation.identifier] += 1
        if operation.method == "PATCH":
            patch_count += 1
            if "application/merge-patch+json" in operation.request_content_type:
                patch_merge_patch_count += 1
        if operation.method == "GET" and operation.pagination != "none":
            paginated_get_count += 1

    refs: list[str] = []
    collect_refs(document, refs)
    unique_refs = sorted(set(refs))
    for ref in unique_refs:
        resolve_pointer(document, ref)

    format_counts: Counter[str] = Counter()
    pattern_counts: dict[str, Counter[str]] = {}
    _walk_schema_formats(document, format_counts, pattern_counts)

    error_schema_fingerprints: Counter[str] = Counter()
    error_response_count = 0
    paths = document.get("paths") or {}
    for path_item in paths.values():
        if not isinstance(path_item, dict):
            continue
        for method in HTTP_METHODS:
            raw = path_item.get(method)
            if not isinstance(raw, dict):
                continue
            responses = raw.get("responses") or {}
            if not isinstance(responses, dict):
                continue
            for status, response in responses.items():
                if not isinstance(status, str) or status.startswith("2"):
                    continue
                if not isinstance(response, dict):
                    continue
                content = response.get("content") or {}
                media = content.get("application/json") if isinstance(content, dict) else None
                schema = media.get("schema") if isinstance(media, dict) else None
                if schema is not None:
                    error_response_count += 1
                    error_schema_fingerprints[schema_fingerprint(schema)] += 1

    if len(error_schema_fingerprints) == 1:
        error_fingerprint = next(iter(error_schema_fingerprints))
    else:  # pragma: no cover - the current contract has exactly one envelope
        error_fingerprint = "multiple"

    servers = document.get("servers") or []
    server_url = servers[0].get("url") if servers and isinstance(servers[0], dict) else "unknown"
    server_default = ""
    if servers and isinstance(servers[0], dict):
        variables = servers[0].get("variables") or {}
        if isinstance(variables, dict):
            for variable in variables.values():
                if isinstance(variable, dict) and "default" in variable:
                    server_default = str(variable["default"])
                    break
    server_text = f"`{server_url}`"
    if server_default:
        server_text += f" (default `{server_default}`)"

    security_schemes = (document.get("components") or {}).get("securitySchemes") or {}
    scheme = security_schemes.get("apiKey") if isinstance(security_schemes, dict) else None
    if isinstance(scheme, dict):
        security_text = (
            f"`{scheme.get('type', '?')}` / `{scheme.get('scheme', '?')}` "
            f"(`bearerFormat: {scheme.get('bearerFormat', '?')}`), global, no operation override"
        )
    else:  # pragma: no cover - the current contract declares the scheme
        security_text = "unknown"

    info = document.get("info") or {}
    return SpecFacts(
        sha256=sha256,
        size=spec_path.stat().st_size,
        openapi=str(document.get("openapi", "unknown")),
        title=str(info.get("title", "unknown")),
        version=str(info.get("version", "unknown")),
        servers=server_text,
        security=security_text,
        path_count=len(paths),
        operation_count=len(operations),
        method_counts=dict(method_counts),
        unique_operation_ids=len({operation.operation_id for operation in operations}),
        component_schema_count=len(((document.get("components") or {}).get("schemas") or {})),
        ref_occurrences=len(refs),
        unique_refs=len(unique_refs),
        request_body_counts=dict(request_body_counts),
        patch_count=patch_count,
        patch_merge_patch_count=patch_merge_patch_count,
        paginated_get_count=paginated_get_count,
        identifier_counts=dict(identifier_counts),
        name_format_counts=dict(format_counts),
        name_pattern_counts={
            schema_format: dict(counts) for schema_format, counts in pattern_counts.items()
        },
        error_response_count=error_response_count,
        error_schema_fingerprint=error_fingerprint,
    )


# ---------------------------------------------------------------------------
# Curated decisions
# ---------------------------------------------------------------------------
def load_curated(path: Path) -> Curated:
    data = load_yaml(path)
    if not isinstance(data, dict):
        raise SpecError(f"{path} must contain a mapping")
    if data.get("version") != 1:
        raise SpecError(f"{path}: unsupported curated version {data.get('version')!r}")
    curated = Curated(data)
    missing = [key for key in DOMAIN_ORDER if key not in curated.domains]
    extra = [key for key in curated.domains if key not in DOMAIN_ORDER]
    if missing or extra:
        raise SpecError(f"curated domains mismatch: missing={missing} extra={extra}")
    for key in DOMAIN_ORDER:
        block = _mapping(curated.domains[key], f"domains.{key}")
        for field in ("title", "v1_scope", "default_exclusion"):
            if not isinstance(block.get(field), str) or not block[field]:
                raise SpecError(f"domains.{key}.{field} must be a non-empty string")
        for field in ("exclusions", "caveats"):
            value = block.get(field) or []
            if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
                raise SpecError(f"domains.{key}.{field} must be a list of strings")
    if not curated.tool_map:
        raise SpecError("tool_map must not be empty")
    # A merged tool covers both IP families, so two operationIds may map to the same tool
    # name. The name is still unique per concept; only the operation-to-tool mapping is
    # many-to-one.
    tool_names = list(curated.tool_map.values())
    if not all(isinstance(name, str) and name for name in tool_names):
        raise SpecError("every tool_map value must be a non-empty MCP tool name")
    for rule in curated.exclusion_rules:
        if not isinstance(rule.get("id"), str) or not isinstance(rule.get("reason"), str):
            raise SpecError("every exclusion rule needs a string id and reason")
        if not any(
            key in rule
            for key in (
                "operation_ids",
                "method",
                "path_prefix",
                "path_prefixes",
                "path_suffix",
                "kind",
            )
        ):
            raise SpecError(f"exclusion rule {rule['id']!r} has no predicate")
    for exception in curated.patch_exceptions:
        for field in ("operation_id", "path", "deviation"):
            if not isinstance(exception.get(field), str) or not exception[field]:
                raise SpecError(f"patch exception needs a string {field}")
    for observation in curated.live_observations:
        for field in ("id", "statement", "decision"):
            if not isinstance(observation.get(field), str) or not observation[field]:
                raise SpecError(f"live observation needs a string {field}")
    composite_names = [tool.get("name") for tool in curated.composite_tools]
    if not all(isinstance(name, str) and name for name in composite_names):
        raise SpecError("every composite tool needs a non-empty string name")
    if len(composite_names) != len(set(composite_names)):
        raise SpecError("composite_tools contains duplicate tool names")
    if set(composite_names) & set(tool_names):
        raise SpecError("a composite tool name collides with a tool_map name")
    for tool in curated.composite_tools:
        for field in ("name", "domain", "description"):
            if not isinstance(tool.get(field), str) or not tool[field]:
                raise SpecError(f"composite tool needs a string {field}")
        if tool.get("kind") not in ("read", "mutation"):
            raise SpecError(f"composite tool {tool['name']!r} needs kind 'read' or 'mutation'")
        if tool["domain"] not in DOMAIN_ORDER:
            raise SpecError(f"composite tool {tool['name']!r} has unknown domain")
        operation_ids = tool.get("operation_ids")
        if (
            not isinstance(operation_ids, list)
            or not operation_ids
            or not all(isinstance(item, str) and item for item in operation_ids)
        ):
            raise SpecError(f"composite tool {tool['name']!r} needs a non-empty operation_ids list")
    for regression in curated.regressions:
        for field in ("id", "statement", "decision"):
            if not isinstance(regression.get(field), str) or not regression[field]:
                raise SpecError(f"regression needs a string {field}")
    return curated


def _rule_matches(rule: Mapping[str, Any], operation: Operation) -> bool:
    operation_ids = rule.get("operation_ids")
    if isinstance(operation_ids, list) and operation.operation_id not in operation_ids:
        return False
    method = rule.get("method")
    if isinstance(method, str) and operation.method != method.upper():
        return False
    path_prefix = rule.get("path_prefix")
    if isinstance(path_prefix, str) and not operation.path.startswith(path_prefix):
        return False
    path_prefixes = rule.get("path_prefixes")
    if isinstance(path_prefixes, list) and not any(
        operation.path.startswith(str(prefix)) for prefix in path_prefixes
    ):
        return False
    path_suffix = rule.get("path_suffix")
    if isinstance(path_suffix, str) and not operation.path.endswith(path_suffix):
        return False
    kind = rule.get("kind")
    if isinstance(kind, str) and operation.kind != kind:
        return False
    return True


def _risk_flags(operation: Operation, curated: Curated) -> str:
    flags: list[str] = []
    if operation.method == "POST" and operation.path.endswith("/delete"):
        flags.append("bulk")
    elif operation.method == "DELETE":
        flags.append("destructive")
    elif operation.method in ("POST", "PATCH"):
        flags.append("write")
    if operation.operation_id.startswith("move") or operation.path.endswith("/move"):
        flags.append("move")
    if "disconnect" in operation.operation_id.lower():
        flags.append("disconnect")
    if operation.operation_id in curated.network_affecting:
        flags.append("network-affecting")
    return ",".join(flags) if flags else "—"


def build_records(document: Any, curated: Curated) -> list[Record]:
    operations = extract_operations(document)
    known_ids = {operation.operation_id for operation in operations}
    unknown = sorted(set(curated.tool_map) - known_ids)
    if unknown:
        raise SpecError(f"tool_map references unknown operationIds: {unknown}")
    patch_notes = {
        exception["operation_id"]: f"PATCH exception: {exception['deviation']}"
        for exception in curated.patch_exceptions
    }
    unknown_patch = sorted(set(patch_notes) - known_ids)
    if unknown_patch:
        raise SpecError(f"patch exceptions reference unknown operationIds: {unknown_patch}")
    for tool in curated.composite_tools:
        unknown_composite = sorted(set(tool["operation_ids"]) - known_ids)
        if unknown_composite:
            raise SpecError(
                f"composite tool {tool['name']!r} references unknown operationIds: "
                f"{unknown_composite}"
            )
        unaudited = sorted(set(tool["operation_ids"]) - set(curated.tool_map))
        if unaudited:
            raise SpecError(
                f"composite tool {tool['name']!r} references operations outside the audited "
                f"v1 tool_map: {unaudited}"
            )

    records: list[Record] = []
    for operation in operations:
        operation = Operation(**{**operation.__dict__, "risk": _risk_flags(operation, curated)})
        note = curated.tool_notes.get(operation.operation_id) or patch_notes.get(
            operation.operation_id
        )
        if operation.operation_id in curated.tool_map:
            mcp = f"`{curated.tool_map[operation.operation_id]}`"
        else:
            reason = None
            for rule in curated.exclusion_rules:
                if _rule_matches(rule, operation):
                    reason = str(rule["reason"])
                    break
            if reason is None:
                block = _mapping(curated.domains[operation.domain], operation.domain)
                reason = str(block["default_exclusion"])
            mcp = f"excluded: {reason}"
        if note:
            mcp += f" [{note}]"
        records.append(Record(operation=operation, mcp=mcp))

    records.sort(
        key=lambda record: (
            DOMAIN_ORDER.index(record.operation.domain),
            record.operation.path,
            METHOD_ORDER[record.operation.method.lower()],
        )
    )
    return records


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------
def validate_inventory(
    records: Sequence[Record], rendered: str, document: Any, curated: Curated
) -> None:
    expected = extract_operations(document)
    expected_ids = {operation.operation_id for operation in expected}
    record_ids = [record.operation.operation_id for record in records]
    if len(records) != len(expected):
        raise SpecError(
            f"inventory has {len(records)} operations but the specification has {len(expected)}"
        )
    if len(record_ids) != len(set(record_ids)):
        duplicates = sorted(
            operation_id for operation_id, count in Counter(record_ids).items() if count > 1
        )
        raise SpecError(f"duplicate operationIds in the inventory: {duplicates}")
    if set(record_ids) != expected_ids:
        missing = sorted(expected_ids - set(record_ids))
        extra = sorted(set(record_ids) - expected_ids)
        raise SpecError(f"inventory/spec mismatch: missing={missing} extra={extra}")
    if len(records) != EXPECTED_OPERATION_COUNT:
        raise SpecError(f"expected {EXPECTED_OPERATION_COUNT} operations, found {len(records)}")

    rendered_rows: list[tuple[str, str, str]] = []
    for line in rendered.splitlines():
        match = ROW_RE.match(line)
        if match:
            rendered_rows.append((match.group(1), match.group(2), match.group(3)))
    if len(rendered_rows) != len(records):
        raise SpecError(
            f"rendered document has {len(rendered_rows)} operation rows, expected {len(records)}"
        )
    rendered_ids = [row[0] for row in rendered_rows]
    if len(rendered_ids) != len(set(rendered_ids)):
        duplicates = sorted(
            operation_id for operation_id, count in Counter(rendered_ids).items() if count > 1
        )
        raise SpecError(f"duplicate operations rendered in the document: {duplicates}")
    if set(rendered_ids) != expected_ids:
        missing = sorted(expected_ids - set(rendered_ids))
        extra = sorted(set(rendered_ids) - expected_ids)
        raise SpecError(f"rendered document/spec mismatch: missing={missing} extra={extra}")
    for operation_id, method, path in rendered_rows:
        matches = [
            record
            for record in records
            if record.operation.operation_id == operation_id
            and record.operation.method == method
            and record.operation.path == path
        ]
        if len(matches) != 1:
            raise SpecError(f"rendered row for {operation_id} does not match exactly one operation")

    composite_domains = {tool["domain"] for tool in curated.composite_tools}
    for domain in DOMAIN_ORDER:
        count = sum(1 for record in records if record.operation.domain == domain)
        if count == 0 and domain not in composite_domains:
            raise SpecError(f"domain {domain!r} has no operations and no composite tools")
    if sum(
        sum(1 for record in records if record.operation.domain == domain) for domain in DOMAIN_ORDER
    ) != len(records):
        raise SpecError("every operation must belong to exactly one domain")


# ---------------------------------------------------------------------------
# Rendering helpers
# ---------------------------------------------------------------------------
def _cell(value: Any) -> str:
    text = str(value).replace("\r", " ").replace("\n", " ").replace("|", "\\|")
    return text.strip()


def markdown_table(headers: Sequence[str], rows: Iterable[Sequence[Any]]) -> str:
    lines = [
        "| " + " | ".join(_cell(header) for header in headers) + " |",
        "|" + "|".join("---" for _ in headers) + "|",
    ]
    for row in rows:
        lines.append("| " + " | ".join(_cell(cell) for cell in row) + " |")
    return "\n".join(lines)


def _bullets(items: Iterable[str]) -> str:
    return "\n".join(f"- {_cell(item)}" for item in items)


def _code(value: str) -> str:
    return f"`{value}`"


def _schema_cell(label: str) -> str:
    return "none" if label == "none" else _code(label)


def _method_summary(facts: SpecFacts) -> str:
    return ", ".join(
        f"{method} {facts.method_counts.get(method, 0)}"
        for method in ("GET", "POST", "PATCH", "DELETE")
    )


def _request_body_summary(facts: SpecFacts) -> str:
    json_count = facts.request_body_counts.get("application/json", 0)
    multipart_count = facts.request_body_counts.get("multipart/form-data", 0)
    none_count = facts.request_body_counts.get("none", 0)
    return (
        f"{json_count} `application/json`, {multipart_count} `multipart/form-data`, "
        f"{none_count} none"
    )


def _tools_for_domain(records: Sequence[Record], domain: str) -> list[str]:
    """The distinct MCP tool names the domain's operations map to, sorted.

    A merged IPv4/IPv6 tool appears once even though two operations map to it.
    """
    tools: set[str] = set()
    for record in records:
        if record.operation.domain != domain or not record.mcp.startswith("`"):
            continue
        tools.add(record.mcp[1:].split("`", 1)[0])
    return sorted(tools)


def _tool_counts(records: Sequence[Record], curated: Curated, domain: str) -> tuple[int, int]:
    """Return (one-to-one operations, total tools including composites).

    The operation count is the number of audited operations the domain exposes; the tool
    count is the number of distinct tools, so a merged IPv4/IPv6 tool counts once.
    """
    operations = sum(
        1 for record in records if record.operation.domain == domain and record.mcp.startswith("`")
    )
    tools = len(_tools_for_domain(records, domain))
    composites = sum(1 for tool in curated.composite_tools if tool["domain"] == domain)
    return operations, tools + composites


def _composite_rows(curated: Curated, domain: str | None = None) -> list[tuple[str, str, str, str]]:
    rows: list[tuple[str, str, str, str]] = []
    for tool in curated.composite_tools:
        if domain is not None and tool["domain"] != domain:
            continue
        rows.append(
            (
                _code(tool["name"]),
                _code(tool["kind"]),
                ", ".join(_code(item) for item in tool["operation_ids"]),
                _cell(tool["description"]),
            )
        )
    return rows


# ---------------------------------------------------------------------------
# Document rendering
# ---------------------------------------------------------------------------
def render_document(
    facts: SpecFacts, records: Sequence[Record], curated: Curated, document: Any
) -> str:
    lines: list[str] = []
    add = lines.append

    add("# API coverage — Sophos Firewall Configuration REST API")
    add("")
    add(
        "> **Generated file.** The inventory tables below are generated from "
        "`firewall_config_openapi.yaml` by `scripts/generate_coverage.py`. Do not hand-edit "
        "generated sections: edit `scripts/coverage_curated.yaml` (human decisions) and "
        "regenerate. The generator refuses to write output when the specification SHA-256 "
        "differs from the embedded value unless `--accept-sha` is passed explicitly."
    )
    add("")
    add("## 1. Provenance and validation")
    add("")
    add(
        "The generator parses the complete checked-in contract, resolves every local `$ref`, "
        "validates the operation inventory and then writes this document. The validation is "
        "part of the generation: a missing, duplicated or extra operation aborts the run "
        "without writing."
    )
    add("")
    add(
        markdown_table(
            ("Fact", "Value"),
            (
                ("Specification file", _code("firewall_config_openapi.yaml")),
                ("SHA-256", _code(facts.sha256)),
                ("Size", f"{facts.size:,} bytes"),
                ("OpenAPI", facts.openapi),
                ("API title", facts.title),
                ("API version", facts.version),
                ("Server / base URL", facts.servers),
                ("Security", facts.security),
                ("Paths", str(facts.path_count)),
                ("Operations", f"{facts.operation_count} ({_method_summary(facts)})"),
                (
                    "operationIds",
                    f"{facts.operation_count} present, {facts.unique_operation_ids} unique",
                ),
                ("Component schemas", str(facts.component_schema_count)),
                (
                    "`$ref`",
                    f"{facts.ref_occurrences} occurrences, {facts.unique_refs} unique, "
                    "all local under `#/components/schemas`, 0 unresolved",
                ),
                ("Request bodies", _request_body_summary(facts)),
                (
                    "PATCH",
                    f"{facts.patch_count} operations, all `application/json`, "
                    f"{facts.patch_merge_patch_count} `application/merge-patch+json`",
                ),
                (
                    "Pagination",
                    f"{facts.paginated_get_count} GET operations declare "
                    "`page`/`pageSize`/`pageTotal`",
                ),
                (
                    "Error responses",
                    f"{facts.error_response_count:,} documented non-2xx responses; one shared "
                    f"JSON envelope schema `inline:object{{error,message,code}}"
                    f"#{facts.error_schema_fingerprint}`",
                ),
                (
                    "Generation",
                    _code("uv run --no-sync python scripts/generate_coverage.py"),
                ),
                (
                    "Drift check",
                    _code("uv run --no-sync python scripts/generate_coverage.py --check"),
                ),
            ),
        )
    )
    add("")
    add(
        "Determinism: the output depends only on the specification and "
        "`scripts/coverage_curated.yaml`. There are no timestamps or environment values, "
        "sections follow the canonical domain order, and rows are sorted by path and then by "
        "the fixed method order GET, POST, PATCH, DELETE. Regenerating from the same inputs "
        "produces byte-identical output."
    )
    add("")

    add("## 2. How to read this document")
    add("")
    add("### 2.1 Columns")
    add("")
    add(
        markdown_table(
            ("Column", "Meaning"),
            (
                ("operationId", "The contract's `operationId`; exactly one row per operation."),
                ("method", "HTTP method (GET, POST, PATCH or DELETE)."),
                ("path", "The contract path, including path parameters."),
                (
                    "request content type",
                    "Declared request media type(s), or `none` when the operation has no body.",
                ),
                (
                    "request schema",
                    "Component schema name or inline-schema label; `none` when there is no body.",
                ),
                ("responses", "Every documented response status, ascending."),
                (
                    "response schema",
                    "Schema of the success response (200/201); `none` when it has no body.",
                ),
                (
                    "pagination",
                    "Declared pagination query parameters, or `none`.",
                ),
                (
                    "other query params",
                    "Non-pagination query parameters (filters, sort, type), or `none`.",
                ),
                (
                    "path identifier",
                    "Identifier form of the path parameter(s): `sfos-object-name-or-id`, "
                    "`lenient`, `uuid`, `untyped` or `none`.",
                ),
                ("kind", "`read` for GET, `mutation` for POST/PATCH/DELETE."),
                (
                    "risk",
                    "Impact flags: `bulk`, `move`, `disconnect`, `network-affecting`, "
                    "`destructive` (single DELETE) or `write` (POST/PATCH); `—` for reads.",
                ),
                (
                    "MCP tool / exclusion",
                    "Intended v1 MCP tool name, or `excluded:` with the explicit reason.",
                ),
            ),
        )
    )
    add("")
    add("### 2.2 Schema labels")
    add("")
    add(
        "- A component schema is shown by its name after `#/components/schemas/` "
        "(for example `FirewallRuleIpv4Firewall`)."
    )
    add(
        "- An inline schema is shown as `inline:<shape>[<n>]#<fingerprint>`, where the "
        "fingerprint is the first 8 hex characters of the SHA-256 of the structurally "
        "normalized schema (descriptions and examples removed). Expand a fingerprint with "
        "`uv run --no-sync python scripts/generate_coverage.py --explain-schema <fingerprint>`."
    )
    add(
        "- `none` means the operation has no request body or no success-response body. "
        "Inline fingerprints change when the structure changes, so a regeneration diff shows "
        "schema drift even when the operation count is unchanged."
    )
    add("")
    add("### 2.3 Risk vocabulary")
    add("")
    add(
        markdown_table(
            ("Flag", "Meaning"),
            (
                ("bulk", "`POST` to a path ending in `/delete` (bulk delete)."),
                ("move", "Changes object ordering (`move*` operations)."),
                ("disconnect", "Disconnects a live session or a cellular modem."),
                (
                    "network-affecting",
                    "Curated list in `scripts/coverage_curated.yaml` (interface mutations and "
                    "cellular-WAN connectivity operations).",
                ),
                ("destructive", "Single-object `DELETE`."),
                ("write", "`POST` create or `PATCH` update."),
                ("—", "Read-only operation."),
            ),
        )
    )
    add("")
    add("### 2.4 Identifier vocabulary")
    add("")
    add(
        markdown_table(
            ("Value", "Meaning"),
            (
                ("sfos-object-name-or-id", "Name or UUID (`format: sfos-object-name-or-id`)."),
                ("lenient", "Lenient name or UUID (`format: sfos-object-name-lenient-or-id`)."),
                ("uuid", "UUID only (`format: uuid`)."),
                ("untyped", "Path parameter with no `format` in the contract."),
                ("none", "No path parameter."),
            ),
        )
    )
    add("")

    add("## 3. Domain mapping rule")
    add("")
    add(
        "Sections and rows are emitted in the canonical order below; within a section rows are "
        "sorted by path and then by the fixed method order GET, POST, PATCH, DELETE. The mapping "
        "is derived from the path only and the first matching rule wins. `network_status` is "
        "evaluated before `network` so the two status paths are not captured by the broader "
        "network rule; `audit` never matches a path because it is provided by composite tools."
    )
    add("")
    domain_counts = Counter(record.operation.domain for record in records)
    add(
        markdown_table(
            ("#", "Domain", "Rule (first match wins)", "Operations"),
            (
                (
                    str(index),
                    _code(rule.key),
                    rule.rule,
                    str(domain_counts.get(rule.key, 0)),
                )
                for index, rule in enumerate(DOMAIN_RULES, start=1)
            ),
        )
    )
    add("")

    add("## 4. Curated decisions")
    add("")
    add("### 4.1 First-release scope (v1)")
    add("")
    add(_cell(curated.release.get("summary", "")))
    add("")
    add(_cell(curated.release.get("rule", "")))
    add("")
    scope_rows: list[tuple[str, str, str, str]] = []
    total_operations = 0
    total_tools = 0
    domains_with_tools = 0
    for rule in DOMAIN_RULES:
        block = _mapping(curated.domains[rule.key], rule.key)
        operations, tool_count = _tool_counts(records, curated, rule.key)
        if tool_count == 0:
            continue
        domains_with_tools += 1
        total_operations += operations
        total_tools += tool_count
        scope_rows.append((rule.title, str(operations), str(tool_count), _cell(block["v1_scope"])))
    scope_rows.append(("**Total**", f"**{total_operations}**", f"**{total_tools}**", ""))
    add(
        markdown_table(
            ("Domain", "v1 operations", "v1 tools", "v1 scope"),
            scope_rows,
        )
    )
    add("")
    add(
        f"Generated: {total_operations} audited operations exposed through "
        f"{total_tools - len(curated.composite_tools)} one-to-one tools (the IPv4/IPv6 pairs "
        f"share one tool each) plus {len(curated.composite_tools)} composite tools = "
        f"{total_tools} MCP tools across "
        f"{domains_with_tools} domains with tools. `admin_system` and `other` are "
        "classification-only domains (0 tools); their full inventories are in §5."
    )
    add("")

    add("### 4.2 Composite tools")
    add("")
    add(
        "Composite tools add no new Sophos endpoint: they reuse the audited operations in "
        "`tool_map` and reason over their results. Each tool declares its `kind`: the three "
        "audit tools are `read`, while the two firewall composites are `mutation` because "
        "they PATCH `enabled` or create a cloned rule. When `SOPHOS_READ_ONLY_MODE=true`, only "
        "`read` tools may be registered; the mutation composites must not be registered in "
        "that mode."
    )
    add("")
    add(
        markdown_table(
            ("Tool", "Kind", "Domain", "Underlying operationIds", "Description"),
            (
                (
                    _code(tool["name"]),
                    _code(tool["kind"]),
                    _code(tool["domain"]),
                    ", ".join(_code(item) for item in tool["operation_ids"]),
                    _cell(tool["description"]),
                )
                for tool in curated.composite_tools
            ),
        )
    )
    add("")

    add("### 4.3 Exclusions")
    add("")
    add(
        "The table lists the ordered exclusion rules. The tool map wins first, then these rules "
        "are evaluated in order, then the per-domain default exclusion applies. Every excluded "
        "operation carries its reason in the inventory row."
    )
    add("")
    add(
        markdown_table(
            ("Rule", "Applies to", "Reason"),
            (
                (
                    _code(str(rule["id"])),
                    _cell(rule.get("applies", "")),
                    _cell(rule["reason"]),
                )
                for rule in curated.exclusion_rules
            ),
        )
    )
    add("")

    add("### 4.4 PATCH semantics and documented exceptions")
    add("")
    add(_cell(curated.patch.get("default_semantics", "")))
    add("")
    add(_cell(curated.patch.get("content_type_rule", "")))
    add("")
    add(
        markdown_table(
            ("Operation", "Path", "Documented deviation"),
            (
                (
                    _code(exception["operation_id"]),
                    _code(exception["path"]),
                    _cell(exception["deviation"]),
                )
                for exception in curated.patch_exceptions
            ),
        )
    )
    add("")
    add(
        "None of these four operations is in the v1 tool surface; they are recorded because "
        "the contract documents them and a future implementation must not assume full-array "
        "replacement."
    )
    add("")

    add("### 4.5 Pagination")
    add("")
    add(_cell(curated.pagination.get("declared_parameters", "")))
    add("")
    add(_cell(curated.pagination.get("declared_maximum", "")))
    add("")
    add(_bullets(str(item) for item in curated.pagination.get("rules") or []))
    add("")

    add("### 4.6 Object identifiers and name formats")
    add("")
    add(_bullets(str(item) for item in curated.identifiers.get("formats") or []))
    add("")
    add("Generated distribution of path-parameter identifier forms across the 700 operations:")
    add("")
    add(
        markdown_table(
            ("Identifier form", "Operations"),
            (
                (form, str(facts.identifier_counts.get(form, 0)))
                for form in (
                    "none",
                    "sfos-object-name-or-id",
                    "lenient",
                    "uuid",
                    "untyped",
                )
            ),
        )
    )
    add("")
    add(
        "Generated distribution of `sfos-object-name*` schema formats and their `pattern` "
        "coverage (the formats are annotations, not assertions):"
    )
    add("")
    format_rows = []
    for schema_format in sorted(facts.name_format_counts):
        counts = facts.name_pattern_counts.get(schema_format, {})
        format_rows.append(
            (
                _code(schema_format),
                str(facts.name_format_counts[schema_format]),
                str(counts.get("none", 0)),
                str(counts.get("comma_only", 0)),
                str(counts.get("other", 0)),
            )
        )
    add(
        markdown_table(
            ("Format", "Occurrences", "No `pattern`", "`^[^,]*$`", "Other `pattern`"),
            format_rows,
        )
    )
    add("")
    add(_bullets(str(item) for item in curated.identifiers.get("rules") or []))
    add("")

    add("### 4.7 Responses and errors")
    add("")
    add(_cell(curated.errors.get("envelope", "")))
    add("")
    add(
        f"Generated: {facts.error_response_count:,} documented non-2xx responses share the "
        f"single envelope schema fingerprint `{facts.error_schema_fingerprint}`. Per-operation "
        "status codes are in the `responses` column; they are not a universal map."
    )
    add("")
    add(_bullets(str(item) for item in curated.errors.get("rules") or []))
    add("")

    add("### 4.8 Security and permissions")
    add("")
    add(_cell(curated.security.get("contract", "")))
    add("")
    add(_bullets(str(item) for item in curated.security.get("rules") or []))
    add("")

    add("### 4.9 Live observations (15 November 2026)")
    add("")
    add(
        "Read-only smoke test against the lab appliance; full evidence in "
        "[`docs/live-evidence/api-smoke-2026-11-15.md`](live-evidence/api-smoke-2026-11-15.md). "
        "These observations are recorded here because they qualify the contract; the contract "
        "remains authoritative for the tool surface."
    )
    add("")
    add(
        markdown_table(
            ("Observation", "Finding", "Decision"),
            (
                (
                    _code(str(observation["id"])),
                    _cell(observation["statement"]),
                    _cell(observation["decision"]),
                )
                for observation in curated.live_observations
            ),
        )
    )
    add("")

    add("### 4.10 Accepted regressions")
    add("")
    add(
        "The REST contract does not expose every capability of the old XML tooling or the Web "
        "Admin Console. These gaps are accepted for v1 and are not hidden behind placeholder "
        "tools."
    )
    add("")
    add(
        markdown_table(
            ("Regression", "Statement", "Decision"),
            (
                (
                    _code(str(regression["id"])),
                    _cell(regression["statement"]),
                    _cell(regression["decision"]),
                )
                for regression in curated.regressions
            ),
        )
    )
    add("")

    add("### 4.11 Firmware and live verification")
    add("")
    add(_cell(curated.firmware.get("status", "")))
    add("")
    live_evidence = str(curated.firmware.get("live_evidence", ""))
    evidence_links = []
    for evidence_path in (part.strip() for part in live_evidence.split(",")):
        if not evidence_path:
            continue
        evidence_href = evidence_path[5:] if evidence_path.startswith("docs/") else evidence_path
        evidence_links.append(f"[`{evidence_path}`]({evidence_href})")
    add(
        f"Live evidence: {', '.join(evidence_links)}. "
        "The opt-in `pytest -m live` protocol and the `docs/live-evidence/<domain>.md` record "
        "format are documented in [`docs/live-evidence/README.md`](live-evidence/README.md)."
    )
    add("")

    add("## 5. Operations by domain")
    add("")
    for index, rule in enumerate(DOMAIN_RULES, start=1):
        block = _mapping(curated.domains[rule.key], rule.key)
        domain_records = [record for record in records if record.operation.domain == rule.key]
        tools = _tools_for_domain(records, rule.key)
        composites = _composite_rows(curated, rule.key)
        add(f"### 5.{index} {rule.title} ({len(domain_records)} operations)")
        add("")
        add(f"**Curated decisions** (`scripts/coverage_curated.yaml` → " f"`domains.{rule.key}`):")
        add("")
        add(f"- v1 scope: {_cell(block['v1_scope'])}")
        if tools:
            add("- v1 tools: " + ", ".join(_code(tool) for tool in tools))
        else:
            add("- v1 tools: none")
        if composites:
            read_count = sum(
                1
                for tool in curated.composite_tools
                if tool["domain"] == rule.key and tool["kind"] == "read"
            )
            mutation_count = len(composites) - read_count
            add(
                f"- composite tools: {len(composites)} "
                f"({read_count} read, {mutation_count} mutation)"
            )
        exclusions = block.get("exclusions") or []
        if exclusions:
            add("- exclusions: " + " ".join(_cell(item) for item in exclusions))
        caveats = block.get("caveats") or []
        if caveats:
            add("- caveats: " + " ".join(_cell(item) for item in caveats))
        add("")
        if composites:
            add("**Composite tools** (reuse audited operations; no new Sophos endpoint):")
            add("")
            add(
                markdown_table(
                    ("Tool", "Kind", "Underlying operationIds", "Description"),
                    composites,
                )
            )
            add("")
        if domain_records:
            add("**Generated inventory** (from `firewall_config_openapi.yaml`):")
            add("")
            add(
                markdown_table(
                    (
                        "operationId",
                        "method",
                        "path",
                        "request content type",
                        "request schema",
                        "responses",
                        "response schema",
                        "pagination",
                        "other query params",
                        "path identifier",
                        "kind",
                        "risk",
                        "MCP tool / exclusion",
                    ),
                    (
                        (
                            _code(record.operation.operation_id),
                            record.operation.method,
                            _code(record.operation.path),
                            record.operation.request_content_type,
                            _schema_cell(record.operation.request_schema),
                            record.operation.response_statuses,
                            _schema_cell(record.operation.response_schema),
                            record.operation.pagination,
                            record.operation.other_query,
                            record.operation.identifier,
                            record.operation.kind,
                            record.operation.risk,
                            record.mcp,
                        )
                        for record in domain_records
                    ),
                )
            )
        else:
            add(
                "**Generated inventory**: none — this domain has no Sophos operation and is "
                "provided entirely by composite tools."
            )
        add("")

    add("## Appendix A — Component schema index")
    add("")
    add(
        "The 32 component schemas referenced by the contract, with their top-level shape and "
        "the number of operations that reference them (directly or through a nested `$ref`)."
    )
    add("")
    component_rows = _component_schema_rows(document)
    add(
        markdown_table(
            ("Schema", "Shape", "Required", "Top-level properties", "Operations"),
            component_rows,
        )
    )
    add("")

    rendered = "\n".join(lines).rstrip("\n") + "\n"
    return rendered


def _flatten_all_of(schema: Any) -> dict[str, Any]:
    """Merge ``allOf`` branches so the appendix can show required/properties."""
    if not isinstance(schema, dict):
        return {"properties": {}, "required": []}
    properties: dict[str, Any] = {}
    required: list[Any] = []
    branches = schema.get("allOf")
    if isinstance(branches, list):
        for branch in branches:
            flattened = _flatten_all_of(branch)
            properties.update(flattened["properties"])
            required.extend(flattened["required"])
    own_properties = schema.get("properties")
    if isinstance(own_properties, dict):
        properties.update(own_properties)
    own_required = schema.get("required")
    if isinstance(own_required, list):
        required.extend(own_required)
    return {"properties": properties, "required": required}


def _component_schema_rows(document: Any) -> list[tuple[str, str, str, str, str]]:
    schemas = (document.get("components") or {}).get("schemas") or {}
    if not isinstance(schemas, dict):
        return []
    usage: Counter[str] = Counter()
    paths = document.get("paths") or {}
    for path_item in paths.values():
        if not isinstance(path_item, dict):
            continue
        for method in HTTP_METHODS:
            raw = path_item.get(method)
            if not isinstance(raw, dict):
                continue
            refs: list[str] = []
            body = raw.get("requestBody") or {}
            content = body.get("content") if isinstance(body, dict) else None
            if isinstance(content, dict):
                for media in content.values():
                    if isinstance(media, dict):
                        collect_refs(media.get("schema"), refs)
            responses = raw.get("responses") or {}
            if isinstance(responses, dict):
                for response in responses.values():
                    if not isinstance(response, dict):
                        continue
                    response_content = response.get("content") or {}
                    if isinstance(response_content, dict):
                        for media in response_content.values():
                            if isinstance(media, dict):
                                collect_refs(media.get("schema"), refs)
            for name in {ref.rsplit("/", 1)[-1] for ref in refs}:
                usage[name] += 1
    rows: list[tuple[str, str, str, str, str]] = []
    for name in sorted(schemas):
        schema = schemas[name]
        resolved = resolve_schema(schema, document)
        shape = schema_shape(resolved)
        flattened = _flatten_all_of(resolved)
        required = list(dict.fromkeys(str(item) for item in flattened["required"]))
        properties = flattened["properties"]
        required_text = ", ".join(required) if required else "—"
        property_text = ", ".join(sorted(properties)) if properties else "—"
        rows.append(
            (
                _code(name),
                shape,
                required_text,
                property_text,
                str(usage.get(name, 0)),
            )
        )
    return rows


# ---------------------------------------------------------------------------
# Generation entry point
# ---------------------------------------------------------------------------
def generate(
    spec_path: Path = DEFAULT_SPEC,
    curated_path: Path = DEFAULT_CURATED,
    accept_sha: bool = False,
) -> tuple[str, SpecFacts, list[Record], Curated]:
    """Return the rendered document and its inputs, enforcing the SHA guard."""
    actual_sha = sha256_file(spec_path)
    if actual_sha != EXPECTED_SPEC_SHA256:
        if not accept_sha:
            raise SpecError(
                "specification SHA-256 mismatch: "
                f"expected {EXPECTED_SPEC_SHA256}, found {actual_sha}. "
                "Review the contract change and rerun with --accept-sha to record it."
            )
        if spec_path.resolve() == DEFAULT_SPEC.resolve():
            update_embedded_sha(actual_sha)
        else:
            print(
                "accepted SHA-256 for a non-default specification; "
                "the embedded constant is unchanged",
                file=sys.stderr,
            )
    document = load_yaml(spec_path)
    if not isinstance(document, dict):
        raise SpecError(f"{spec_path} does not contain an OpenAPI mapping")
    assert_all_refs_resolved(document)
    facts = compute_facts(document, spec_path, actual_sha)
    _validate_facts(facts)
    curated = load_curated(curated_path)
    records = build_records(document, curated)
    rendered = render_document(facts, records, curated, document)
    validate_inventory(records, rendered, document, curated)
    return rendered, facts, records, curated


def _validate_facts(facts: SpecFacts) -> None:
    if facts.openapi != EXPECTED_OPENAPI:
        raise SpecError(f"unexpected OpenAPI version: {facts.openapi}")
    if facts.title != EXPECTED_INFO_TITLE:
        raise SpecError(f"unexpected API title: {facts.title}")
    if facts.version != EXPECTED_INFO_VERSION:
        raise SpecError(f"unexpected API version: {facts.version}")
    if facts.path_count != EXPECTED_PATH_COUNT:
        raise SpecError(f"expected {EXPECTED_PATH_COUNT} paths, found {facts.path_count}")
    if facts.operation_count != EXPECTED_OPERATION_COUNT:
        raise SpecError(
            f"expected {EXPECTED_OPERATION_COUNT} operations, found {facts.operation_count}"
        )
    if facts.unique_operation_ids != EXPECTED_UNIQUE_OPERATION_IDS:
        raise SpecError(
            "expected 700 unique operationIds, found "
            f"{facts.unique_operation_ids} (duplicates: "
            f"{facts.operation_count - facts.unique_operation_ids})"
        )


def update_embedded_sha(new_sha: str) -> None:
    """Record a reviewed specification SHA-256 in this script."""
    text = SCRIPT_PATH.read_text(encoding="utf-8")
    new_text, replacements = SHA_CONSTANT_RE.subn(f'EXPECTED_SPEC_SHA256 = "{new_sha}"', text)
    if replacements != 1:
        raise SpecError("could not locate the embedded SHA-256 constant")
    SCRIPT_PATH.write_text(new_text, encoding="utf-8")


def explain_schema(document: Any, fingerprint: str) -> list[tuple[str, str]]:
    """Return (operationId role, normalized JSON) for a fingerprint."""
    matches: list[tuple[str, str]] = []
    seen: set[str] = set()
    paths = document.get("paths") or {}
    for path in sorted(paths):
        path_item = paths[path]
        if not isinstance(path_item, dict):
            continue
        for method in HTTP_METHODS:
            raw = path_item.get(method)
            if not isinstance(raw, dict):
                continue
            operation_id = str(raw.get("operationId", "?"))
            schemas: list[tuple[str, Any]] = []
            body = raw.get("requestBody") or {}
            content = body.get("content") if isinstance(body, dict) else None
            if isinstance(content, dict):
                for media_type in sorted(content):
                    media = content[media_type]
                    if isinstance(media, dict):
                        schemas.append((f"{operation_id} request", media.get("schema")))
            responses = raw.get("responses") or {}
            if isinstance(responses, dict):
                for status in sorted(responses):
                    response = responses[status]
                    if not isinstance(response, dict):
                        continue
                    response_content = response.get("content") or {}
                    if isinstance(response_content, dict):
                        for media_type in sorted(response_content):
                            media = response_content[media_type]
                            if isinstance(media, dict):
                                schemas.append(
                                    (f"{operation_id} response {status}", media.get("schema"))
                                )
            for label, schema in schemas:
                if not isinstance(schema, dict) or "$ref" in schema:
                    continue
                resolved = resolve_schema(schema, document)
                if schema_fingerprint(resolved) != fingerprint:
                    continue
                normalized = json.dumps(
                    normalize_schema(resolved),
                    sort_keys=True,
                    indent=2,
                    ensure_ascii=False,
                )
                if normalized in seen:
                    continue
                seen.add(normalized)
                matches.append((label, normalized))
    return matches


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate docs/API-COVERAGE.md from firewall_config_openapi.yaml."
    )
    parser.add_argument("--spec", type=Path, default=DEFAULT_SPEC, help="OpenAPI YAML path")
    parser.add_argument(
        "--curated", type=Path, default=DEFAULT_CURATED, help="curated decisions YAML path"
    )
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help="Markdown output path")
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify that the output file matches the generated content; write nothing",
    )
    parser.add_argument(
        "--accept-sha",
        action="store_true",
        help=(
            "accept the current specification SHA-256; records it in this script when the "
            "default specification is used"
        ),
    )
    parser.add_argument(
        "--explain-schema",
        metavar="FINGERPRINT",
        help="print the normalized schema for an inline fingerprint and exit",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if args.explain_schema:
            actual_sha = sha256_file(args.spec)
            if actual_sha != EXPECTED_SPEC_SHA256 and not args.accept_sha:
                raise SpecError(
                    "specification SHA-256 mismatch: "
                    f"expected {EXPECTED_SPEC_SHA256}, found {actual_sha}"
                )
            document = load_yaml(args.spec)
            matches = explain_schema(document, args.explain_schema)
            if not matches:
                raise SpecError(f"no inline schema with fingerprint {args.explain_schema!r}")
            for label, normalized in matches:
                print(f"# {label}")
                print(normalized)
            return 0

        rendered, facts, records, _curated = generate(
            spec_path=args.spec,
            curated_path=args.curated,
            accept_sha=args.accept_sha,
        )
        if args.check:
            if not args.output.exists():
                raise SpecError(f"{args.output} does not exist; run without --check first")
            existing = args.output.read_bytes()
            if existing != rendered.encode("utf-8"):
                raise SpecError(
                    f"{args.output} is out of date; regenerate with "
                    "`uv run --no-sync python scripts/generate_coverage.py`"
                )
            print(f"{args.output} is up to date", file=sys.stderr)
            return 0
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("w", encoding="utf-8", newline="\n") as handle:
            handle.write(rendered)
        domain_summary = ", ".join(
            f"{rule.key}={sum(1 for record in records if record.operation.domain == rule.key)}"
            for rule in DOMAIN_RULES
        )
        print(
            f"wrote {args.output} ({facts.operation_count} operations; {domain_summary})",
            file=sys.stderr,
        )
        return 0
    except SpecError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2 if "SHA-256 mismatch" in str(exc) else 1


if __name__ == "__main__":
    raise SystemExit(main())
