"""Static tests for the deterministic API coverage generator.

These tests never contact a firewall and never need credentials: they parse the
checked-in OpenAPI contract, regenerate the coverage document and compare the
result with the committed file.
"""

from __future__ import annotations

import hashlib
import importlib.util
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
GENERATOR_PATH = ROOT / "scripts" / "generate_coverage.py"
CURATED_PATH = ROOT / "scripts" / "coverage_curated.yaml"
SPEC_PATH = ROOT / "firewall_config_openapi.yaml"
DOC_PATH = ROOT / "docs" / "API-COVERAGE.md"
LIVE_README = ROOT / "docs" / "live-evidence" / "README.md"

EXPECTED_SHA256 = "58c4bc79ac930ce030202e09835865dcb12fcd44e9132e1f4234a1ed1743b1d5"
EXPECTED_OPERATION_COUNT = 700
EXPECTED_PATH_COUNT = 384
EXPECTED_METHOD_COUNTS = {"GET": 263, "POST": 210, "PATCH": 134, "DELETE": 93}
HTTP_METHODS = ("get", "post", "patch", "delete")
METHOD_ORDER = {method.upper(): index for index, method in enumerate(HTTP_METHODS)}
INLINE_SCHEMA_RE = re.compile(r"^inline:.+#[0-9a-f]{8}$")
ROW_RE = re.compile(r"^\| `([A-Za-z][A-Za-z0-9]*)` \| (GET|POST|PATCH|DELETE) \| `([^`]+)` \|")
HEADING_RE = re.compile(r"^### 5\.(\d+) (.+) \((\d+) operations\)$")


def _load_generator() -> Any:
    spec = importlib.util.spec_from_file_location("generate_coverage", GENERATOR_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _load_yaml(path: Path) -> Any:
    loader = getattr(yaml, "CSafeLoader", yaml.SafeLoader)
    with path.open("rb") as handle:
        return yaml.load(handle, Loader=loader)


def _iter_operations(document: Any) -> list[dict[str, str]]:
    operations: list[dict[str, str]] = []
    for path, path_item in document["paths"].items():
        for method in HTTP_METHODS:
            raw = path_item.get(method)
            if not isinstance(raw, dict):
                continue
            operations.append(
                {
                    "operationId": raw["operationId"],
                    "method": method.upper(),
                    "path": path,
                }
            )
    return operations


def _parse_rows(document_text: str) -> list[tuple[str, str, str]]:
    rows: list[tuple[str, str, str]] = []
    for line in document_text.splitlines():
        match = ROW_RE.match(line)
        if match:
            rows.append((match.group(1), match.group(2), match.group(3)))
    return rows


def _parse_row_cells(line: str) -> list[str]:
    assert line.startswith("| ") and line.endswith(" |")
    return [cell.strip() for cell in line[2:-2].split(" | ")]


def _run_generator(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(GENERATOR_PATH), *arguments],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )


@pytest.fixture(scope="session")
def generator() -> Any:
    return _load_generator()


@pytest.fixture(scope="session")
def openapi() -> Any:
    return _load_yaml(SPEC_PATH)


@pytest.fixture(scope="session")
def curated() -> Any:
    return _load_yaml(CURATED_PATH)


@pytest.fixture(scope="session")
def generated(tmp_path_factory: pytest.TempPathFactory) -> str:
    output = tmp_path_factory.mktemp("coverage") / "API-COVERAGE.md"
    result = _run_generator("--output", str(output))
    assert result.returncode == 0, result.stderr
    return output.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Specification baseline and reference resolution
# ---------------------------------------------------------------------------
def test_spec_sha_matches_embedded_constant(generator: Any) -> None:
    digest = hashlib.sha256(SPEC_PATH.read_bytes()).hexdigest()
    assert digest == EXPECTED_SHA256
    assert generator.EXPECTED_SPEC_SHA256 == EXPECTED_SHA256


def test_full_parse_and_baseline(openapi: Any) -> None:
    assert openapi["openapi"] == "3.0.0"
    assert openapi["info"]["title"] == "Sophos Firewall Configuration API"
    assert openapi["info"]["version"] == "1.0.0"
    assert len(openapi["paths"]) == EXPECTED_PATH_COUNT
    operations = _iter_operations(openapi)
    assert len(operations) == EXPECTED_OPERATION_COUNT
    operation_ids = [operation["operationId"] for operation in operations]
    assert len(operation_ids) == len(set(operation_ids)) == EXPECTED_OPERATION_COUNT
    method_counts: dict[str, int] = {}
    for operation in operations:
        method_counts[operation["method"]] = method_counts.get(operation["method"], 0) + 1
    assert method_counts == EXPECTED_METHOD_COUNTS
    assert len(openapi["components"]["schemas"]) == 32


def test_every_reference_is_local_and_resolved(generator: Any, openapi: Any) -> None:
    refs: list[str] = []
    generator.collect_refs(openapi, refs)
    assert len(refs) == generator.EXPECTED_REF_OCCURRENCES == 76
    assert len(set(refs)) == generator.EXPECTED_UNIQUE_REFS == 32
    for ref in set(refs):
        assert ref.startswith("#/components/schemas/")
        generator.resolve_pointer(openapi, ref)
    resolved = generator.resolve_schema(openapi, openapi)
    remaining: list[str] = []
    generator.collect_refs(resolved, remaining)
    assert remaining == []


# ---------------------------------------------------------------------------
# Curated decisions
# ---------------------------------------------------------------------------
def test_curated_decisions_present(generator: Any, curated: Any) -> None:
    assert curated["version"] == 1
    assert list(curated["domains"]) == list(generator.DOMAIN_ORDER)
    assert len(curated["tool_map"]) == 96
    assert len(set(curated["tool_map"].values())) == 96
    operations = _iter_operations(_load_yaml(SPEC_PATH))
    known = {operation["operationId"] for operation in operations}
    assert set(curated["tool_map"]) <= known

    patch_exceptions = {item["operation_id"] for item in curated["patch"]["exceptions"]}
    assert patch_exceptions == {
        "patchMessages",
        "updateCentralFirewallReportingLogComponents",
        "updateSyslogServerLogs",
        "updateAlertNotificationSettings",
    }
    assert patch_exceptions <= known

    rule_ids = {rule["id"] for rule in curated["exclusion_rules"]}
    assert {
        "bulk_delete",
        "administrators_crud",
        "user_groups",
        "vpn_mutations",
        "interface_mutations",
        "country_groups",
        "mac_objects",
        "login_logout",
    } <= rule_ids
    for rule in curated["exclusion_rules"]:
        assert rule["reason"].strip()

    scope_text = " ".join(block["v1_scope"] for block in curated["domains"].values())
    assert "WAF" in scope_text or any(
        "WAF" in item
        for block in curated["domains"].values()
        for item in block.get("exclusions", [])
    )
    assert any("bulk" in rule["reason"].lower() for rule in curated["exclusion_rules"])
    assert "read-only" in curated["domains"]["ipsec_vpn"]["v1_scope"].lower()
    assert "read-only" in curated["domains"]["interfaces"]["v1_scope"].lower()

    pagination_rules = " ".join(curated["pagination"]["rules"])
    assert "page >= 1" in pagination_rules
    assert "1 <= pageSize <= 100" in pagination_rules
    assert "pageTotal" in pagination_rules

    identifier_text = " ".join(curated["identifiers"]["formats"])
    for name_format in (
        "sfos-object-name",
        "sfos-object-name-or-id",
        "sfos-object-name-lenient",
        "sfos-object-name-lenient-or-id",
    ):
        assert name_format in identifier_text

    assert "error" in curated["errors"]["envelope"]
    observations = {item["id"]: item for item in curated["live_observations"]}
    assert "live_users_pagination" in observations
    live_users = observations["live_users_pagination"]
    for token in ("page", "pageSize", "pageTotal", "100", "invalidPageSizeParam"):
        assert token in live_users["statement"]
    assert "does not expose" in live_users["decision"]
    assert "page_zero" in observations
    assert "error_envelopes" in observations
    assert curated["firmware"]["status"].strip()


# ---------------------------------------------------------------------------
# Document completeness and determinism
# ---------------------------------------------------------------------------
def test_every_operation_is_represented_exactly_once(openapi: Any, generated: str) -> None:
    expected = _iter_operations(openapi)
    rows = _parse_rows(generated)
    assert len(rows) == EXPECTED_OPERATION_COUNT
    assert len({row[0] for row in rows}) == EXPECTED_OPERATION_COUNT
    expected_set = {
        (operation["operationId"], operation["method"], operation["path"]) for operation in expected
    }
    assert set(rows) == expected_set


def test_rows_are_grouped_by_domain_and_sorted(generator: Any, generated: str) -> None:
    lines = generated.splitlines()
    sections: dict[str, list[tuple[str, str, str]]] = {}
    current: str | None = None
    declared_counts: dict[str, int] = {}
    title_to_key = {title: key for key, title in generator.DOMAIN_TITLES.items()}
    for line in lines:
        heading = HEADING_RE.match(line)
        if heading:
            title = heading.group(2)
            assert title in title_to_key, f"unknown domain heading: {title}"
            current = title_to_key[title]
            declared_counts[current] = int(heading.group(3))
            sections[current] = []
            continue
        if line.startswith("## ") and current is not None:
            current = None
        row = ROW_RE.match(line)
        if row and current is not None:
            sections[current].append((row.group(1), row.group(2), row.group(3)))
    assert set(sections) == set(generator.DOMAIN_ORDER)
    assert sum(declared_counts.values()) == EXPECTED_OPERATION_COUNT
    for key, rows in sections.items():
        assert rows, f"domain {key} has no rows"
        assert len(rows) == declared_counts[key]
        order = [(path, METHOD_ORDER[method]) for _operation_id, method, path in rows]
        assert order == sorted(order), f"domain {key} rows are not sorted"
        for _operation_id, _method, path in rows:
            assert generator.domain_for_path(path) == key


def test_every_row_records_required_fields(generator: Any, openapi: Any, generated: str) -> None:
    component_names = set(openapi["components"]["schemas"])
    for line in generated.splitlines():
        if not ROW_RE.match(line):
            continue
        cells = _parse_row_cells(line)
        assert len(cells) == 13, f"unexpected column count: {line[:80]}"
        (
            operation_id,
            method,
            path,
            request_content_type,
            request_schema,
            responses,
            response_schema,
            pagination,
            other_query,
            identifier,
            kind,
            risk,
            mcp,
        ) = cells
        assert operation_id.startswith("`") and operation_id.endswith("`")
        assert method in {"GET", "POST", "PATCH", "DELETE"}
        assert path.startswith("`/") and path.endswith("`")
        assert request_content_type in {
            "none",
            "application/json",
            "multipart/form-data",
            "application/json,multipart/form-data",
        }
        for schema in (request_schema, response_schema):
            if schema == "none":
                continue
            if schema.startswith("`"):
                label = schema.strip("`")
                if label.startswith("inline:"):
                    assert INLINE_SCHEMA_RE.match(label), label
                else:
                    assert label in component_names, label
            else:
                pytest.fail(f"schema cell is not labelled: {schema!r}")
        assert responses and all(part.isdigit() for part in responses.split(","))
        assert pagination == "none" or set(pagination.split(",")) <= {
            "page",
            "pageSize",
            "pageTotal",
        }
        assert other_query == "none" or other_query
        assert identifier in {
            "none",
            "sfos-object-name-or-id",
            "lenient",
            "uuid",
            "untyped",
        }
        assert kind in {"read", "mutation"}
        assert risk
        assert mcp.startswith("`") or mcp.startswith("excluded: ")


def test_document_documents_the_mapping_rule(generator: Any, generated: str) -> None:
    assert "## 3. Domain mapping rule" in generated
    for rule in generator.DOMAIN_RULES:
        assert rule.rule in generated
        assert rule.title in generated
    assert "first matching rule wins" in generated
    assert "GET, POST, PATCH, DELETE" in generated


def test_deterministic_regeneration(generated: str, tmp_path: Path) -> None:
    first = tmp_path / "first.md"
    second = tmp_path / "second.md"
    for output in (first, second):
        result = _run_generator("--output", str(output))
        assert result.returncode == 0, result.stderr
    assert first.read_bytes() == second.read_bytes()
    assert first.read_text(encoding="utf-8") == generated
    assert DOC_PATH.read_text(encoding="utf-8") == generated


def test_check_mode_reports_no_drift() -> None:
    result = _run_generator("--check")
    assert result.returncode == 0, result.stderr


def test_explain_schema_expands_a_fingerprint(generated: str) -> None:
    match = re.search(r"`(inline:object\{items,pages\}#[0-9a-f]{8})`", generated)
    assert match is not None
    fingerprint = match.group(1).rsplit("#", 1)[1]
    result = _run_generator("--explain-schema", fingerprint)
    assert result.returncode == 0, result.stderr
    assert '"items"' in result.stdout
    assert '"pages"' in result.stdout


# ---------------------------------------------------------------------------
# SHA guard and inventory refusal
# ---------------------------------------------------------------------------
def _write_modified_spec(target: Path) -> None:
    data = SPEC_PATH.read_bytes()
    marker = b"Programmatically manage"
    assert marker in data
    modified = data.replace(marker, b"Xrogrammatically manage", 1)
    assert len(modified) == len(data)
    target.write_bytes(modified)


def test_sha_guard_refuses_a_modified_spec(tmp_path: Path) -> None:
    modified = tmp_path / "modified.yaml"
    _write_modified_spec(modified)
    output = tmp_path / "coverage.md"
    result = _run_generator("--spec", str(modified), "--output", str(output))
    assert result.returncode == 2
    assert "SHA-256 mismatch" in result.stderr
    assert not output.exists()


def test_accept_sha_allows_a_reviewed_spec_without_rewriting_the_script(
    tmp_path: Path,
) -> None:
    modified = tmp_path / "modified.yaml"
    _write_modified_spec(modified)
    output = tmp_path / "coverage.md"
    before = GENERATOR_PATH.read_bytes()
    result = _run_generator("--spec", str(modified), "--accept-sha", "--output", str(output))
    assert result.returncode == 0, result.stderr
    assert output.exists()
    assert GENERATOR_PATH.read_bytes() == before


def test_inventory_refuses_missing_or_duplicate_operations(generator: Any) -> None:
    document = _load_yaml(SPEC_PATH)
    curated = generator.load_curated(CURATED_PATH)
    records = generator.build_records(document, curated)
    facts = generator.compute_facts(document, SPEC_PATH, EXPECTED_SHA256)
    rendered = generator.render_document(facts, records, curated, document)
    generator.validate_inventory(records, rendered, document)

    with pytest.raises(generator.SpecError):
        generator.validate_inventory(records[:-1], rendered, document)

    with pytest.raises(generator.SpecError):
        generator.validate_inventory(records + [records[0]], rendered, document)

    first_row = next(line for line in rendered.splitlines() if ROW_RE.match(line))
    with pytest.raises(generator.SpecError):
        generator.validate_inventory(records, rendered.replace(first_row + "\n", "", 1), document)


# ---------------------------------------------------------------------------
# Live evidence protocol documentation
# ---------------------------------------------------------------------------
def test_live_evidence_protocol_is_documented() -> None:
    text = LIVE_README.read_text(encoding="utf-8")
    lowered = text.lower()
    for token in (
        "pytest -m live",
        "sophos_host",
        "sophos_port",
        "sophos_api_key",
        "read-only",
        "appliance model",
        "sfos build",
        "administrator profile",
        "allowlist",
        "operationids",
        "deferral",
    ):
        assert token in lowered, f"missing live-evidence token: {token}"
    assert "docs/live-evidence/<domain>.md" in text
    assert "never writes" in text.lower() or "no writes" in text.lower()


def test_live_evidence_links_exist() -> None:
    assert (ROOT / "docs" / "live-evidence" / "api-smoke-2026-11-15.md").is_file()
    assert LIVE_README.is_file()


def test_curated_file_has_no_generated_operation_rows() -> None:
    text = CURATED_PATH.read_text(encoding="utf-8")
    assert "| `" not in text
    assert "inline:" not in text


def test_generator_has_no_hardcoded_timestamp(generated: str) -> None:
    assert "Generated on" not in generated
    assert "generated at" not in generated.lower()
    assert re.search(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}", generated) is None
