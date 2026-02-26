"""Test suite for ComplianceEngine.

Validates that all 18 vulnerability categories map correctly to at
least one control per framework (SOC 2, PCI-DSS, HIPAA, ISO 27001).
"""

from __future__ import annotations

import uuid

import pytest

from reports.compliance_engine import ComplianceEngine, FRAMEWORKS
from reports.models import FindingRecord, Severity, VulnCategory


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def engine() -> ComplianceEngine:
    eng = ComplianceEngine()
    eng.load_rules()
    return eng


def _make_finding(category: str, severity: Severity = Severity.HIGH) -> FindingRecord:
    return FindingRecord(
        id=uuid.uuid4(),
        run_id=uuid.uuid4(),
        title=f"Test finding: {category}",
        severity=severity,
        description=f"Synthetic finding for {category} testing.",
        vuln_category=category,
    )


# ---------------------------------------------------------------------------
# Per-category mapping tests (all 18 categories)
# ---------------------------------------------------------------------------

ALL_CATEGORIES = [c.value for c in VulnCategory]


@pytest.mark.parametrize("category", ALL_CATEGORIES)
def test_category_maps_to_all_frameworks(engine: ComplianceEngine, category: str):
    """Every category must map to ≥1 control in each of the 4 frameworks."""
    finding = _make_finding(category)
    mapping = engine.map_finding(finding)

    for fw in FRAMEWORKS:
        controls = getattr(mapping, fw)
        assert len(controls) >= 1, (
            f"{category} has no controls for {fw}. "
            f"Expected at least 1 mapping."
        )


@pytest.mark.parametrize("category", ALL_CATEGORIES)
def test_category_control_ids_are_non_empty(engine: ComplianceEngine, category: str):
    """Each mapped control must have a non-empty control_id."""
    finding = _make_finding(category)
    mapping = engine.map_finding(finding)

    for fw in FRAMEWORKS:
        for ctrl in getattr(mapping, fw):
            assert ctrl.control_id, (
                f"{category}/{fw}: control_id is empty."
            )


# ---------------------------------------------------------------------------
# Control matrix tests
# ---------------------------------------------------------------------------

def test_control_matrix_marks_triggered_as_fail(engine: ComplianceEngine):
    """Findings that trigger a control should mark it as FAIL."""
    findings = [_make_finding("INJECTION")]
    matrix = engine.generate_control_matrix(findings)

    fail_entries = [e for e in matrix.entries if e.status.value == "fail"]
    assert len(fail_entries) > 0, "Expected at least one FAIL entry."


def test_control_matrix_includes_pass_entries(engine: ComplianceEngine):
    """Controls not triggered by any finding should remain PASS."""
    findings = [_make_finding("INJECTION")]
    matrix = engine.generate_control_matrix(findings)

    pass_entries = [e for e in matrix.entries if e.status.value == "pass"]
    assert len(pass_entries) > 0, "Expected at least one PASS entry."


def test_control_matrix_empty_findings(engine: ComplianceEngine):
    """An empty findings list should yield all-PASS entries."""
    matrix = engine.generate_control_matrix([])
    fail_entries = [e for e in matrix.entries if e.status.value == "fail"]
    assert len(fail_entries) == 0


# ---------------------------------------------------------------------------
# Export test
# ---------------------------------------------------------------------------

def test_export_mapping_structure(engine: ComplianceEngine):
    """export_mapping returns expected dict keys."""
    run_id = uuid.uuid4()
    findings = [_make_finding("XSS"), _make_finding("SSRF")]
    export = engine.export_mapping(run_id, findings)

    assert "run_id" in export
    assert "per_finding" in export
    assert "control_matrix" in export
    assert len(export["per_finding"]) == 2


# ---------------------------------------------------------------------------
# Edge case: unknown category
# ---------------------------------------------------------------------------

def test_unknown_category_returns_empty_mapping(engine: ComplianceEngine):
    """An unknown vuln_category should return empty control lists."""
    finding = _make_finding("TOTALLY_UNKNOWN_CATEGORY")
    mapping = engine.map_finding(finding)

    for fw in FRAMEWORKS:
        assert len(getattr(mapping, fw)) == 0
