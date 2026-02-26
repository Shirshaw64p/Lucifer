"""Test suite for CVSSScorer.

Validates 5 known findings produce correct CVSS scores by comparing
against hand-calculated vector strings and expected score ranges.
"""

from __future__ import annotations

import uuid

import pytest

from reports.cvss_scorer import CVSSScorer
from reports.models import FindingRecord, Severity


@pytest.fixture(scope="module")
def scorer() -> CVSSScorer:
    return CVSSScorer()


def _make_finding(**kwargs) -> FindingRecord:
    defaults = dict(
        id=uuid.uuid4(),
        run_id=uuid.uuid4(),
        title="Test Finding",
        severity=Severity.HIGH,
        description="Test description.",
    )
    defaults.update(kwargs)
    return FindingRecord(**defaults)


# ---------------------------------------------------------------------------
# Test 1: Critical RCE via Injection (network, no auth, scope changed)
# Expected: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H → 10.0 Critical
# ---------------------------------------------------------------------------

def test_critical_injection_rce(scorer: CVSSScorer):
    finding = _make_finding(
        title="Remote Code Execution via SQL Injection",
        severity=Severity.CRITICAL,
        vuln_category="INJECTION",
        attack_vector="network",
        privileges_required="none",
        user_interaction="none",
        scope_changed=True,
        confidentiality_impact="high",
        integrity_impact="high",
        availability_impact="high",
    )
    result = scorer.score_finding(finding)

    assert result.vector_string == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    assert result.numeric_score == 10.0
    assert result.severity_label == "Critical"


# ---------------------------------------------------------------------------
# Test 2: High severity IDOR (network, low priv, C:H)
# Expected: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N → 6.5 Medium
# ---------------------------------------------------------------------------

def test_high_idor(scorer: CVSSScorer):
    finding = _make_finding(
        title="IDOR — Accessing Other Users' Records",
        severity=Severity.HIGH,
        vuln_category="IDOR",
        attack_vector="network",
        privileges_required="low",
        user_interaction="none",
        scope_changed=False,
        confidentiality_impact="high",
        integrity_impact="none",
        availability_impact="none",
    )
    result = scorer.score_finding(finding)

    assert result.vector_string == "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"
    assert result.numeric_score == 6.5
    assert result.severity_label == "Medium"


# ---------------------------------------------------------------------------
# Test 3: Medium XSS — reflected (network, no priv, requires user click)
# Expected: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N → 5.4 Medium
# ---------------------------------------------------------------------------

def test_medium_reflected_xss(scorer: CVSSScorer):
    finding = _make_finding(
        title="Reflected XSS in Search Parameter",
        severity=Severity.MEDIUM,
        vuln_category="XSS",
        attack_vector="network",
        privileges_required="none",
        user_interaction="required",
        scope_changed=False,
        confidentiality_impact="low",
        integrity_impact="low",
        availability_impact="none",
    )
    result = scorer.score_finding(finding)

    assert result.vector_string == "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"
    assert result.numeric_score == 5.4
    assert result.severity_label == "Medium"


# ---------------------------------------------------------------------------
# Test 4: Low info disclosure — local, high complexity
# Expected: CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N → 2.0 Low
# ---------------------------------------------------------------------------

def test_low_info_disclosure(scorer: CVSSScorer):
    finding = _make_finding(
        title="Local Information Disclosure",
        severity=Severity.LOW,
        vuln_category="SENSITIVE_DATA_EXPOSURE",
        attack_vector="local",
        privileges_required="low",
        user_interaction="required",
        scope_changed=False,
        confidentiality_impact="low",
        integrity_impact="none",
        availability_impact="none",
    )
    result = scorer.score_finding(finding)

    assert result.vector_string == "CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:L/I:N/A:N"
    # Score should be in Low range (0.1-3.9)
    assert 0.1 <= result.numeric_score <= 3.9, f"Score {result.numeric_score} not in Low range"
    assert result.severity_label == "Low"


# ---------------------------------------------------------------------------
# Test 5: Auto-scored finding with no explicit metrics (uses category defaults)
# Insecure Deserialization defaulting to Critical
# ---------------------------------------------------------------------------

def test_auto_scored_insecure_deserialization(scorer: CVSSScorer):
    """A finding with no explicit metrics should use category defaults."""
    finding = _make_finding(
        title="Insecure Deserialization in API Endpoint",
        severity=Severity.CRITICAL,
        vuln_category="INSECURE_DESERIALIZATION",
        # No explicit CVSS attributes — should use category defaults
    )
    result = scorer.score_finding(finding)

    assert result.vector_string.startswith("CVSS:3.1/")
    # Insecure deserialization defaults: AV:N/AC:L/PR:N/S:C/C:H/I:H/A:H → 10.0
    assert result.numeric_score >= 9.0, (
        f"Expected Critical score for INSECURE_DESERIALIZATION, got {result.numeric_score}"
    )
    assert result.severity_label == "Critical"


# ---------------------------------------------------------------------------
# Additional validation tests
# ---------------------------------------------------------------------------

def test_score_finding_returns_cvss_result(scorer: CVSSScorer):
    """Verify the return type has the expected fields."""
    finding = _make_finding(vuln_category="XSS")
    result = scorer.score_finding(finding)

    assert hasattr(result, "finding_id")
    assert hasattr(result, "vector_string")
    assert hasattr(result, "numeric_score")
    assert hasattr(result, "severity_label")
    assert result.finding_id == finding.id


def test_info_severity_produces_low_score(scorer: CVSSScorer):
    """Info-level findings should score near zero."""
    finding = _make_finding(
        severity=Severity.INFO,
        vuln_category="INSUFFICIENT_LOGGING",
    )
    result = scorer.score_finding(finding)
    assert result.numeric_score <= 4.0
