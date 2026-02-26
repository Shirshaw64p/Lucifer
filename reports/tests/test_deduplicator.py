"""Test suite for FindingDeduplicator.

Validates 3 duplicate finding scenarios:
1. Exact duplicates (same category, URL, title) — should merge
2. Same category + URL but different description — should NOT merge
3. Multiple overlapping duplicates — correct group merging
"""

from __future__ import annotations

import uuid

import pytest

from reports.deduplicator import FindingDeduplicator
from reports.models import EvidenceRef, FindingRecord, Severity


def _make_finding(
    title: str = "Test Finding",
    severity: Severity = Severity.HIGH,
    vuln_category: str = "INJECTION",
    endpoint_url: str = "https://example.com/api/login",
    description: str = "SQL injection vulnerability.",
    agent_name: str | None = None,
    evidence: list[EvidenceRef] | None = None,
) -> FindingRecord:
    return FindingRecord(
        id=uuid.uuid4(),
        run_id=uuid.uuid4(),
        title=title,
        severity=severity,
        description=description,
        vuln_category=vuln_category,
        endpoint_url=endpoint_url,
        agent_name=agent_name,
        evidence=evidence or [],
    )


@pytest.fixture
def dedup() -> FindingDeduplicator:
    return FindingDeduplicator()


# ---------------------------------------------------------------------------
# Test 1: Exact duplicates — same title, category, URL
# ---------------------------------------------------------------------------

def test_exact_duplicates_merged(dedup: FindingDeduplicator):
    """Two findings with identical category, URL, and near-identical
    title/description should be merged into one.
    """
    f1 = _make_finding(
        title="SQL Injection in Login Endpoint",
        description="The /api/login endpoint is vulnerable to SQL injection.",
        severity=Severity.HIGH,
        agent_name="recon-agent",
        evidence=[
            EvidenceRef(
                artifact_id=uuid.uuid4(),
                artifact_type="screenshot",
                storage_path="/ev/sqli1.png",
            )
        ],
    )
    f2 = _make_finding(
        title="SQL Injection in Login Endpoint",
        description="The /api/login endpoint is vulnerable to SQL injection.",
        severity=Severity.CRITICAL,
        agent_name="exploit-agent",
        evidence=[
            EvidenceRef(
                artifact_id=uuid.uuid4(),
                artifact_type="log",
                storage_path="/ev/sqli2.har",
            )
        ],
    )

    result = dedup.deduplicate([f1, f2])

    assert len(result) == 1, f"Expected 1 merged finding, got {len(result)}"
    merged = result[0]
    # Should keep the higher severity
    assert merged.severity == Severity.CRITICAL
    # Should combine evidence from both
    assert len(merged.evidence) == 2
    # Should note both agents
    assert "recon-agent" in merged.description
    assert "exploit-agent" in merged.description


# ---------------------------------------------------------------------------
# Test 2: Same category + URL but different description (below threshold)
# ---------------------------------------------------------------------------

def test_different_descriptions_not_merged(dedup: FindingDeduplicator):
    """Findings with the same URL and category but substantially different
    descriptions should NOT be merged.
    """
    f1 = _make_finding(
        title="SQL Injection in Login Endpoint",
        description="The login form allows SQL injection via the username field.",
        vuln_category="INJECTION",
        endpoint_url="https://example.com/api/login",
    )
    f2 = _make_finding(
        title="Server-Side Request Forgery in Image Upload",
        description="The image upload feature allows server-side request forgery to internal services.",
        vuln_category="SSRF",
        endpoint_url="https://example.com/api/upload",
    )

    result = dedup.deduplicate([f1, f2])

    assert len(result) == 2, f"Expected 2 separate findings, got {len(result)}"


# ---------------------------------------------------------------------------
# Test 3: Multiple overlapping duplicates
# ---------------------------------------------------------------------------

def test_multiple_overlapping_duplicates(dedup: FindingDeduplicator):
    """Three findings from different agents all reporting the same vuln
    should collapse to one.
    """
    base_kwargs = dict(
        title="Broken Authentication on Admin Panel",
        description="Admin panel authentication can be bypassed.",
        vuln_category="BROKEN_AUTH",
        endpoint_url="https://example.com/admin",
    )

    f1 = _make_finding(severity=Severity.HIGH, agent_name="agent-A", **base_kwargs)
    f2 = _make_finding(severity=Severity.MEDIUM, agent_name="agent-B", **base_kwargs)
    f3 = _make_finding(severity=Severity.CRITICAL, agent_name="agent-C", **base_kwargs)

    result = dedup.deduplicate([f1, f2, f3])

    assert len(result) == 1
    merged = result[0]
    assert merged.severity == Severity.CRITICAL  # highest wins
    assert "agent-A" in merged.description
    assert "agent-B" in merged.description
    assert "agent-C" in merged.description


# ---------------------------------------------------------------------------
# Additional edge cases
# ---------------------------------------------------------------------------

def test_single_finding_unchanged(dedup: FindingDeduplicator):
    """A single finding should pass through untouched."""
    f = _make_finding()
    result = dedup.deduplicate([f])
    assert len(result) == 1
    assert result[0].id == f.id


def test_empty_list(dedup: FindingDeduplicator):
    """Empty input should return empty output."""
    assert dedup.deduplicate([]) == []


def test_different_categories_not_merged(dedup: FindingDeduplicator):
    """Findings with different categories but same URL should not merge."""
    f1 = _make_finding(
        vuln_category="INJECTION",
        endpoint_url="https://example.com/api/data",
        title="SQL Injection in Data Endpoint",
        description="SQL injection vulnerability in the data API.",
    )
    f2 = _make_finding(
        vuln_category="XSS",
        endpoint_url="https://example.com/api/data",
        title="XSS in Data Endpoint",
        description="Cross-site scripting vulnerability in the data API.",
    )

    result = dedup.deduplicate([f1, f2])
    assert len(result) == 2


def test_url_normalization(dedup: FindingDeduplicator):
    """Findings with equivalent URLs (different schemes/trailing slashes)
    but same category and text should merge.
    """
    f1 = _make_finding(
        title="Broken Auth on Login",
        description="Authentication bypass on login page.",
        vuln_category="BROKEN_AUTH",
        endpoint_url="https://example.com/login/",
        severity=Severity.HIGH,
    )
    f2 = _make_finding(
        title="Broken Auth on Login",
        description="Authentication bypass on login page.",
        vuln_category="BROKEN_AUTH",
        endpoint_url="http://example.com/login",
        severity=Severity.MEDIUM,
    )

    result = dedup.deduplicate([f1, f2])
    assert len(result) == 1
    assert result[0].severity == Severity.HIGH
