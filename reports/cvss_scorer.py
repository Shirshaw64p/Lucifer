"""CVSS 3.1 Scoring Engine for Lucifer findings.

Auto-maps finding attributes to CVSS 3.1 base metrics and computes
the vector string, numeric score, and severity label using the ``cvss``
Python library.

Usage::

    scorer = CVSSScorer()
    vector, score, label = scorer.score_finding(finding)
"""

from __future__ import annotations

import logging
from typing import Tuple

from cvss import CVSS3

from reports.models import CVSSResult, FindingRecord, Severity

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Metric value mappings — from finding attributes to CVSS abbreviations
# ---------------------------------------------------------------------------

_AV_MAP = {
    "network": "N",
    "adjacent": "A",
    "local": "L",
    "physical": "P",
}

_AC_MAP = {
    "low": "L",
    "high": "H",
}

_PR_MAP = {
    "none": "N",
    "low": "L",
    "high": "H",
}

_UI_MAP = {
    "none": "N",
    "required": "R",
}

_SCOPE_MAP = {
    True: "C",    # Changed
    False: "U",   # Unchanged
}

_IMPACT_MAP = {
    "none": "N",
    "low": "L",
    "high": "H",
}

# Severity → default CVSS metric guesses when attributes are missing
_SEVERITY_DEFAULTS = {
    Severity.CRITICAL: {
        "AV": "N", "AC": "L", "PR": "N", "UI": "N",
        "S": "C", "C": "H", "I": "H", "A": "H",
    },
    Severity.HIGH: {
        "AV": "N", "AC": "L", "PR": "L", "UI": "N",
        "S": "U", "C": "H", "I": "H", "A": "N",
    },
    Severity.MEDIUM: {
        "AV": "N", "AC": "L", "PR": "L", "UI": "R",
        "S": "U", "C": "L", "I": "L", "A": "N",
    },
    Severity.LOW: {
        "AV": "L", "AC": "H", "PR": "L", "UI": "R",
        "S": "U", "C": "L", "I": "N", "A": "N",
    },
    Severity.INFO: {
        "AV": "L", "AC": "H", "PR": "H", "UI": "R",
        "S": "U", "C": "N", "I": "N", "A": "N",
    },
}

# Category-specific overrides for more accurate default scoring
_CATEGORY_AV_OVERRIDES = {
    "INJECTION": {"AV": "N", "AC": "L", "PR": "N", "S": "C", "C": "H", "I": "H"},
    "XSS": {"AV": "N", "AC": "L", "UI": "R", "C": "L", "I": "L"},
    "SSRF": {"AV": "N", "AC": "L", "PR": "L", "S": "C"},
    "XXE": {"AV": "N", "AC": "L", "PR": "N", "C": "H", "I": "L"},
    "IDOR": {"AV": "N", "AC": "L", "PR": "L", "C": "H"},
    "BOLA": {"AV": "N", "AC": "L", "PR": "L", "C": "H"},
    "BFLA": {"AV": "N", "AC": "L", "PR": "L", "C": "H", "I": "H"},
    "BROKEN_AUTH": {"AV": "N", "AC": "L", "PR": "N", "C": "H", "I": "H"},
    "JWT_VULNERABILITY": {"AV": "N", "AC": "L", "PR": "N", "C": "H", "I": "H"},
    "MASS_ASSIGNMENT": {"AV": "N", "AC": "L", "PR": "L", "I": "H"},
    "INSECURE_DESERIALIZATION": {"AV": "N", "AC": "L", "PR": "N", "S": "C", "C": "H", "I": "H", "A": "H"},
    "CRYPTOGRAPHIC_FAILURE": {"AV": "N", "AC": "H", "PR": "N", "C": "H"},
    "NETWORK_EXPOSURE": {"AV": "N", "AC": "L", "PR": "N"},
    "CLOUD_MISCONFIGURATION": {"AV": "N", "AC": "L", "PR": "N"},
    "SECURITY_MISCONFIGURATION": {"AV": "N", "AC": "L", "PR": "N"},
    "SENSITIVE_DATA_EXPOSURE": {"AV": "N", "AC": "L", "PR": "N", "C": "H"},
    "INSUFFICIENT_LOGGING": {"AV": "N", "AC": "H", "PR": "H", "C": "N", "I": "L", "A": "N"},
    "BROKEN_ACCESS_CONTROL": {"AV": "N", "AC": "L", "PR": "L", "C": "H", "I": "H"},
}


class CVSSScorer:
    """Compute CVSS 3.1 scores for Lucifer findings.

    Each finding may optionally carry explicit metric attributes
    (``attack_vector``, ``privileges_required``, etc.).  When those
    are missing the scorer uses intelligent defaults based on severity
    and vulnerability category.
    """

    def score_finding(self, finding: FindingRecord) -> CVSSResult:
        """Score a single finding.

        Returns:
            A :class:`CVSSResult` containing the CVSS vector string,
            numeric score, and severity label.
        """
        metrics = self._build_metrics(finding)
        vector_string = self._metrics_to_vector(metrics)

        try:
            c = CVSS3(vector_string)
            numeric_score = c.base_score
            severity_label = self._label_from_score(numeric_score)
        except Exception as exc:
            logger.warning("CVSS calculation failed for finding %s: %s", finding.id, exc)
            numeric_score = 0.0
            severity_label = "None"

        logger.debug(
            "CVSS scored finding %s: %s → %.1f (%s)",
            finding.id, vector_string, numeric_score, severity_label,
        )

        return CVSSResult(
            finding_id=finding.id,
            vector_string=vector_string,
            numeric_score=numeric_score,
            severity_label=severity_label,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_metrics(self, finding: FindingRecord) -> dict:
        """Resolve CVSS metric values from explicit attributes, category
        overrides, or severity-based defaults (in that priority order).
        """
        severity = finding.severity or Severity.MEDIUM
        defaults = dict(_SEVERITY_DEFAULTS.get(severity, _SEVERITY_DEFAULTS[Severity.MEDIUM]))

        # Apply category overrides
        category = (finding.vuln_category or "").upper().strip()
        if category in _CATEGORY_AV_OVERRIDES:
            defaults.update(_CATEGORY_AV_OVERRIDES[category])

        # Resolve each metric — explicit value wins over default
        av = _AV_MAP.get((finding.attack_vector or "").lower(), defaults["AV"])
        ac = _AC_MAP.get("low", defaults["AC"])  # AC is rarely set explicitly
        pr = _PR_MAP.get((finding.privileges_required or "").lower(), defaults["PR"])
        ui = _UI_MAP.get((finding.user_interaction or "").lower(), defaults.get("UI", "N"))
        s = _SCOPE_MAP.get(finding.scope_changed, None) or defaults.get("S", "U")
        c = _IMPACT_MAP.get((finding.confidentiality_impact or "").lower(), defaults.get("C", "N"))
        i = _IMPACT_MAP.get((finding.integrity_impact or "").lower(), defaults.get("I", "N"))
        a = _IMPACT_MAP.get((finding.availability_impact or "").lower(), defaults.get("A", "N"))

        return {"AV": av, "AC": ac, "PR": pr, "UI": ui, "S": s, "C": c, "I": i, "A": a}

    @staticmethod
    def _metrics_to_vector(metrics: dict) -> str:
        """Build a CVSS 3.1 vector string from a dict of metric abbreviations."""
        return (
            f"CVSS:3.1/AV:{metrics['AV']}/AC:{metrics['AC']}"
            f"/PR:{metrics['PR']}/UI:{metrics['UI']}/S:{metrics['S']}"
            f"/C:{metrics['C']}/I:{metrics['I']}/A:{metrics['A']}"
        )

    @staticmethod
    def _label_from_score(score: float) -> str:
        """Map a numeric CVSS score to a severity label."""
        if score >= 9.0:
            return "Critical"
        if score >= 7.0:
            return "High"
        if score >= 4.0:
            return "Medium"
        if score >= 0.1:
            return "Low"
        return "None"
