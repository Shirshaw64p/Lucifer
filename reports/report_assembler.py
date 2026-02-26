"""Report Assembler — orchestrates all report components into a final deliverable.

Pulls together:
- Confirmed findings (from DB or in-memory)
- Compliance mappings (ComplianceEngine)
- CVSS scores (CVSSScorer)
- Evidence metadata (EvidenceStore / filesystem)
- Run journal summary
- LLM-generated prose (Report Agent Brain)

Then renders everything through the PDFRenderer.

Usage::

    assembler = ReportAssembler()
    report_content = await assembler.assemble(run_id)
    pdf_bytes = assembler.render_pdf(report_content)
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from uuid import UUID

from reports.compliance_engine import ComplianceEngine
from reports.cvss_scorer import CVSSScorer
from reports.deduplicator import FindingDeduplicator
from reports.models import (
    AssetRecord,
    FindingRecord,
    ReportContent,
    Severity,
)
from reports.pdf_renderer import PDFRenderer

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Severity ordering for risk rating calculation
# ---------------------------------------------------------------------------
_SEV_ORDER = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
}


class ReportAssembler:
    """Assembles all data sources into a :class:`ReportContent` model.

    The assembler is designed to work in two modes:

    1. **Standalone** — findings, assets, and journal are passed directly
       (useful for testing and CLI usage).
    2. **Integrated** — data is loaded from the database / evidence store
       via injected loader callbacks.
    """

    def __init__(
        self,
        compliance_engine: Optional[ComplianceEngine] = None,
        cvss_scorer: Optional[CVSSScorer] = None,
        pdf_renderer: Optional[PDFRenderer] = None,
        deduplicator: Optional[FindingDeduplicator] = None,
        # Optional loader callbacks for DB/store integration
        load_findings_fn: Optional[Callable[[UUID], List[FindingRecord]]] = None,
        load_assets_fn: Optional[Callable[[UUID], List[AssetRecord]]] = None,
        load_journal_fn: Optional[Callable[[UUID], str]] = None,
        load_run_metadata_fn: Optional[Callable[[UUID], Dict[str, Any]]] = None,
    ):
        self.compliance = compliance_engine or ComplianceEngine()
        self.cvss = cvss_scorer or CVSSScorer()
        self.pdf = pdf_renderer or PDFRenderer()
        self.dedup = deduplicator or FindingDeduplicator()

        self._load_findings = load_findings_fn
        self._load_assets = load_assets_fn
        self._load_journal = load_journal_fn
        self._load_run_metadata = load_run_metadata_fn

    # ------------------------------------------------------------------
    # Core assembly
    # ------------------------------------------------------------------

    async def assemble(
        self,
        run_id: UUID,
        *,
        findings: Optional[List[FindingRecord]] = None,
        assets: Optional[List[AssetRecord]] = None,
        journal_summary: Optional[str] = None,
        run_metadata: Optional[Dict[str, Any]] = None,
    ) -> ReportContent:
        """Assemble a complete :class:`ReportContent` for the given run.

        Args:
            run_id: The engagement run ID.
            findings: Pre-loaded findings (skips DB loader if provided).
            assets: Pre-loaded assets.
            journal_summary: Pre-loaded journal text.
            run_metadata: Dict with keys like ``target_name``, ``operator``.

        Returns:
            Fully populated :class:`ReportContent` ready for PDF rendering.
        """
        # 1. Load raw data
        findings = findings or self._fetch_findings(run_id)
        assets = assets or self._fetch_assets(run_id)
        journal_summary = journal_summary or self._fetch_journal(run_id)
        run_metadata = run_metadata or self._fetch_run_metadata(run_id)

        # 2. De-duplicate findings
        findings = self.dedup.deduplicate(findings)

        # 3. Sort by severity (Critical first)
        findings.sort(key=lambda f: _SEV_ORDER.get(f.severity, 0), reverse=True)

        # 4. Score each finding with CVSS
        for f in findings:
            result = self.cvss.score_finding(f)
            f.cvss_score = result.numeric_score
            f.cvss_vector = result.vector_string

        # 5. Map compliance
        self.compliance.load_rules()
        for f in findings:
            f.compliance = self.compliance.map_finding(f)

        control_matrix = self.compliance.generate_control_matrix(findings)

        # 6. Call Report Agent Brain for narratives
        brain_narratives = await self._generate_narratives(findings, journal_summary, run_metadata)

        # 7. Attach brain-generated content to findings
        for f in findings:
            fid = str(f.id)
            f.business_impact = brain_narratives.get("business_impacts", {}).get(fid, f.business_impact)
            f.remediation_guidance = brain_narratives.get("remediations", {}).get(fid, f.remediation_guidance)

        # 8. Compute overall risk rating
        risk_rating = self._compute_risk_rating(findings)

        # 9. Assemble ReportContent
        rc = ReportContent(
            run_id=run_id,
            report_date=datetime.utcnow(),
            target_name=run_metadata.get("target_name", ""),
            classification=run_metadata.get("classification", "CONFIDENTIAL"),
            operator=run_metadata.get("operator", "Lucifer AI"),
            executive_summary=brain_narratives.get("executive_summary", ""),
            risk_rating=risk_rating,
            attack_narrative=brain_narratives.get("attack_narrative", ""),
            findings=findings,
            compliance_matrix=control_matrix,
            assets=assets,
            journal_summary=journal_summary,
        )

        logger.info(
            "Assembled report for run %s: %d findings, risk=%s",
            run_id, len(findings), risk_rating,
        )
        return rc

    def render_pdf(self, report_content: ReportContent) -> bytes:
        """Render assembled content to PDF bytes."""
        return self.pdf.render(report_content)

    def save_pdf(self, pdf_bytes: bytes, run_id: UUID) -> Path:
        """Save PDF to disk and return the path."""
        return self.pdf.save(pdf_bytes, run_id)

    # ------------------------------------------------------------------
    # Celery task entry point
    # ------------------------------------------------------------------

    def trigger(self, run_id: UUID) -> Path:
        """Synchronous entry point for Celery task invocation.

        Calls ``assemble()`` → ``render_pdf()`` → ``save_pdf()`` and
        returns the download path.
        """
        loop = asyncio.new_event_loop()
        try:
            rc = loop.run_until_complete(self.assemble(run_id))
        finally:
            loop.close()

        pdf_bytes = self.render_pdf(rc)
        return self.save_pdf(pdf_bytes, run_id)

    # ------------------------------------------------------------------
    # Data loaders (delegate to callbacks or return empty defaults)
    # ------------------------------------------------------------------

    def _fetch_findings(self, run_id: UUID) -> List[FindingRecord]:
        if self._load_findings:
            return self._load_findings(run_id)
        logger.warning("No findings loader configured — returning empty list")
        return []

    def _fetch_assets(self, run_id: UUID) -> List[AssetRecord]:
        if self._load_assets:
            return self._load_assets(run_id)
        return []

    def _fetch_journal(self, run_id: UUID) -> str:
        if self._load_journal:
            return self._load_journal(run_id)
        return ""

    def _fetch_run_metadata(self, run_id: UUID) -> Dict[str, Any]:
        if self._load_run_metadata:
            return self._load_run_metadata(run_id)
        return {}

    # ------------------------------------------------------------------
    # Report Brain integration
    # ------------------------------------------------------------------

    async def _generate_narratives(
        self,
        findings: List[FindingRecord],
        journal_summary: str,
        run_metadata: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Call the Report Agent Brain to produce narrative content.

        Returns a dict with keys:
        - executive_summary (str)
        - attack_narrative (str)
        - business_impacts (dict[finding_id_str → str])
        - remediations (dict[finding_id_str → str])
        """
        try:
            from agents.brains.report import ReportBrain
            brain = ReportBrain()
        except ImportError:
            logger.warning("Report Brain not available — using fallback narratives")
            return self._fallback_narratives(findings)

        findings_dicts = [f.model_dump(mode="json") for f in findings]
        for fd in findings_dicts:
            fd["severity"] = fd.get("severity", "medium")

        try:
            exec_summary = await brain.generate_executive_summary(findings_dicts, run_metadata)
            attack_narrative = await brain.generate_attack_narrative(journal_summary, findings_dicts)

            business_impacts: Dict[str, str] = {}
            remediations: Dict[str, str] = {}
            for fd in findings_dicts:
                fid = fd.get("id", "")
                business_impacts[str(fid)] = await brain.generate_business_impact(fd)
                remediations[str(fid)] = await brain.generate_remediation_guidance(fd)

            return {
                "executive_summary": exec_summary,
                "attack_narrative": attack_narrative,
                "business_impacts": business_impacts,
                "remediations": remediations,
            }
        except Exception as exc:
            logger.error("Report Brain call failed: %s — using fallbacks", exc)
            return self._fallback_narratives(findings)

    @staticmethod
    def _fallback_narratives(findings: List[FindingRecord]) -> Dict[str, Any]:
        """Generate minimal fallback narratives when the Brain is unavailable."""
        n_crit = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        n_high = sum(1 for f in findings if f.severity == Severity.HIGH)
        exec_summary = (
            f"This engagement identified {len(findings)} findings, "
            f"including {n_crit} Critical and {n_high} High severity issues. "
            f"Immediate remediation is recommended."
        )
        return {
            "executive_summary": exec_summary,
            "attack_narrative": "Attack narrative not available.",
            "business_impacts": {},
            "remediations": {},
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _compute_risk_rating(findings: List[FindingRecord]) -> str:
        """Derive an overall risk rating from the findings set."""
        if not findings:
            return "Low"
        sevs = [f.severity for f in findings]
        if Severity.CRITICAL in sevs:
            return "Critical"
        n_high = sum(1 for s in sevs if s == Severity.HIGH)
        if n_high >= 3:
            return "Critical"
        if n_high >= 1:
            return "High"
        n_med = sum(1 for s in sevs if s == Severity.MEDIUM)
        if n_med >= 3:
            return "High"
        if n_med >= 1:
            return "Medium"
        return "Low"
