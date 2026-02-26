"""Report Agent Brain — LLM-powered narrative generation for pentest reports.

Generates:
  - Executive summaries with risk posture overview
  - Detailed technical findings with evidence references
  - Prioritised remediation plans
  - PDF / Markdown export artefacts

Single-pass brain: one LLM call synthesises all findings into a cohesive
report, then tools handle formatting and export.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from agents.base import AgentBrain


# ── Pydantic schemas ────────────────────────────────────────────────

class ExecutiveSummary(BaseModel):
    """High-level risk posture overview for stakeholders."""
    risk_rating: str = Field(..., description="Overall risk rating: critical / high / medium / low")
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    key_risks: List[str] = Field(default_factory=list, description="Top risk bullet points")
    summary_markdown: str = ""


class TechnicalFinding(BaseModel):
    """Single finding formatted for the technical report."""
    finding_id: str = ""
    title: str = ""
    severity: str = "info"
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    description: str = ""
    evidence_refs: List[str] = Field(default_factory=list)
    affected_components: List[str] = Field(default_factory=list)
    attack_narrative: str = ""
    business_impact: str = ""
    remediation: str = ""


class RemediationItem(BaseModel):
    """Single remediation action with priority."""
    priority: int = Field(..., description="1 = highest priority")
    finding_ids: List[str] = Field(default_factory=list)
    action: str = ""
    effort_estimate: str = ""
    expected_risk_reduction: str = ""


class ReportInput(BaseModel):
    """Input schema for the Report brain."""
    run_id: str
    target: str = ""
    findings: List[Dict[str, Any]] = Field(default_factory=list)
    evidence_packages: List[Dict[str, Any]] = Field(default_factory=list)
    journal_summaries: Dict[str, str] = Field(default_factory=dict, description="agent_type → journal summary text")
    report_format: str = Field("markdown", description="markdown | pdf | both")
    client_name: Optional[str] = None
    engagement_name: Optional[str] = None


class ReportOutput(BaseModel):
    """Output schema for the Report brain."""
    executive_summary: ExecutiveSummary
    technical_findings: List[TechnicalFinding] = Field(default_factory=list)
    remediation_plan: List[RemediationItem] = Field(default_factory=list)
    markdown_report: str = ""
    pdf_path: Optional[str] = None
    total_pages: int = 0


# ── Brain ────────────────────────────────────────────────────────────

class ReportBrain(AgentBrain):
    """Synthesises all pentest findings into professional reports.

    Single-pass brain: one LLM call produces the structured report,
    then export tools convert to the requested format.
    """

    AGENT_TYPE = "report"
    LLM_MODEL = "claude-3-5-sonnet"
    SYSTEM_PROMPT = (
        "You are a senior penetration-testing report writer. "
        "Given structured findings, evidence packages, and agent journals, "
        "produce a professional penetration test report with:\n"
        "1. An executive summary with overall risk rating and key risks\n"
        "2. Detailed technical findings — each with description, evidence, "
        "   attack narrative, business impact, and remediation\n"
        "3. A prioritised remediation plan ordered by risk reduction\n\n"
        "Write in clear, professional English. Reference evidence by ID. "
        "Use CVSS scores where available. Be specific and actionable."
    )
    MAX_STEPS = 1          # single-pass
    TOKEN_BUDGET = 50_000
    APPROVAL_REQUIRED_TOOLS: list[str] = []   # report generation is safe

    # ── tools ────────────────────────────────────────────────────────

    def get_tools(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": "generate_executive_summary",
                "description": (
                    "Produce an executive summary from findings. "
                    "Returns risk rating, severity counts, and key risk bullets."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "findings": {
                            "type": "array",
                            "description": "List of finding dicts with severity, title, cvss_score",
                        },
                        "client_name": {"type": "string"},
                        "engagement_name": {"type": "string"},
                    },
                    "required": ["findings"],
                },
            },
            {
                "name": "generate_technical_report",
                "description": (
                    "Generate detailed technical findings section. "
                    "Each finding includes description, evidence refs, "
                    "attack narrative, business impact, and remediation."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "findings": {"type": "array"},
                        "evidence_packages": {"type": "array"},
                        "journal_summaries": {"type": "object"},
                    },
                    "required": ["findings"],
                },
            },
            {
                "name": "generate_remediation_plan",
                "description": (
                    "Create a prioritised remediation plan from findings. "
                    "Orders actions by risk-reduction impact and effort."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "findings": {"type": "array"},
                    },
                    "required": ["findings"],
                },
            },
            {
                "name": "export_pdf",
                "description": "Export the final report to PDF format.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "markdown_content": {
                            "type": "string",
                            "description": "Full report in Markdown",
                        },
                        "output_path": {"type": "string"},
                    },
                    "required": ["markdown_content"],
                },
            },
            {
                "name": "export_markdown",
                "description": "Export the final report as a Markdown file.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "markdown_content": {"type": "string"},
                        "output_path": {"type": "string"},
                    },
                    "required": ["markdown_content"],
                },
            },
        ]

    # ── schemas ──────────────────────────────────────────────────────

    def get_input_schema(self):
        return ReportInput

    def get_output_schema(self):
        return ReportOutput

    # ── single-pass override ─────────────────────────────────────────

    async def run(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Single-pass report generation.

        Sends all findings + evidence to the LLM in one prompt and
        parses the structured report output.
        """
        validated = ReportInput(**input_data)

        self.save_memory(
            texts=[f"Report generation for run {validated.run_id}"],
            metadatas=[{"run_id": validated.run_id, "target": validated.target}],
            ids=[f"report-start-{validated.run_id}"],
        )

        from agents.llm import get_llm

        llm = get_llm(self.LLM_MODEL)

        user_prompt = self._build_report_prompt(validated)
        messages = [
            {"role": "system", "content": self.SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ]

        raw = await llm.achat(messages, max_tokens=self.TOKEN_BUDGET)
        content = raw.get("content", "")

        output = self._parse_report(content, validated)

        self.write_journal(
            run_id=validated.run_id,
            step=1,
            action="generate_report",
            observation=f"Generated report with {len(output.get('technical_findings', []))} findings",
        )

        return output

    # ── helpers ──────────────────────────────────────────────────────

    def _build_report_prompt(self, inp: ReportInput) -> str:
        """Build the mega-prompt with all findings and evidence."""
        parts = [
            f"# Penetration Test Report Generation\n",
            f"**Run ID:** {inp.run_id}",
            f"**Target:** {inp.target}",
        ]
        if inp.client_name:
            parts.append(f"**Client:** {inp.client_name}")
        if inp.engagement_name:
            parts.append(f"**Engagement:** {inp.engagement_name}")

        parts.append(f"\n## Findings ({len(inp.findings)} total)\n")
        for i, f in enumerate(inp.findings, 1):
            parts.append(f"### Finding {i}")
            for k, v in f.items():
                parts.append(f"- **{k}:** {v}")
            parts.append("")

        if inp.evidence_packages:
            parts.append(f"\n## Evidence Packages ({len(inp.evidence_packages)})\n")
            for ep in inp.evidence_packages:
                parts.append(f"- {ep.get('finding_id', 'unknown')}: {ep.get('description', '')}")

        if inp.journal_summaries:
            parts.append("\n## Agent Journal Summaries\n")
            for agent, summary in inp.journal_summaries.items():
                parts.append(f"### {agent}\n{summary}\n")

        parts.append(
            "\n---\n"
            "Produce a JSON object with keys: executive_summary, "
            "technical_findings, remediation_plan, markdown_report. "
            "Follow the output schema exactly."
        )

        return "\n".join(parts)

    def _parse_report(self, content: str, inp: ReportInput) -> Dict[str, Any]:
        """Parse LLM output into ReportOutput, with fallback construction."""
        import json
        import re

        # Try to extract JSON from the response
        json_match = re.search(r"\{[\s\S]*\}", content)
        if json_match:
            try:
                parsed = json.loads(json_match.group())
                output = ReportOutput(**parsed)
                return output.model_dump()
            except (json.JSONDecodeError, Exception):
                pass

        # Fallback: construct minimal report from available data
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in inp.findings:
            sev = f.get("severity", "info").lower()
            if sev in severity_counts:
                severity_counts[sev] += 1

        # Determine overall risk
        if severity_counts["critical"] > 0:
            risk = "critical"
        elif severity_counts["high"] > 0:
            risk = "high"
        elif severity_counts["medium"] > 0:
            risk = "medium"
        else:
            risk = "low"

        exec_summary = ExecutiveSummary(
            risk_rating=risk,
            total_findings=len(inp.findings),
            critical_count=severity_counts["critical"],
            high_count=severity_counts["high"],
            medium_count=severity_counts["medium"],
            low_count=severity_counts["low"],
            info_count=severity_counts["info"],
            key_risks=[f.get("title", "Unknown") for f in inp.findings
                       if f.get("severity", "").lower() in ("critical", "high")],
            summary_markdown=content[:2000] if content else "Report generation produced no content.",
        )

        tech_findings = [
            TechnicalFinding(
                finding_id=f.get("id", f"FIND-{i}"),
                title=f.get("title", "Untitled"),
                severity=f.get("severity", "info"),
                cvss_score=f.get("cvss_score"),
                description=f.get("description", ""),
                remediation=f.get("remediation", ""),
            )
            for i, f in enumerate(inp.findings, 1)
        ]

        remediation_items = [
            RemediationItem(
                priority=i,
                finding_ids=[tf.finding_id],
                action=tf.remediation or f"Remediate {tf.title}",
                effort_estimate="TBD",
                expected_risk_reduction=tf.severity,
            )
            for i, tf in enumerate(
                sorted(tech_findings, key=lambda t: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(t.severity, 5)),
                1,
            )
        ]

        output = ReportOutput(
            executive_summary=exec_summary,
            technical_findings=tech_findings,
            remediation_plan=remediation_items,
            markdown_report=content or "# Report\n\nGeneration incomplete.",
        )
        return output.model_dump()
