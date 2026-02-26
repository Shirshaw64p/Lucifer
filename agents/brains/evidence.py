"""
agents/brains/evidence.py — Evidence Collection Agent Brain
=============================================================
Agent Type : evidence
LLM Model  : Claude 3.5 Sonnet
Loop Type  : ReAct (per-finding)
Max Steps  : 30 (per finding)
Token Budget: 75,000

Purpose: Validate findings from other agents, collect evidence,
generate proof-of-concept demonstrations, calculate CVSS scores,
and create evidence packages for each vulnerability.
"""

from __future__ import annotations

from typing import Any, ClassVar, Dict, List, Optional, Type

from pydantic import BaseModel, Field

from agents.base import AgentBrain


# ---------------------------------------------------------------------------
# Input Schema
# ---------------------------------------------------------------------------
class EvidenceInput(BaseModel):
    """Validated input for the Evidence Collection Agent."""
    run_id: str = Field(..., description="Unique run identifier")
    task_id: str = Field(..., description="Unique task identifier")
    target: str = Field(..., description="Target URL, domain, or IP")
    scope: Dict[str, Any] = Field(default_factory=dict, description="Engagement scope")
    findings: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Raw findings from all agents to validate and enrich",
    )
    agent_results: Dict[str, Any] = Field(
        default_factory=dict,
        description="Complete results from all agents for cross-referencing",
    )
    evidence_level: str = Field(
        default="standard",
        description="Evidence depth: minimal, standard, comprehensive",
    )


# ---------------------------------------------------------------------------
# Output Schema
# ---------------------------------------------------------------------------
class EvidencePackage(BaseModel):
    """Complete evidence package for a single finding."""
    finding_id: str = Field(..., description="Original finding ID")
    finding_title: str = Field(default="", description="Finding title")
    validated: bool = Field(default=False, description="Whether the finding was validated")
    validation_method: str = Field(default="", description="How the finding was validated")
    severity_original: str = Field(default="", description="Original severity assigned")
    severity_adjusted: str = Field(default="", description="Adjusted severity after validation")
    cvss_vector: str = Field(default="", description="CVSS 3.1 vector string")
    cvss_score: float = Field(default=0.0, description="CVSS 3.1 base score")
    cwe_id: str = Field(default="", description="CWE identifier")
    cve_ids: List[str] = Field(default_factory=list, description="Related CVE IDs if applicable")
    poc_description: str = Field(default="", description="Step-by-step PoC description")
    poc_request: str = Field(default="", description="HTTP request for PoC")
    poc_response: str = Field(default="", description="Relevant response snippet")
    screenshots: List[str] = Field(
        default_factory=list,
        description="Screenshot file references",
    )
    request_log: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Complete request/response log for evidence",
    )
    impact_analysis: str = Field(default="", description="Business impact analysis")
    remediation_detailed: str = Field(default="", description="Detailed remediation with code examples")
    remediation_priority: str = Field(default="medium", description="Remediation priority: immediate, high, medium, low")
    false_positive: bool = Field(default=False, description="Marked as false positive")
    false_positive_reason: str = Field(default="", description="Reason for false positive classification")
    evidence_hash: str = Field(default="", description="SHA-256 hash of evidence for integrity")
    collected_at: str = Field(default="", description="Evidence collection timestamp")


class EvidenceOutput(BaseModel):
    """Validated output from the Evidence Collection Agent."""
    target: str = Field(..., description="Target as provided")
    evidence_packages: List[EvidencePackage] = Field(
        default_factory=list,
        description="Evidence packages for each validated finding",
    )
    validated_count: int = Field(default=0, description="Number of findings validated")
    false_positive_count: int = Field(default=0, description="Number of false positives identified")
    total_findings_reviewed: int = Field(default=0, description="Total findings reviewed")
    severity_distribution: Dict[str, int] = Field(
        default_factory=dict,
        description="Distribution of findings by severity",
    )
    overall_risk_rating: str = Field(
        default="medium",
        description="Overall risk: critical, high, medium, low",
    )
    summary: str = Field(default="", description="Evidence collection summary")


# ---------------------------------------------------------------------------
# Tool Definitions
# ---------------------------------------------------------------------------
EVIDENCE_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "screenshot_capture",
            "description": (
                "Capture a screenshot of a web page or application state as evidence. "
                "Returns the path to the saved screenshot file."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "URL to capture"},
                    "selector": {"type": "string", "description": "CSS selector to capture specific element"},
                    "full_page": {"type": "boolean", "description": "Capture full page (default: true)"},
                    "wait_seconds": {"type": "integer", "description": "Wait before capture (for dynamic content)"},
                    "label": {"type": "string", "description": "Label for the screenshot"},
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "request_log",
            "description": (
                "Send an HTTP request and log the complete request/response pair "
                "as evidence. Includes timing, headers, and body."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Target URL"},
                    "method": {"type": "string", "description": "HTTP method"},
                    "headers": {"type": "object", "description": "Request headers"},
                    "body": {"type": "string", "description": "Request body"},
                    "label": {"type": "string", "description": "Label for this evidence request"},
                    "follow_redirects": {"type": "boolean", "description": "Follow redirects"},
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "poc_generate",
            "description": (
                "Generate a proof-of-concept script or description for a vulnerability. "
                "Creates standalone PoC that can be used to demonstrate the issue."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "vuln_type": {"type": "string", "description": "Vulnerability type"},
                    "target_url": {"type": "string", "description": "Target URL"},
                    "parameter": {"type": "string", "description": "Vulnerable parameter"},
                    "payload": {"type": "string", "description": "Working payload"},
                    "format": {"type": "string", "description": "PoC format: curl, python, burp, manual_steps"},
                    "notes": {"type": "string", "description": "Additional context for PoC generation"},
                },
                "required": ["vuln_type", "target_url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "cvss_calculate",
            "description": (
                "Calculate CVSS 3.1 base score from individual metric values. "
                "Returns the vector string and numeric score."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "attack_vector": {"type": "string", "description": "AV: Network, Adjacent, Local, Physical"},
                    "attack_complexity": {"type": "string", "description": "AC: Low, High"},
                    "privileges_required": {"type": "string", "description": "PR: None, Low, High"},
                    "user_interaction": {"type": "string", "description": "UI: None, Required"},
                    "scope": {"type": "string", "description": "S: Unchanged, Changed"},
                    "confidentiality": {"type": "string", "description": "C: None, Low, High"},
                    "integrity": {"type": "string", "description": "I: None, Low, High"},
                    "availability": {"type": "string", "description": "A: None, Low, High"},
                },
                "required": [
                    "attack_vector", "attack_complexity", "privileges_required",
                    "user_interaction", "scope", "confidentiality", "integrity", "availability",
                ],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "evidence_store",
            "description": (
                "Store an evidence artifact (file, data blob, or text) with metadata "
                "and integrity hash."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "finding_id": {"type": "string", "description": "Associated finding ID"},
                    "evidence_type": {"type": "string", "description": "Type: screenshot, request_response, file, text"},
                    "content": {"type": "string", "description": "Evidence content or file path"},
                    "label": {"type": "string", "description": "Evidence label/description"},
                    "metadata": {"type": "object", "description": "Additional metadata"},
                },
                "required": ["finding_id", "evidence_type", "content"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "hash_verify",
            "description": (
                "Generate or verify SHA-256 hash for evidence integrity. "
                "Used to create tamper-proof evidence chains."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "content": {"type": "string", "description": "Content to hash"},
                    "expected_hash": {"type": "string", "description": "Expected hash for verification (optional)"},
                    "algorithm": {"type": "string", "description": "Hash algorithm: sha256, sha512, md5"},
                },
                "required": ["content"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "http_request",
            "description": "Send a custom HTTP request for evidence validation.",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Target URL"},
                    "method": {"type": "string", "description": "HTTP method"},
                    "headers": {"type": "object", "description": "Custom headers"},
                    "body": {"type": "string", "description": "Request body"},
                },
                "required": ["url"],
            },
        },
    },
]


# ---------------------------------------------------------------------------
# Brain Class
# ---------------------------------------------------------------------------
class EvidenceBrain(AgentBrain):
    """Evidence Collection Agent Brain — validates findings and collects evidence."""

    AGENT_TYPE: ClassVar[str] = "evidence"
    LLM_MODEL: ClassVar[str] = "claude-3-5-sonnet"
    MAX_STEPS: ClassVar[int] = 30  # per finding — total varies with finding count
    TOKEN_BUDGET: ClassVar[int] = 75_000

    SYSTEM_PROMPT: ClassVar[str] = (
        "You are the Lucifer Evidence Collection Agent — an expert in vulnerability "
        "validation, evidence collection, and CVSS scoring.\n\n"
        "## Your Mission\n"
        "For each finding reported by other agents, you must:\n"
        "1. **Validate** — Reproduce the vulnerability to confirm it is real. "
        "Send the exact request and verify the expected response.\n"
        "2. **Collect Evidence** — Capture screenshots, request/response logs, "
        "and any relevant artifacts as proof.\n"
        "3. **Score** — Calculate the accurate CVSS 3.1 base score using the "
        "cvss_calculate tool. Map to the correct CWE.\n"
        "4. **Generate PoC** — Create a clear, reproducible proof-of-concept "
        "for each validated finding.\n"
        "5. **Assess Impact** — Write a business impact analysis explaining "
        "the real-world consequences.\n"
        "6. **Write Remediation** — Provide detailed, code-level remediation "
        "guidance specific to the technology stack.\n"
        "7. **Identify False Positives** — Flag and explain any findings that "
        "cannot be validated.\n\n"
        "## Methodology\n"
        "- Process findings in severity order (critical first).\n"
        "- For each finding, attempt to reproduce with the original payload.\n"
        "- If reproduction fails, try variations before marking false positive.\n"
        "- Collect at least request/response evidence for every validated finding.\n"
        "- Screenshots for any visual/UI-related findings.\n"
        "- Hash all evidence for integrity verification.\n"
        "- Adjust severity if original assessment was inaccurate.\n\n"
        "## Output Requirements\n"
        "Provide an evidence package for each finding with validation status, "
        "CVSS score, PoC, impact analysis, and detailed remediation. Include "
        "summary statistics and overall risk rating."
    )

    # No approval needed — evidence collection is non-destructive
    APPROVAL_REQUIRED_TOOLS: ClassVar[List[str]] = []

    def get_tools(self) -> List[Dict[str, Any]]:
        return EVIDENCE_TOOLS

    def get_input_schema(self) -> Type[BaseModel]:
        return EvidenceInput

    def get_output_schema(self) -> Type[BaseModel]:
        return EvidenceOutput
