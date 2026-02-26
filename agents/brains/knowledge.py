"""
agents/brains/knowledge.py — Knowledge Base Agent Brain
=========================================================
Agent Type : knowledge
LLM Model  : Claude 3.5 Haiku
Loop Type  : Single-pass (no ReAct loop)
Max Steps  : 1 (single-pass)
Token Budget: 30,000

Purpose: Knowledge base query agent that provides CVE lookups,
exploit database searches, vulnerability correlations, CWE lookups,
and attack pattern matching. Runs as a single-pass information
retrieval agent.
"""

from __future__ import annotations

from typing import Any, ClassVar, Dict, List, Optional, Type

from pydantic import BaseModel, Field

from agents.base import AgentBrain


# ---------------------------------------------------------------------------
# Input Schema
# ---------------------------------------------------------------------------
class KnowledgeInput(BaseModel):
    """Validated input for the Knowledge Base Agent."""
    run_id: str = Field(..., description="Unique run identifier")
    task_id: str = Field(..., description="Unique task identifier")
    target: str = Field(default="", description="Target context (optional)")
    scope: Dict[str, Any] = Field(default_factory=dict, description="Engagement scope")
    queries: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Knowledge queries — each with 'type' and 'query' fields",
    )
    technologies: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Technology stack to correlate against vulnerability databases",
    )
    services: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Services and versions to look up known vulnerabilities for",
    )
    findings_to_enrich: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Existing findings that need CVE/CWE enrichment",
    )


# ---------------------------------------------------------------------------
# Output Schema
# ---------------------------------------------------------------------------
class CVERecord(BaseModel):
    """A CVE record from the knowledge base."""
    cve_id: str = Field(..., description="CVE identifier (e.g., CVE-2024-12345)")
    description: str = Field(default="", description="CVE description")
    cvss_score: Optional[float] = Field(default=None, description="CVSS score")
    severity: str = Field(default="", description="Severity rating")
    affected_product: str = Field(default="", description="Affected product/version")
    published_date: str = Field(default="", description="Publication date")
    exploit_available: bool = Field(default=False, description="Whether public exploit exists")
    references: List[str] = Field(default_factory=list, description="Reference URLs")


class ExploitRecord(BaseModel):
    """An exploit record from the knowledge base."""
    exploit_id: str = Field(default="", description="Exploit DB identifier")
    title: str = Field(default="", description="Exploit title")
    cve_ids: List[str] = Field(default_factory=list, description="Related CVEs")
    platform: str = Field(default="", description="Target platform")
    exploit_type: str = Field(default="", description="Type: remote, local, webapps, dos")
    verified: bool = Field(default=False, description="Whether exploit is verified")
    source_url: str = Field(default="", description="Source URL")


class VulnerabilityCorrelation(BaseModel):
    """Correlation between detected technology and known vulnerabilities."""
    technology: str = Field(..., description="Technology name and version")
    known_cves: List[str] = Field(default_factory=list, description="Known CVEs")
    critical_count: int = Field(default=0, description="Number of critical CVEs")
    high_count: int = Field(default=0, description="Number of high CVEs")
    exploit_available_count: int = Field(default=0, description="CVEs with public exploits")
    recommendation: str = Field(default="", description="Recommended action")


class KnowledgeOutput(BaseModel):
    """Validated output from the Knowledge Base Agent."""
    target: str = Field(default="", description="Target context")
    cve_results: List[CVERecord] = Field(
        default_factory=list,
        description="CVE lookup results",
    )
    exploit_results: List[ExploitRecord] = Field(
        default_factory=list,
        description="Exploit database search results",
    )
    vulnerability_correlations: List[VulnerabilityCorrelation] = Field(
        default_factory=list,
        description="Technology-to-vulnerability correlations",
    )
    cwe_mappings: Dict[str, str] = Field(
        default_factory=dict,
        description="CWE ID to name/description mappings",
    )
    attack_patterns: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="MITRE ATT&CK patterns relevant to findings",
    )
    enriched_findings: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Original findings enriched with CVE/CWE data",
    )
    threat_intelligence: Dict[str, Any] = Field(
        default_factory=dict,
        description="Relevant threat intelligence context",
    )
    summary: str = Field(default="", description="Knowledge base query summary")


# ---------------------------------------------------------------------------
# Tool Definitions
# ---------------------------------------------------------------------------
KNOWLEDGE_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "cve_lookup",
            "description": (
                "Look up CVE details by CVE ID or search for CVEs affecting "
                "a specific product/vendor/version combination."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "cve_id": {"type": "string", "description": "Specific CVE ID to look up"},
                    "product": {"type": "string", "description": "Product name to search"},
                    "vendor": {"type": "string", "description": "Vendor name"},
                    "version": {"type": "string", "description": "Product version"},
                    "severity_min": {"type": "string", "description": "Minimum severity: low, medium, high, critical"},
                    "year_from": {"type": "integer", "description": "CVEs from year (e.g., 2023)"},
                    "limit": {"type": "integer", "description": "Max results (default: 20)"},
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "exploit_db_search",
            "description": (
                "Search exploit databases (Exploit-DB, PacketStorm, etc.) for "
                "public exploits matching a CVE, product, or keyword."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Search query (CVE ID, product, keyword)"},
                    "platform": {"type": "string", "description": "Target platform filter"},
                    "exploit_type": {"type": "string", "description": "Type: remote, local, webapps, dos"},
                    "verified_only": {"type": "boolean", "description": "Only return verified exploits"},
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "vulnerability_correlate",
            "description": (
                "Correlate a technology stack (products and versions) against "
                "vulnerability databases to identify known issues."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "technologies": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "name": {"type": "string"},
                                "version": {"type": "string"},
                                "category": {"type": "string"},
                            },
                        },
                        "description": "List of technologies to correlate",
                    },
                    "severity_threshold": {"type": "string", "description": "Minimum severity for results"},
                },
                "required": ["technologies"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "cwe_lookup",
            "description": (
                "Look up CWE (Common Weakness Enumeration) details by ID or "
                "search for CWEs by keyword."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "cwe_id": {"type": "string", "description": "CWE ID (e.g., CWE-79)"},
                    "keyword": {"type": "string", "description": "Search keyword"},
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "attack_pattern_match",
            "description": (
                "Match findings against MITRE ATT&CK patterns and techniques. "
                "Returns relevant tactics, techniques, and sub-techniques."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "finding_type": {"type": "string", "description": "Type of finding (sqli, xss, rce, etc.)"},
                    "context": {"type": "string", "description": "Additional context about the finding"},
                    "platform": {"type": "string", "description": "Platform: web, network, cloud, mobile"},
                },
                "required": ["finding_type"],
            },
        },
    },
]


# ---------------------------------------------------------------------------
# Brain Class
# ---------------------------------------------------------------------------
class KnowledgeBrain(AgentBrain):
    """Knowledge Base Agent Brain — CVE/exploit lookups and vulnerability correlation."""

    AGENT_TYPE: ClassVar[str] = "knowledge"
    LLM_MODEL: ClassVar[str] = "claude-3-5-haiku"
    MAX_STEPS: ClassVar[int] = 1  # single-pass
    TOKEN_BUDGET: ClassVar[int] = 30_000

    SYSTEM_PROMPT: ClassVar[str] = (
        "You are the Lucifer Knowledge Base Agent — an expert in cybersecurity "
        "threat intelligence, vulnerability databases, and attack pattern analysis.\n\n"
        "## Your Mission\n"
        "Provide knowledge base services to enrich the penetration test:\n"
        "1. **CVE Lookups** — Look up specific CVEs or search for CVEs affecting "
        "the target's technology stack.\n"
        "2. **Exploit Search** — Search public exploit databases for available "
        "exploits targeting discovered technologies.\n"
        "3. **Vulnerability Correlation** — Correlate the detected technology "
        "stack against known vulnerability databases.\n"
        "4. **CWE Mapping** — Map findings to appropriate CWE identifiers.\n"
        "5. **ATT&CK Mapping** — Match findings to MITRE ATT&CK techniques.\n\n"
        "## Mode\n"
        "You operate in SINGLE-PASS mode. Analyse the input, make all necessary "
        "tool calls, and produce your complete output in one pass. There is no "
        "iterative loop — gather all information at once.\n\n"
        "## Output Requirements\n"
        "Provide CVE results, exploit availability, technology correlations, "
        "CWE mappings, ATT&CK patterns, and enriched findings. Prioritise by "
        "severity and exploit availability."
    )

    # No approval needed — read-only knowledge lookups
    APPROVAL_REQUIRED_TOOLS: ClassVar[List[str]] = []

    def get_tools(self) -> List[Dict[str, Any]]:
        return KNOWLEDGE_TOOLS

    def get_input_schema(self) -> Type[BaseModel]:
        return KnowledgeInput

    def get_output_schema(self) -> Type[BaseModel]:
        return KnowledgeOutput

    def run(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Override run() for single-pass execution.

        The Knowledge Agent runs with MAX_STEPS=1, meaning the
        ReAct loop will produce output in a single iteration.
        This is effectively a single LLM call with tools.
        """
        # Use parent's run() — the MAX_STEPS=1 naturally creates single-pass behavior
        return super().run(context)
