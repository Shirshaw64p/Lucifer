"""Pydantic models for the Lucifer reporting engine.

These define the data structures flowing through the report pipeline:
compliance mappings, CVSS results, evidence metadata, and the
assembled ReportContent used by the PDF renderer.
"""

from __future__ import annotations

import enum
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnCategory(str, enum.Enum):
    BROKEN_AUTH = "BROKEN_AUTH"
    INJECTION = "INJECTION"
    XSS = "XSS"
    IDOR = "IDOR"
    BOLA = "BOLA"
    BFLA = "BFLA"
    SSRF = "SSRF"
    XXE = "XXE"
    MASS_ASSIGNMENT = "MASS_ASSIGNMENT"
    SENSITIVE_DATA_EXPOSURE = "SENSITIVE_DATA_EXPOSURE"
    SECURITY_MISCONFIGURATION = "SECURITY_MISCONFIGURATION"
    BROKEN_ACCESS_CONTROL = "BROKEN_ACCESS_CONTROL"
    CRYPTOGRAPHIC_FAILURE = "CRYPTOGRAPHIC_FAILURE"
    CLOUD_MISCONFIGURATION = "CLOUD_MISCONFIGURATION"
    NETWORK_EXPOSURE = "NETWORK_EXPOSURE"
    INSUFFICIENT_LOGGING = "INSUFFICIENT_LOGGING"
    JWT_VULNERABILITY = "JWT_VULNERABILITY"
    INSECURE_DESERIALIZATION = "INSECURE_DESERIALIZATION"


class ControlStatus(str, enum.Enum):
    PASS = "pass"
    FAIL = "fail"
    PARTIAL = "partial"
    NOT_TESTED = "not_tested"


# ---------------------------------------------------------------------------
# Compliance models
# ---------------------------------------------------------------------------

class FrameworkControl(BaseModel):
    """A single control from a compliance framework."""
    control_id: str
    title: str
    description: str = ""


class ComplianceMapping(BaseModel):
    """Maps a single finding to controls across all four frameworks."""
    finding_id: UUID
    vuln_category: str
    soc2: List[FrameworkControl] = Field(default_factory=list)
    pci_dss: List[FrameworkControl] = Field(default_factory=list)
    hipaa: List[FrameworkControl] = Field(default_factory=list)
    iso27001: List[FrameworkControl] = Field(default_factory=list)


class ControlMatrixEntry(BaseModel):
    """One row of the control matrix: a specific control and its status."""
    framework: str
    control_id: str
    title: str
    status: ControlStatus = ControlStatus.NOT_TESTED
    finding_ids: List[UUID] = Field(default_factory=list)


class ControlMatrix(BaseModel):
    """Full compliance control matrix across all frameworks."""
    entries: List[ControlMatrixEntry] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# CVSS models
# ---------------------------------------------------------------------------

class CVSSResult(BaseModel):
    """CVSS 3.1 scoring output for a finding."""
    finding_id: UUID
    vector_string: str
    numeric_score: float
    severity_label: str  # Critical / High / Medium / Low / None


# ---------------------------------------------------------------------------
# Evidence models
# ---------------------------------------------------------------------------

class EvidenceRef(BaseModel):
    """Lightweight reference to an evidence artifact."""
    artifact_id: UUID
    artifact_type: str  # screenshot, pcap, log, report, other
    storage_path: str
    mime_type: str = ""
    size_bytes: int = 0
    base64_data: Optional[str] = None  # populated at render time


# ---------------------------------------------------------------------------
# Finding models (used in report assembly)
# ---------------------------------------------------------------------------

class FindingRecord(BaseModel):
    """A normalised finding record used throughout the report pipeline."""
    id: UUID
    run_id: UUID
    target_id: Optional[UUID] = None
    title: str
    severity: Severity
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    description: str
    remediation: Optional[str] = None
    raw_output: Optional[str] = None
    agent_id: Optional[UUID] = None
    agent_name: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    vuln_category: Optional[str] = None
    endpoint_url: Optional[str] = None
    attack_vector: Optional[str] = None
    privileges_required: Optional[str] = None
    user_interaction: Optional[str] = None
    scope_changed: Optional[bool] = None
    confidentiality_impact: Optional[str] = None
    integrity_impact: Optional[str] = None
    availability_impact: Optional[str] = None
    evidence: List[EvidenceRef] = Field(default_factory=list)
    compliance: Optional[ComplianceMapping] = None
    business_impact: Optional[str] = None
    remediation_guidance: Optional[str] = None
    effort_estimate: Optional[str] = None  # e.g. "2 hours", "1 sprint"


# ---------------------------------------------------------------------------
# Target / asset models
# ---------------------------------------------------------------------------

class AssetRecord(BaseModel):
    """Discovered asset for the asset inventory section."""
    id: UUID
    target_type: str
    value: str
    in_scope: bool = True
    metadata_: Dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Report content model (assembled by ReportAssembler)
# ---------------------------------------------------------------------------

class ReportContent(BaseModel):
    """Top-level container for a fully assembled pentest report.

    This is the single object consumed by the Jinja2 templates and
    the PDFRenderer to produce the final deliverable.
    """
    run_id: UUID
    report_date: datetime = Field(default_factory=datetime.utcnow)

    # Cover page
    target_name: str = ""
    classification: str = "CONFIDENTIAL"
    operator: str = ""

    # Executive summary (generated by Report Brain)
    executive_summary: str = ""
    risk_rating: str = ""  # Critical / High / Medium / Low

    # Attack narrative (generated by Report Brain)
    attack_narrative: str = ""

    # Findings
    findings: List[FindingRecord] = Field(default_factory=list)

    # Compliance
    compliance_matrix: Optional[ControlMatrix] = None

    # Assets
    assets: List[AssetRecord] = Field(default_factory=list)

    # Run journal summary (for narrative context)
    journal_summary: str = ""

    # Metadata
    generated_at: datetime = Field(default_factory=datetime.utcnow)
