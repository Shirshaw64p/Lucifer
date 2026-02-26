"""
agents/brains/cloud.py — Cloud Security Agent Brain
=====================================================
Agent Type : cloud
LLM Model  : Claude 3.5 Sonnet
Loop Type  : ReAct
Max Steps  : 60
Token Budget: 150,000

Purpose: Assess cloud infrastructure security including AWS, Azure,
and GCP misconfigurations, IAM policies, storage bucket permissions,
container security, and cloud metadata exposure.
"""

from __future__ import annotations

from typing import Any, ClassVar, Dict, List, Optional, Type

from pydantic import BaseModel, Field

from agents.base import AgentBrain


# ---------------------------------------------------------------------------
# Input Schema
# ---------------------------------------------------------------------------
class CloudInput(BaseModel):
    """Validated input for the Cloud Security Agent."""
    run_id: str = Field(..., description="Unique run identifier")
    task_id: str = Field(..., description="Unique task identifier")
    target: str = Field(..., description="Target domain, IP, or cloud resource identifier")
    scope: Dict[str, Any] = Field(default_factory=dict, description="Engagement scope")
    cloud_provider: str = Field(
        default="auto",
        description="Cloud provider: aws, azure, gcp, auto-detect",
    )
    discovered_hosts: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Hosts discovered by recon agent",
    )
    technologies: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Technology stack from recon (cloud indicators)",
    )
    cloud_endpoints: List[str] = Field(
        default_factory=list,
        description="Discovered cloud-specific endpoints (S3, blob, etc.)",
    )
    credentials: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Cloud credentials for authenticated assessment (if authorised)",
    )


# ---------------------------------------------------------------------------
# Output Schema
# ---------------------------------------------------------------------------
class CloudMisconfiguration(BaseModel):
    """A cloud misconfiguration finding."""
    finding_id: str = Field(default="", description="Unique finding ID")
    title: str = Field(..., description="Finding title")
    cloud_provider: str = Field(default="", description="Affected cloud provider")
    service: str = Field(default="", description="Cloud service (S3, IAM, EC2, etc.)")
    resource: str = Field(default="", description="Specific resource identifier")
    vuln_type: str = Field(
        ...,
        description="Type: public_bucket, iam_overprivileged, metadata_exposed, "
                    "encryption_disabled, logging_disabled, mfa_missing, network_exposure, "
                    "container_escape, secrets_exposed, insecure_api_gateway",
    )
    severity: str = Field(..., description="Severity: critical, high, medium, low, informational")
    description: str = Field(default="", description="Detailed description")
    evidence: str = Field(default="", description="Evidence and proof")
    remediation: str = Field(default="", description="Cloud-specific remediation")
    compliance_impact: List[str] = Field(
        default_factory=list,
        description="Compliance frameworks affected (CIS, SOC2, PCI-DSS, etc.)",
    )
    cvss_score: Optional[float] = Field(default=None, description="CVSS 3.1 score")
    cwe_id: str = Field(default="", description="CWE identifier")
    confidence: float = Field(default=0.0, description="Confidence 0.0-1.0")


class CloudOutput(BaseModel):
    """Validated output from the Cloud Security Agent."""
    target: str = Field(..., description="Target as provided")
    cloud_provider: str = Field(default="unknown", description="Detected cloud provider")
    misconfigurations: List[CloudMisconfiguration] = Field(
        default_factory=list,
        description="All cloud misconfigurations found",
    )
    storage_findings: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Storage (S3/Blob/GCS) specific findings",
    )
    iam_findings: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="IAM/access control findings",
    )
    network_findings: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Cloud network configuration findings",
    )
    container_findings: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Container/Kubernetes findings",
    )
    metadata_exposed: bool = Field(
        default=False,
        description="Whether cloud metadata service is accessible",
    )
    compliance_summary: Dict[str, Any] = Field(
        default_factory=dict,
        description="Compliance posture summary (CIS Benchmarks, etc.)",
    )
    summary: str = Field(default="", description="Executive summary")
    risk_score: float = Field(default=0.0, description="Overall cloud risk 0.0-10.0")


# ---------------------------------------------------------------------------
# Tool Definitions
# ---------------------------------------------------------------------------
CLOUD_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "aws_s3_check",
            "description": (
                "Check AWS S3 buckets for misconfigurations. Tests for public access, "
                "ACL issues, bucket policy exposure, and server-side encryption status."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "bucket_name": {"type": "string", "description": "S3 bucket name to check"},
                    "region": {"type": "string", "description": "AWS region (default: us-east-1)"},
                    "checks": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Checks: public_access, acl, policy, encryption, versioning, logging",
                    },
                },
                "required": ["bucket_name"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "aws_iam_check",
            "description": (
                "Assess AWS IAM configuration for overprivileged roles, missing MFA, "
                "unused credentials, and policy analysis."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "resource": {"type": "string", "description": "IAM resource to assess (user, role, policy ARN)"},
                    "checks": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Checks: admin_access, mfa_status, key_rotation, unused_creds, policy_analysis",
                    },
                },
                "required": ["resource"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "azure_blob_check",
            "description": (
                "Check Azure Blob Storage containers for public access, anonymous read, "
                "shared access signatures, and encryption configuration."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "storage_account": {"type": "string", "description": "Azure storage account name"},
                    "container_name": {"type": "string", "description": "Container name (if known)"},
                    "checks": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Checks: public_access, sas_tokens, encryption, network_rules",
                    },
                },
                "required": ["storage_account"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "gcp_bucket_check",
            "description": (
                "Check Google Cloud Storage buckets for public access, IAM bindings, "
                "uniform bucket-level access, and encryption." 
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "bucket_name": {"type": "string", "description": "GCS bucket name"},
                    "checks": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Checks: public_access, iam_bindings, uniform_access, encryption",
                    },
                },
                "required": ["bucket_name"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "cloud_metadata_check",
            "description": (
                "Test for cloud metadata service exposure (SSRF to metadata). "
                "Checks AWS IMDS, Azure IMDS, GCP metadata server accessibility "
                "from the target application."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target_url": {"type": "string", "description": "Web application URL to test SSRF from"},
                    "parameter": {"type": "string", "description": "URL parameter susceptible to SSRF"},
                    "cloud_provider": {"type": "string", "description": "Provider: aws, azure, gcp, all"},
                },
                "required": ["target_url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "terraform_scan",
            "description": (
                "Scan exposed Terraform state files or Infrastructure-as-Code "
                "for secrets, misconfigurations, and compliance violations."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "URL to Terraform state file or IaC repository"},
                    "scan_type": {"type": "string", "description": "Type: state_file, tfplan, hcl_files"},
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "kubernetes_check",
            "description": (
                "Assess Kubernetes cluster security including API server exposure, "
                "RBAC configuration, network policies, and pod security."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "api_server_url": {"type": "string", "description": "Kubernetes API server URL"},
                    "auth_token": {"type": "string", "description": "Service account token if available"},
                    "checks": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Checks: api_exposure, rbac, network_policies, pod_security, secrets, dashboard",
                    },
                },
                "required": ["api_server_url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "container_scan",
            "description": (
                "Scan container images or registries for vulnerabilities, "
                "misconfigurations, and exposed secrets."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "image": {"type": "string", "description": "Container image to scan (registry/image:tag)"},
                    "registry_url": {"type": "string", "description": "Container registry URL"},
                    "checks": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Checks: cve_scan, misconfig, secrets, base_image, privileged",
                    },
                },
                "required": ["image"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "http_request",
            "description": "Send a custom HTTP request for manual cloud endpoint testing.",
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
class CloudBrain(AgentBrain):
    """Cloud Security Agent Brain — assesses cloud infrastructure security."""

    AGENT_TYPE: ClassVar[str] = "cloud"
    LLM_MODEL: ClassVar[str] = "claude-3-5-sonnet"
    MAX_STEPS: ClassVar[int] = 60
    TOKEN_BUDGET: ClassVar[int] = 150_000

    SYSTEM_PROMPT: ClassVar[str] = (
        "You are the Lucifer Cloud Security Agent — an expert in cloud infrastructure "
        "security assessment for AWS, Azure, and Google Cloud Platform.\n\n"
        "## Your Mission\n"
        "Assess the target's cloud infrastructure for security misconfigurations:\n"
        "1. **Storage Security** — Check S3 buckets, Azure Blob containers, and GCS buckets "
        "for public access, improper ACLs, missing encryption, and data exposure.\n"
        "2. **IAM & Access Control** — Assess identity and access management for overprivileged "
        "roles, missing MFA, unused credentials, and policy weaknesses.\n"
        "3. **Network Exposure** — Check security groups, network ACLs, and firewall rules "
        "for overly permissive access.\n"
        "4. **Metadata Service** — Test for cloud metadata service exposure via SSRF vectors.\n"
        "5. **Container Security** — Assess Kubernetes clusters, container images, and "
        "orchestration platforms for vulnerabilities and misconfigurations.\n"
        "6. **Infrastructure as Code** — Scan any exposed Terraform state files or IaC "
        "configurations for secrets and misconfigurations.\n"
        "7. **Compliance** — Map findings to CIS Benchmarks, SOC 2, PCI-DSS, and other "
        "compliance frameworks.\n\n"
        "## Methodology\n"
        "- Start by identifying the cloud provider(s) in use.\n"
        "- Enumerate cloud resources visible from external reconnaissance.\n"
        "- Test storage buckets/containers for public access first (quick wins).\n"
        "- Check for metadata service exposure through known SSRF vectors.\n"
        "- If credentials are provided, perform authenticated configuration review.\n"
        "- Map all findings to compliance frameworks for remediation prioritisation.\n\n"
        "## Output Requirements\n"
        "Provide detailed cloud misconfigurations with compliance mapping, "
        "separate findings for storage, IAM, network, and containers, "
        "plus an overall cloud security posture assessment."
    )

    # Write/modify operations on cloud resources require approval
    APPROVAL_REQUIRED_TOOLS: ClassVar[List[str]] = [
        "cloud_metadata_check",
        "kubernetes_check",
    ]

    def get_tools(self) -> List[Dict[str, Any]]:
        return CLOUD_TOOLS

    def get_input_schema(self) -> Type[BaseModel]:
        return CloudInput

    def get_output_schema(self) -> Type[BaseModel]:
        return CloudOutput
