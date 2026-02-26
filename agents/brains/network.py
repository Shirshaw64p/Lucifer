"""
agents/brains/network.py — Network Security Agent Brain
=========================================================
Agent Type : network
LLM Model  : Claude 3.5 Haiku
Loop Type  : ReAct
Max Steps  : 40
Token Budget: 80,000

Purpose: Network-layer security assessment including protocol analysis,
firewall detection, network segmentation, DNS security, SNMP exposure,
and SSL/TLS configuration analysis.
"""

from __future__ import annotations

from typing import Any, ClassVar, Dict, List, Optional, Type

from pydantic import BaseModel, Field

from agents.base import AgentBrain


# ---------------------------------------------------------------------------
# Input Schema
# ---------------------------------------------------------------------------
class NetworkInput(BaseModel):
    """Validated input for the Network Security Agent."""
    run_id: str = Field(..., description="Unique run identifier")
    task_id: str = Field(..., description="Unique task identifier")
    target: str = Field(..., description="Target IP range, hostname, or CIDR block")
    scope: Dict[str, Any] = Field(default_factory=dict, description="Engagement scope")
    discovered_hosts: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Hosts and IPs discovered by recon agent",
    )
    open_ports: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Open ports discovered by recon agent",
    )
    test_areas: List[str] = Field(
        default_factory=lambda: ["protocols", "firewall", "dns", "snmp", "ssl_tls", "segmentation"],
        description="Network test areas to focus on",
    )


# ---------------------------------------------------------------------------
# Output Schema
# ---------------------------------------------------------------------------
class NetworkVulnerability(BaseModel):
    """A network-layer vulnerability finding."""
    finding_id: str = Field(default="", description="Unique finding ID")
    title: str = Field(..., description="Finding title")
    vuln_type: str = Field(
        ...,
        description="Type: weak_protocol, firewall_bypass, dns_zone_transfer, "
                    "snmp_public_community, ssl_weak_cipher, ssl_expired_cert, "
                    "network_segmentation_bypass, smb_signing_disabled, "
                    "cleartext_protocol, unnecessary_service",
    )
    severity: str = Field(..., description="Severity: critical, high, medium, low, informational")
    affected_host: str = Field(default="", description="Affected host IP/hostname")
    affected_port: int = Field(default=0, description="Affected port number")
    protocol: str = Field(default="", description="Affected protocol")
    description: str = Field(default="", description="Detailed description")
    evidence: str = Field(default="", description="Evidence and proof")
    remediation: str = Field(default="", description="Remediation steps")
    cvss_score: Optional[float] = Field(default=None, description="CVSS 3.1 score")
    cwe_id: str = Field(default="", description="CWE identifier")
    confidence: float = Field(default=0.0, description="Confidence 0.0-1.0")


class NetworkOutput(BaseModel):
    """Validated output from the Network Security Agent."""
    target: str = Field(..., description="Target as provided")
    vulnerabilities: List[NetworkVulnerability] = Field(
        default_factory=list,
        description="All network vulnerabilities discovered",
    )
    protocol_analysis: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Protocol analysis results per host/port",
    )
    firewall_assessment: Dict[str, Any] = Field(
        default_factory=dict,
        description="Firewall detection and rule analysis",
    )
    dns_findings: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="DNS security findings (zone transfers, etc.)",
    )
    ssl_tls_findings: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="SSL/TLS configuration findings",
    )
    snmp_findings: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="SNMP exposure findings",
    )
    network_map: Dict[str, Any] = Field(
        default_factory=dict,
        description="Network topology and segmentation assessment",
    )
    cleartext_services: List[Dict[str, str]] = Field(
        default_factory=list,
        description="Services using cleartext protocols",
    )
    summary: str = Field(default="", description="Executive summary")
    risk_score: float = Field(default=0.0, description="Overall network risk 0.0-10.0")


# ---------------------------------------------------------------------------
# Tool Definitions
# ---------------------------------------------------------------------------
NETWORK_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "nmap_scan",
            "description": (
                "Perform an Nmap scan with custom options. Supports service detection, "
                "OS fingerprinting, script scanning, and various scan types."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target host, IP, or CIDR range"},
                    "ports": {"type": "string", "description": "Port specification (e.g., '1-65535', 'top-1000')"},
                    "scan_type": {"type": "string", "description": "Scan type: syn, connect, udp, fin, xmas, null"},
                    "options": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Additional Nmap options: service_detect, os_detect, script_scan, traceroute",
                    },
                    "scripts": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "NSE scripts to run (e.g., ssl-enum-ciphers, smb-security-mode)",
                    },
                    "timing": {"type": "string", "description": "Timing: T0-T5 (paranoid to insane)"},
                },
                "required": ["target"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "protocol_analyze",
            "description": (
                "Analyse a specific network protocol on a host:port. "
                "Checks for protocol-specific vulnerabilities and misconfigurations."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "host": {"type": "string", "description": "Target host"},
                    "port": {"type": "integer", "description": "Target port"},
                    "protocol": {
                        "type": "string",
                        "description": "Protocol: ssh, ftp, smtp, telnet, rdp, smb, snmp, ldap, mysql, postgres",
                    },
                    "checks": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Specific checks: auth_methods, encryption, versions, known_vulns",
                    },
                },
                "required": ["host", "port", "protocol"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "firewall_detect",
            "description": (
                "Detect and fingerprint firewalls and packet filters. "
                "Uses various techniques to identify firewall type and rule gaps."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target host or IP"},
                    "ports": {"type": "string", "description": "Ports to probe"},
                    "techniques": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Techniques: ttl_analysis, window_analysis, fragment_scan, protocol_manipulation",
                    },
                },
                "required": ["target"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "network_trace",
            "description": (
                "Perform traceroute and network path analysis to map network "
                "topology and identify segmentation boundaries."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Destination host"},
                    "protocol": {"type": "string", "description": "Protocol: icmp, tcp, udp"},
                    "port": {"type": "integer", "description": "Port for TCP/UDP traceroute"},
                    "max_hops": {"type": "integer", "description": "Maximum hops (default: 30)"},
                },
                "required": ["target"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "dns_zone_transfer",
            "description": (
                "Attempt DNS zone transfer (AXFR) against the target's nameservers. "
                "Tests all discovered nameservers for misconfigured zone transfer."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "domain": {"type": "string", "description": "Target domain"},
                    "nameserver": {"type": "string", "description": "Specific nameserver to test (optional)"},
                },
                "required": ["domain"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "snmp_check",
            "description": (
                "Check for SNMP service exposure and attempt to enumerate using "
                "common community strings."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target IP"},
                    "port": {"type": "integer", "description": "SNMP port (default: 161)"},
                    "version": {"type": "string", "description": "SNMP version: v1, v2c, v3"},
                    "community_strings": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Community strings to test (default: public, private, community)",
                    },
                },
                "required": ["target"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "ssl_tls_check",
            "description": (
                "Comprehensive SSL/TLS assessment including protocol versions, "
                "cipher suites, certificate validation, and known vulnerabilities "
                "(BEAST, POODLE, Heartbleed, ROBOT, etc.)."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "host": {"type": "string", "description": "Target hostname"},
                    "port": {"type": "integer", "description": "Port (default: 443)"},
                    "checks": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Checks: protocols, ciphers, certificate, heartbleed, poodle, beast, robot, renegotiation",
                    },
                },
                "required": ["host"],
            },
        },
    },
]


# ---------------------------------------------------------------------------
# Brain Class
# ---------------------------------------------------------------------------
class NetworkBrain(AgentBrain):
    """Network Security Agent Brain — network-layer security assessment."""

    AGENT_TYPE: ClassVar[str] = "network"
    LLM_MODEL: ClassVar[str] = "claude-3-5-haiku"
    MAX_STEPS: ClassVar[int] = 40
    TOKEN_BUDGET: ClassVar[int] = 80_000

    SYSTEM_PROMPT: ClassVar[str] = (
        "You are the Lucifer Network Security Agent — an expert in network-layer "
        "penetration testing and infrastructure security assessment.\n\n"
        "## Your Mission\n"
        "Assess the target's network security posture:\n"
        "1. **Protocol Analysis** — Examine network services for protocol-specific "
        "vulnerabilities (SSH, FTP, SMTP, RDP, SMB, etc.). Check for weak ciphers, "
        "outdated versions, and cleartext protocols.\n"
        "2. **Firewall Assessment** — Detect and fingerprint firewalls. Identify filtered "
        "vs. closed ports and potential rule gaps.\n"
        "3. **DNS Security** — Test for DNS zone transfers, DNSSEC status, and DNS-based "
        "information disclosure.\n"
        "4. **SNMP Exposure** — Check for SNMP services with default or weak community "
        "strings. Enumerate system information if accessible.\n"
        "5. **SSL/TLS Assessment** — Comprehensive assessment of all TLS endpoints for "
        "protocol versions, cipher strength, certificate issues, and known vulnerabilities.\n"
        "6. **Network Segmentation** — Map network topology and test segmentation "
        "boundaries.\n\n"
        "## Methodology\n"
        "- Start with the open ports and hosts from recon as your baseline.\n"
        "- Perform protocol-specific analysis on each discovered service.\n"
        "- Test for cleartext protocols that should be encrypted.\n"
        "- Check firewall rules for inconsistencies and bypasses.\n"
        "- Assess all TLS endpoints for current best practices.\n"
        "- Document network topology and segmentation findings.\n\n"
        "## Output Requirements\n"
        "Provide detailed network vulnerabilities, protocol analysis per service, "
        "firewall assessment, DNS/SNMP findings, SSL/TLS analysis, and an overall "
        "network security posture summary."
    )

    # Active scanning beyond scope requires approval
    APPROVAL_REQUIRED_TOOLS: ClassVar[List[str]] = [
        "snmp_check",
    ]

    def get_tools(self) -> List[Dict[str, Any]]:
        return NETWORK_TOOLS

    def get_input_schema(self) -> Type[BaseModel]:
        return NetworkInput

    def get_output_schema(self) -> Type[BaseModel]:
        return NetworkOutput
