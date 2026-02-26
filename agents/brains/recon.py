"""
agents/brains/recon.py — Reconnaissance Agent Brain
====================================================
Agent Type : recon
LLM Model  : Claude 3.5 Haiku
Loop Type  : ReAct
Max Steps  : 50
Token Budget: 100,000

Purpose: Map the target's external attack surface through passive and
active reconnaissance. Enumerate subdomains, open ports, running
services, technology stacks, and potential entry points.
"""

from __future__ import annotations

from typing import Any, ClassVar, Dict, List, Optional, Type

from pydantic import BaseModel, Field

from agents.base import AgentBrain


# ---------------------------------------------------------------------------
# Input Schema
# ---------------------------------------------------------------------------
class ReconInput(BaseModel):
    """Validated input for the Reconnaissance Agent."""
    run_id: str = Field(..., description="Unique run identifier")
    task_id: str = Field(..., description="Unique task identifier")
    target: str = Field(..., description="Primary target domain, IP, or URL")
    scope: Dict[str, Any] = Field(
        default_factory=dict,
        description="Engagement scope definition (allowed domains, IPs, ports, methods)",
    )
    recon_depth: str = Field(
        default="standard",
        description="Reconnaissance depth: passive | standard | deep",
    )
    focus_areas: List[str] = Field(
        default_factory=list,
        description="Specific areas to focus on (e.g., subdomains, ports, tech_stack)",
    )
    exclude_patterns: List[str] = Field(
        default_factory=list,
        description="Patterns to exclude from reconnaissance",
    )


# ---------------------------------------------------------------------------
# Output Schema
# ---------------------------------------------------------------------------
class DiscoveredHost(BaseModel):
    """A discovered host/subdomain."""
    hostname: str
    ip_addresses: List[str] = Field(default_factory=list)
    source: str = ""
    is_alive: bool = False


class OpenPort(BaseModel):
    """An open port discovered on a host."""
    host: str
    port: int
    protocol: str = "tcp"
    service: str = ""
    version: str = ""
    banner: str = ""


class TechnologyFingerprint(BaseModel):
    """Technology detected on a target."""
    host: str
    category: str  # e.g., web_server, framework, cms, cdn, waf
    name: str
    version: str = ""
    confidence: float = 0.0


class EntryPoint(BaseModel):
    """A potential entry point for further testing."""
    url: str = ""
    host: str = ""
    port: int = 0
    entry_type: str = ""  # web_app, api, login_form, admin_panel, etc.
    notes: str = ""
    priority: str = "medium"  # critical, high, medium, low


class ReconOutput(BaseModel):
    """Validated output from the Reconnaissance Agent."""
    target: str = Field(..., description="Primary target as provided")
    discovered_hosts: List[DiscoveredHost] = Field(
        default_factory=list,
        description="All discovered subdomains and hosts",
    )
    open_ports: List[OpenPort] = Field(
        default_factory=list,
        description="All discovered open ports and services",
    )
    technologies: List[TechnologyFingerprint] = Field(
        default_factory=list,
        description="Detected technology stack and components",
    )
    entry_points: List[EntryPoint] = Field(
        default_factory=list,
        description="Identified potential entry points for attack",
    )
    dns_records: Dict[str, Any] = Field(
        default_factory=dict,
        description="DNS records (A, AAAA, MX, NS, TXT, CNAME, SOA)",
    )
    whois_info: Dict[str, Any] = Field(
        default_factory=dict,
        description="WHOIS registration information",
    )
    ssl_certificates: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="SSL/TLS certificate details",
    )
    waf_detected: Optional[str] = Field(
        default=None,
        description="Web Application Firewall detected (name or None)",
    )
    cdn_detected: Optional[str] = Field(
        default=None,
        description="CDN provider detected (name or None)",
    )
    attack_surface_summary: str = Field(
        default="",
        description="Human-readable summary of the attack surface",
    )
    recommendations: List[str] = Field(
        default_factory=list,
        description="Recommended next steps for other agents",
    )


# ---------------------------------------------------------------------------
# Tool Definitions
# ---------------------------------------------------------------------------
RECON_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "subdomain_enumerate",
            "description": (
                "Enumerate subdomains of a given domain using multiple sources "
                "(DNS brute-force, certificate transparency logs, search engines, "
                "passive DNS databases)."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "domain": {"type": "string", "description": "Target root domain"},
                    "methods": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Enumeration methods: dns_bruteforce, cert_transparency, passive_dns, search_engine",
                    },
                    "wordlist": {"type": "string", "description": "Wordlist name for brute-force (default: common)"},
                },
                "required": ["domain"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "port_scan",
            "description": (
                "Scan for open ports on a target host. Supports TCP SYN, TCP connect, "
                "and UDP scans with configurable port ranges."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target IP or hostname"},
                    "ports": {"type": "string", "description": "Port range (e.g., '1-1000', '80,443,8080', 'top-100')"},
                    "scan_type": {"type": "string", "description": "Scan type: syn | connect | udp"},
                    "timing": {"type": "string", "description": "Scan timing: slow | normal | fast | aggressive"},
                },
                "required": ["target"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "service_fingerprint",
            "description": (
                "Fingerprint services running on discovered open ports. "
                "Identifies service name, version, and banner information."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target IP or hostname"},
                    "port": {"type": "integer", "description": "Port number to fingerprint"},
                    "protocol": {"type": "string", "description": "Protocol: tcp | udp"},
                },
                "required": ["target", "port"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "dns_lookup",
            "description": (
                "Perform DNS lookups for various record types. "
                "Supports A, AAAA, MX, NS, TXT, CNAME, SOA, SRV records."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "domain": {"type": "string", "description": "Domain to query"},
                    "record_types": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Record types to query (default: all)",
                    },
                    "nameserver": {"type": "string", "description": "Custom nameserver to use"},
                },
                "required": ["domain"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "whois_lookup",
            "description": "Perform WHOIS lookup for domain registration information.",
            "parameters": {
                "type": "object",
                "properties": {
                    "domain": {"type": "string", "description": "Domain to look up"},
                },
                "required": ["domain"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "certificate_transparency",
            "description": (
                "Search Certificate Transparency logs for certificates issued "
                "to the target domain and its subdomains."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "domain": {"type": "string", "description": "Domain to search CT logs for"},
                    "include_expired": {"type": "boolean", "description": "Include expired certificates"},
                },
                "required": ["domain"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "web_crawl",
            "description": (
                "Crawl a web application to discover pages, forms, API endpoints, "
                "and other resources. Respects robots.txt and scope constraints."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Starting URL to crawl"},
                    "max_depth": {"type": "integer", "description": "Maximum crawl depth (default: 3)"},
                    "max_pages": {"type": "integer", "description": "Maximum pages to crawl (default: 100)"},
                    "follow_redirects": {"type": "boolean", "description": "Follow HTTP redirects"},
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "technology_detect",
            "description": (
                "Detect technologies used by a web application including web servers, "
                "frameworks, CMS, JavaScript libraries, CDNs, and WAFs."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "URL to analyse"},
                    "aggressive": {"type": "boolean", "description": "Use aggressive detection methods"},
                },
                "required": ["url"],
            },
        },
    },
]


# ---------------------------------------------------------------------------
# Brain Class
# ---------------------------------------------------------------------------
class ReconBrain(AgentBrain):
    """Reconnaissance Agent Brain — maps the target attack surface."""

    AGENT_TYPE: ClassVar[str] = "recon"
    LLM_MODEL: ClassVar[str] = "claude-3-5-haiku"
    MAX_STEPS: ClassVar[int] = 50
    TOKEN_BUDGET: ClassVar[int] = 100_000

    SYSTEM_PROMPT: ClassVar[str] = (
        "You are the Lucifer Reconnaissance Agent — an expert in mapping external "
        "attack surfaces for penetration testing engagements.\n\n"
        "## Your Mission\n"
        "Systematically discover and document the target's external footprint:\n"
        "1. **Subdomain Enumeration** — Find all subdomains via DNS brute-force, "
        "certificate transparency logs, passive DNS, and search engine dorking.\n"
        "2. **Port Scanning** — Identify open ports and running services on all "
        "discovered hosts.\n"
        "3. **Service Fingerprinting** — Determine exact versions of services to "
        "identify potential vulnerabilities.\n"
        "4. **Technology Detection** — Map the complete technology stack including "
        "web servers, frameworks, CMS, CDNs, and WAFs.\n"
        "5. **Entry Point Identification** — Catalogue all potential entry points "
        "(web apps, APIs, login forms, admin panels, exposed services).\n\n"
        "## Methodology\n"
        "- Start with passive reconnaissance (DNS, WHOIS, CT logs) before active scanning.\n"
        "- Progress from broad discovery to targeted fingerprinting.\n"
        "- Prioritise findings by potential impact and exploitability.\n"
        "- Always stay within the defined scope boundaries.\n"
        "- Document everything — other agents depend on your findings.\n\n"
        "## Output Requirements\n"
        "Provide a comprehensive attack surface map including all discovered hosts, "
        "open ports, technologies, and entry points. Include an attack surface summary "
        "and recommendations for which specialised agents should investigate further."
    )

    # No approval gates needed — reconnaissance is passive/low-risk
    APPROVAL_REQUIRED_TOOLS: ClassVar[List[str]] = []

    def get_tools(self) -> List[Dict[str, Any]]:
        return RECON_TOOLS

    def get_input_schema(self) -> Type[BaseModel]:
        return ReconInput

    def get_output_schema(self) -> Type[BaseModel]:
        return ReconOutput
