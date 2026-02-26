"""
agents/brains/web.py — Web Application Security Agent Brain
============================================================
Agent Type : web
LLM Model  : Claude 3.5 Sonnet
Loop Type  : ReAct
Max Steps  : 80
Token Budget: 200,000

Purpose: Comprehensive web application security testing including
XSS, CSRF, SSRF, directory traversal, header analysis, cookie
security, CORS misconfigurations, and SSL/TLS assessment.
"""

from __future__ import annotations

from typing import Any, ClassVar, Dict, List, Optional, Type

from pydantic import BaseModel, Field

from agents.base import AgentBrain


# ---------------------------------------------------------------------------
# Input Schema
# ---------------------------------------------------------------------------
class WebInput(BaseModel):
    """Validated input for the Web Application Security Agent."""
    run_id: str = Field(..., description="Unique run identifier")
    task_id: str = Field(..., description="Unique task identifier")
    target: str = Field(..., description="Target URL or web application base URL")
    scope: Dict[str, Any] = Field(default_factory=dict, description="Engagement scope")
    discovered_hosts: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Hosts discovered by recon agent",
    )
    entry_points: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Entry points identified by recon agent",
    )
    technologies: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Technology stack from recon agent",
    )
    test_categories: List[str] = Field(
        default_factory=lambda: ["xss", "csrf", "ssrf", "traversal", "headers", "cookies", "cors", "ssl"],
        description="Categories of tests to run",
    )
    authentication: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Authentication credentials if provided",
    )


# ---------------------------------------------------------------------------
# Output Schema
# ---------------------------------------------------------------------------
class WebVulnerability(BaseModel):
    """A web vulnerability finding."""
    vuln_id: str = Field(default="", description="Unique vulnerability identifier")
    title: str = Field(..., description="Vulnerability title")
    vuln_type: str = Field(..., description="Type: xss_reflected, xss_stored, xss_dom, csrf, ssrf, path_traversal, open_redirect, etc.")
    severity: str = Field(..., description="Severity: critical, high, medium, low, informational")
    url: str = Field(default="", description="Affected URL")
    parameter: str = Field(default="", description="Affected parameter")
    payload: str = Field(default="", description="Proof-of-concept payload used")
    evidence: str = Field(default="", description="Evidence of exploitation (response snippet, etc.)")
    description: str = Field(default="", description="Detailed technical description")
    remediation: str = Field(default="", description="Specific remediation advice")
    cvss_score: Optional[float] = Field(default=None, description="CVSS 3.1 base score")
    cwe_id: str = Field(default="", description="CWE identifier (e.g., CWE-79)")
    confidence: float = Field(default=0.0, description="Confidence level 0.0-1.0")
    request: str = Field(default="", description="HTTP request that triggered the finding")
    response_snippet: str = Field(default="", description="Relevant response snippet")


class HeaderAnalysis(BaseModel):
    """Security header analysis result."""
    header: str
    present: bool
    value: str = ""
    status: str = "missing"  # present, missing, misconfigured
    recommendation: str = ""


class CookieAnalysis(BaseModel):
    """Cookie security analysis result."""
    name: str
    secure: bool = False
    httponly: bool = False
    samesite: str = ""
    path: str = "/"
    domain: str = ""
    issues: List[str] = Field(default_factory=list)


class WebOutput(BaseModel):
    """Validated output from the Web Application Security Agent."""
    target: str = Field(..., description="Target URL as provided")
    vulnerabilities: List[WebVulnerability] = Field(
        default_factory=list,
        description="All discovered web vulnerabilities",
    )
    header_analysis: List[HeaderAnalysis] = Field(
        default_factory=list,
        description="Security header analysis results",
    )
    cookie_analysis: List[CookieAnalysis] = Field(
        default_factory=list,
        description="Cookie security analysis results",
    )
    cors_findings: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="CORS misconfiguration findings",
    )
    ssl_findings: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="SSL/TLS configuration findings",
    )
    forms_discovered: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Forms discovered during testing",
    )
    total_requests_made: int = Field(default=0, description="Total HTTP requests made")
    summary: str = Field(default="", description="Executive summary of web security posture")
    risk_score: float = Field(default=0.0, description="Overall risk score 0.0-10.0")


# ---------------------------------------------------------------------------
# Tool Definitions
# ---------------------------------------------------------------------------
WEB_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "http_request",
            "description": (
                "Send an HTTP request to a target URL with full control over method, "
                "headers, body, and parameters. Returns full response including headers and body."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Target URL"},
                    "method": {"type": "string", "description": "HTTP method: GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD"},
                    "headers": {"type": "object", "description": "Custom HTTP headers"},
                    "body": {"type": "string", "description": "Request body"},
                    "params": {"type": "object", "description": "URL query parameters"},
                    "follow_redirects": {"type": "boolean", "description": "Follow redirects (default: true)"},
                    "timeout": {"type": "integer", "description": "Request timeout in seconds"},
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "xss_scan",
            "description": (
                "Test a URL/parameter combination for Cross-Site Scripting (XSS) vulnerabilities. "
                "Tests for reflected, stored, and DOM-based XSS using multiple payloads."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Target URL"},
                    "parameter": {"type": "string", "description": "Parameter to test"},
                    "method": {"type": "string", "description": "HTTP method: GET or POST"},
                    "xss_type": {"type": "string", "description": "Type: reflected, stored, dom, all"},
                    "payload_set": {"type": "string", "description": "Payload set: basic, evasion, polyglot"},
                    "context": {"type": "string", "description": "Injection context: html, attribute, javascript, url"},
                },
                "required": ["url", "parameter"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "csrf_check",
            "description": (
                "Check a form or endpoint for Cross-Site Request Forgery (CSRF) protection. "
                "Analyses tokens, SameSite cookies, and Origin/Referer validation."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "URL of the form or endpoint"},
                    "method": {"type": "string", "description": "HTTP method the form uses"},
                    "form_data": {"type": "object", "description": "Form fields and values"},
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "directory_bruteforce",
            "description": (
                "Brute-force discover hidden directories and files on a web server "
                "using wordlists. Identifies backup files, admin panels, and sensitive paths."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Base URL to scan"},
                    "wordlist": {"type": "string", "description": "Wordlist: common, medium, large, api"},
                    "extensions": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "File extensions to append (e.g., .php, .bak, .conf)",
                    },
                    "recursive": {"type": "boolean", "description": "Recurse into discovered directories"},
                    "status_codes": {
                        "type": "array",
                        "items": {"type": "integer"},
                        "description": "HTTP status codes to report (default: 200, 201, 301, 302, 403)",
                    },
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "header_analysis",
            "description": (
                "Analyse HTTP response headers of a target for security misconfigurations. "
                "Checks for CSP, HSTS, X-Frame-Options, X-Content-Type-Options, and more."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "URL to analyse headers for"},
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "cookie_analysis",
            "description": (
                "Analyse cookies set by a web application for security issues. "
                "Checks Secure, HttpOnly, SameSite flags, scope, and predictability."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "URL to collect and analyse cookies from"},
                    "session_cookie_name": {"type": "string", "description": "Name of the session cookie to focus on"},
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "cors_check",
            "description": (
                "Test a URL for CORS misconfigurations. Sends requests with various "
                "Origin headers to detect overly permissive access control."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "URL to test"},
                    "origin_tests": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Custom origins to test (also tests null, subdomain, reflection)",
                    },
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "ssl_tls_check",
            "description": (
                "Analyse SSL/TLS configuration of a target. Checks certificate validity, "
                "protocol versions, cipher suites, and known vulnerabilities."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "host": {"type": "string", "description": "Hostname to check"},
                    "port": {"type": "integer", "description": "Port number (default: 443)"},
                },
                "required": ["host"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "ssrf_test",
            "description": (
                "Test a URL/parameter for Server-Side Request Forgery (SSRF) vulnerabilities. "
                "Attempts to make the server fetch internal resources or interact with external canary."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Target URL with potential SSRF parameter"},
                    "parameter": {"type": "string", "description": "Parameter to inject SSRF payload into"},
                    "method": {"type": "string", "description": "HTTP method"},
                    "callback_url": {"type": "string", "description": "Callback URL for out-of-band detection"},
                },
                "required": ["url", "parameter"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "path_traversal_test",
            "description": (
                "Test a URL/parameter for path traversal vulnerabilities. "
                "Attempts to read files outside the web root using various bypass techniques."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Target URL"},
                    "parameter": {"type": "string", "description": "Parameter to test"},
                    "os_type": {"type": "string", "description": "Target OS: linux, windows, auto"},
                },
                "required": ["url", "parameter"],
            },
        },
    },
]


# ---------------------------------------------------------------------------
# Brain Class
# ---------------------------------------------------------------------------
class WebBrain(AgentBrain):
    """Web Application Security Agent Brain — tests for web vulnerabilities."""

    AGENT_TYPE: ClassVar[str] = "web"
    LLM_MODEL: ClassVar[str] = "claude-3-5-sonnet"
    MAX_STEPS: ClassVar[int] = 80
    TOKEN_BUDGET: ClassVar[int] = 200_000

    SYSTEM_PROMPT: ClassVar[str] = (
        "You are the Lucifer Web Application Security Agent — an expert web application "
        "penetration tester specialising in OWASP Top 10 and beyond.\n\n"
        "## Your Mission\n"
        "Perform comprehensive web application security testing on the target:\n"
        "1. **Cross-Site Scripting (XSS)** — Test all input vectors for reflected, stored, "
        "and DOM-based XSS. Use context-aware payloads and WAF bypass techniques.\n"
        "2. **Cross-Site Request Forgery (CSRF)** — Assess anti-CSRF protections on all "
        "state-changing operations.\n"
        "3. **Server-Side Request Forgery (SSRF)** — Probe URL parameters and file upload "
        "functionality for SSRF.\n"
        "4. **Directory Traversal** — Test file inclusion and path traversal in parameters "
        "that reference files or paths.\n"
        "5. **Security Headers** — Evaluate CSP, HSTS, X-Frame-Options, X-Content-Type-Options, "
        "Referrer-Policy, Permissions-Policy.\n"
        "6. **Cookie Security** — Check Secure, HttpOnly, SameSite flags, and session "
        "management practices.\n"
        "7. **CORS** — Test for overly permissive cross-origin resource sharing.\n"
        "8. **SSL/TLS** — Assess certificate validity, protocol versions, and cipher strength.\n\n"
        "## Methodology\n"
        "- Start by mapping the application: discover pages, forms, and API endpoints.\n"
        "- Analyse the technology stack to select appropriate payloads.\n"
        "- Test each input vector methodically — don't skip parameters.\n"
        "- Use evasion techniques when WAF is detected.\n"
        "- Validate findings with proof-of-concept payloads.\n"
        "- Rate each finding by severity with CVSS scoring.\n"
        "- Provide specific, actionable remediation for every finding.\n\n"
        "## Output Requirements\n"
        "Provide a complete list of web vulnerabilities found, security header analysis, "
        "cookie analysis, CORS findings, and SSL assessment. Include proof-of-concept "
        "payloads and evidence for each vulnerability."
    )

    # Active exploitation tools require approval
    APPROVAL_REQUIRED_TOOLS: ClassVar[List[str]] = [
        "ssrf_test",
    ]

    def get_tools(self) -> List[Dict[str, Any]]:
        return WEB_TOOLS

    def get_input_schema(self) -> Type[BaseModel]:
        return WebInput

    def get_output_schema(self) -> Type[BaseModel]:
        return WebOutput
