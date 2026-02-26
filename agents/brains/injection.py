"""
agents/brains/injection.py — Injection Testing Agent Brain
===========================================================
Agent Type : injection
LLM Model  : Claude 3.5 Sonnet
Loop Type  : ReAct
Max Steps  : 100
Token Budget: 250,000

Purpose: Comprehensive injection vulnerability testing including SQL
injection, command injection, LDAP injection, template injection,
XPath injection, and other injection vectors.
"""

from __future__ import annotations

from typing import Any, ClassVar, Dict, List, Optional, Type

from pydantic import BaseModel, Field

from agents.base import AgentBrain


# ---------------------------------------------------------------------------
# Input Schema
# ---------------------------------------------------------------------------
class InjectionInput(BaseModel):
    """Validated input for the Injection Testing Agent."""
    run_id: str = Field(..., description="Unique run identifier")
    task_id: str = Field(..., description="Unique task identifier")
    target: str = Field(..., description="Target URL or application endpoint")
    scope: Dict[str, Any] = Field(default_factory=dict, description="Engagement scope")
    entry_points: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Entry points from recon/web agents with parameters to test",
    )
    technologies: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Technology stack from recon agent (informs payload selection)",
    )
    discovered_forms: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Forms discovered by web agent",
    )
    injection_types: List[str] = Field(
        default_factory=lambda: ["sqli", "cmdi", "ldapi", "ssti", "xpathi", "nosqli"],
        description="Injection types to test",
    )
    authentication: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Authentication credentials for authenticated testing",
    )
    waf_detected: Optional[str] = Field(
        default=None,
        description="WAF name if detected — triggers evasion payloads",
    )


# ---------------------------------------------------------------------------
# Output Schema
# ---------------------------------------------------------------------------
class InjectionFinding(BaseModel):
    """A single injection vulnerability finding."""
    finding_id: str = Field(default="", description="Unique finding ID")
    title: str = Field(..., description="Finding title")
    injection_type: str = Field(
        ...,
        description="Type: sqli_union, sqli_blind_boolean, sqli_blind_time, sqli_error, "
                    "sqli_stacked, cmdi, cmdi_blind, ldapi, ssti, xpathi, nosqli, header_injection",
    )
    severity: str = Field(..., description="Severity: critical, high, medium, low")
    url: str = Field(default="", description="Affected URL")
    parameter: str = Field(default="", description="Vulnerable parameter")
    method: str = Field(default="GET", description="HTTP method")
    payload: str = Field(default="", description="Proof-of-concept payload")
    payload_encoded: str = Field(default="", description="URL-encoded or otherwise encoded payload")
    evidence: str = Field(default="", description="Evidence of exploitation")
    database_type: Optional[str] = Field(default=None, description="Identified database type (for SQLi)")
    data_extracted: List[str] = Field(
        default_factory=list,
        description="Any data successfully extracted (table names, user info, etc.)",
    )
    description: str = Field(default="", description="Detailed technical description")
    remediation: str = Field(default="", description="Specific remediation steps")
    cvss_score: Optional[float] = Field(default=None, description="CVSS 3.1 base score")
    cwe_id: str = Field(default="", description="CWE identifier")
    confidence: float = Field(default=0.0, description="Confidence 0.0-1.0")
    waf_bypassed: bool = Field(default=False, description="Whether WAF was bypassed")
    request: str = Field(default="", description="Full HTTP request used")
    response_snippet: str = Field(default="", description="Relevant response snippet")


class InjectionOutput(BaseModel):
    """Validated output from the Injection Testing Agent."""
    target: str = Field(..., description="Target as provided")
    findings: List[InjectionFinding] = Field(
        default_factory=list,
        description="All injection vulnerabilities discovered",
    )
    parameters_tested: int = Field(default=0, description="Total parameters tested")
    payloads_sent: int = Field(default=0, description="Total payloads sent")
    waf_bypass_techniques: List[str] = Field(
        default_factory=list,
        description="WAF bypass techniques that were successful",
    )
    database_info: Dict[str, Any] = Field(
        default_factory=dict,
        description="Database information extracted (type, version, tables, etc.)",
    )
    summary: str = Field(default="", description="Executive summary of injection testing")
    risk_score: float = Field(default=0.0, description="Overall injection risk score 0.0-10.0")


# ---------------------------------------------------------------------------
# Tool Definitions
# ---------------------------------------------------------------------------
INJECTION_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "sql_inject_test",
            "description": (
                "Test a parameter for SQL injection vulnerabilities. Supports "
                "error-based, union-based, blind boolean, blind time-based, and "
                "stacked query injection techniques. Auto-detects database type."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Target URL"},
                    "parameter": {"type": "string", "description": "Parameter to inject into"},
                    "method": {"type": "string", "description": "HTTP method: GET or POST"},
                    "technique": {
                        "type": "string",
                        "description": "Technique: error, union, blind_boolean, blind_time, stacked, all",
                    },
                    "dbms": {"type": "string", "description": "Target DBMS hint: mysql, postgres, mssql, oracle, sqlite, auto"},
                    "level": {"type": "integer", "description": "Test level 1-5 (higher = more payloads)"},
                    "risk": {"type": "integer", "description": "Risk level 1-3 (higher = more dangerous payloads)"},
                    "tamper": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Tamper scripts for WAF bypass: space2comment, between, randomcase, etc.",
                    },
                },
                "required": ["url", "parameter"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "command_inject_test",
            "description": (
                "Test a parameter for OS command injection vulnerabilities. "
                "Tests both in-band and blind (time-based, out-of-band) command injection."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Target URL"},
                    "parameter": {"type": "string", "description": "Parameter to test"},
                    "method": {"type": "string", "description": "HTTP method"},
                    "os_type": {"type": "string", "description": "Target OS: linux, windows, auto"},
                    "separator": {"type": "string", "description": "Command separator to try: ;, |, &&, ||, newline"},
                    "callback_url": {"type": "string", "description": "Callback for blind detection"},
                },
                "required": ["url", "parameter"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "ldap_inject_test",
            "description": (
                "Test a parameter for LDAP injection vulnerabilities. "
                "Tests authentication bypass and data extraction via LDAP query manipulation."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Target URL"},
                    "parameter": {"type": "string", "description": "Parameter to test"},
                    "method": {"type": "string", "description": "HTTP method"},
                    "auth_context": {"type": "boolean", "description": "Whether this is an authentication form"},
                },
                "required": ["url", "parameter"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "template_inject_test",
            "description": (
                "Test a parameter for Server-Side Template Injection (SSTI). "
                "Auto-detects template engine (Jinja2, Twig, Freemarker, etc.) "
                "and tests for code execution."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Target URL"},
                    "parameter": {"type": "string", "description": "Parameter to test"},
                    "method": {"type": "string", "description": "HTTP method"},
                    "engine_hint": {"type": "string", "description": "Template engine hint: jinja2, twig, freemarker, velocity, auto"},
                },
                "required": ["url", "parameter"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "xpath_inject_test",
            "description": (
                "Test a parameter for XPath injection vulnerabilities. "
                "Tests authentication bypass and data extraction via XPath query manipulation."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Target URL"},
                    "parameter": {"type": "string", "description": "Parameter to test"},
                    "method": {"type": "string", "description": "HTTP method"},
                },
                "required": ["url", "parameter"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "nosql_inject_test",
            "description": (
                "Test a parameter for NoSQL injection vulnerabilities. "
                "Supports MongoDB, CouchDB, and other NoSQL databases. "
                "Tests operator injection, JavaScript injection, and query manipulation."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Target URL"},
                    "parameter": {"type": "string", "description": "Parameter to test"},
                    "method": {"type": "string", "description": "HTTP method"},
                    "dbms": {"type": "string", "description": "NoSQL DB: mongodb, couchdb, auto"},
                    "content_type": {"type": "string", "description": "Content type: json, form-urlencoded"},
                },
                "required": ["url", "parameter"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "http_request",
            "description": (
                "Send a custom HTTP request for manual injection testing. "
                "Full control over method, headers, body, and encoding."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Target URL"},
                    "method": {"type": "string", "description": "HTTP method"},
                    "headers": {"type": "object", "description": "Custom headers"},
                    "body": {"type": "string", "description": "Request body"},
                    "params": {"type": "object", "description": "Query parameters"},
                    "content_type": {"type": "string", "description": "Content-Type header value"},
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "payload_generate",
            "description": (
                "Generate injection payloads tailored to the target context. "
                "Supports WAF evasion, encoding, and context-specific modifications."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "injection_type": {"type": "string", "description": "Type: sqli, cmdi, ssti, xpathi, nosqli, ldapi"},
                    "context": {"type": "string", "description": "Injection context: string, numeric, column, filename"},
                    "dbms": {"type": "string", "description": "Target DBMS for SQLi payloads"},
                    "waf_bypass": {"type": "boolean", "description": "Generate WAF evasion variants"},
                    "encoding": {"type": "string", "description": "Encoding: url, double-url, unicode, hex, base64"},
                    "count": {"type": "integer", "description": "Number of payloads to generate"},
                },
                "required": ["injection_type"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "blind_inject_detect",
            "description": (
                "Detect blind injection vulnerabilities using differential analysis. "
                "Compares responses between true/false conditions or uses time-based detection."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Target URL"},
                    "parameter": {"type": "string", "description": "Parameter to test"},
                    "method": {"type": "string", "description": "HTTP method"},
                    "detection_method": {"type": "string", "description": "Method: boolean, time, error, oob"},
                    "true_payload": {"type": "string", "description": "Payload for true condition"},
                    "false_payload": {"type": "string", "description": "Payload for false condition"},
                    "time_threshold": {"type": "number", "description": "Time threshold in seconds for time-based detection"},
                },
                "required": ["url", "parameter"],
            },
        },
    },
]


# ---------------------------------------------------------------------------
# Brain Class
# ---------------------------------------------------------------------------
class InjectionBrain(AgentBrain):
    """Injection Testing Agent Brain — comprehensive injection vulnerability testing."""

    AGENT_TYPE: ClassVar[str] = "injection"
    LLM_MODEL: ClassVar[str] = "claude-3-5-sonnet"
    MAX_STEPS: ClassVar[int] = 100
    TOKEN_BUDGET: ClassVar[int] = 250_000

    SYSTEM_PROMPT: ClassVar[str] = (
        "You are the Lucifer Injection Testing Agent — a world-class specialist in finding "
        "and exploiting injection vulnerabilities.\n\n"
        "## Your Mission\n"
        "Systematically test all input vectors for injection vulnerabilities:\n"
        "1. **SQL Injection** — Test for error-based, union-based, blind boolean, blind time-based, "
        "and stacked query SQLi. Identify the DBMS, extract schema info, and demonstrate data access.\n"
        "2. **Command Injection** — Test for OS command injection via common separators and "
        "blind techniques. Demonstrate code execution capability.\n"
        "3. **LDAP Injection** — Test LDAP queries in authentication and search functions.\n"
        "4. **Server-Side Template Injection (SSTI)** — Detect template engines and test for "
        "code execution through template syntax.\n"
        "5. **XPath Injection** — Test XML-backed applications for XPath query manipulation.\n"
        "6. **NoSQL Injection** — Test MongoDB/CouchDB applications for operator injection "
        "and query manipulation.\n\n"
        "## Methodology\n"
        "- Begin by analyzing the entry points and technology stack to prioritise tests.\n"
        "- For each parameter, start with detection payloads before exploitation.\n"
        "- Use the payload_generate tool to create context-aware and WAF-evading payloads.\n"
        "- For blind injection, use the blind_inject_detect tool with differential analysis.\n"
        "- Escalate from detection to proof-of-concept extraction.\n"
        "- If WAF is detected, progressively apply bypass techniques.\n"
        "- Document every successful payload and extraction step.\n"
        "- NEVER extract or modify actual user data — demonstrate capability only.\n\n"
        "## Output Requirements\n"
        "Provide detailed findings for each injection vulnerability including type, payload, "
        "evidence, DBMS info, CVSS score, and remediation. Include WAF bypass details if applicable."
    )

    # ALL injection tests require approval — these are high-risk active attack tools
    APPROVAL_REQUIRED_TOOLS: ClassVar[List[str]] = [
        "sql_inject_test",
        "command_inject_test",
        "ldap_inject_test",
        "template_inject_test",
        "xpath_inject_test",
        "nosql_inject_test",
        "blind_inject_detect",
    ]

    def get_tools(self) -> List[Dict[str, Any]]:
        return INJECTION_TOOLS

    def get_input_schema(self) -> Type[BaseModel]:
        return InjectionInput

    def get_output_schema(self) -> Type[BaseModel]:
        return InjectionOutput
