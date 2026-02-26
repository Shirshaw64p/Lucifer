"""
agents/brains/api.py — API Security Agent Brain
=================================================
Agent Type : api
LLM Model  : Claude 3.5 Sonnet
Loop Type  : ReAct
Max Steps  : 90
Token Budget: 225,000

Purpose: Comprehensive API security testing including REST, GraphQL,
and gRPC APIs. Tests for BOLA, BFLA, mass assignment, rate limiting,
improper input validation, and authentication bypass.
"""

from __future__ import annotations

from typing import Any, ClassVar, Dict, List, Optional, Type

from pydantic import BaseModel, Field

from agents.base import AgentBrain


# ---------------------------------------------------------------------------
# Input Schema
# ---------------------------------------------------------------------------
class APIInput(BaseModel):
    """Validated input for the API Security Agent."""
    run_id: str = Field(..., description="Unique run identifier")
    task_id: str = Field(..., description="Unique task identifier")
    target: str = Field(..., description="API base URL")
    scope: Dict[str, Any] = Field(default_factory=dict, description="Engagement scope")
    api_spec_url: Optional[str] = Field(
        default=None,
        description="URL to OpenAPI/Swagger spec, GraphQL introspection, or gRPC reflection",
    )
    entry_points: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="API endpoints discovered by recon agent",
    )
    technologies: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Technology stack from recon",
    )
    authentication: Optional[Dict[str, Any]] = Field(
        default=None,
        description="API authentication (API key, Bearer token, OAuth token)",
    )
    api_type: str = Field(
        default="rest",
        description="API type: rest, graphql, grpc, soap",
    )
    rate_limit_aware: bool = Field(
        default=True,
        description="Respect rate limits during testing",
    )


# ---------------------------------------------------------------------------
# Output Schema
# ---------------------------------------------------------------------------
class APIVulnerability(BaseModel):
    """An API security vulnerability."""
    finding_id: str = Field(default="", description="Unique finding ID")
    title: str = Field(..., description="Finding title")
    vuln_type: str = Field(
        ...,
        description="Type: bola, bfla, mass_assignment, excessive_data_exposure, "
                    "rate_limit_bypass, improper_auth, injection, ssrf, "
                    "graphql_introspection, graphql_dos, schema_leak, "
                    "broken_function_auth, security_misconfiguration",
    )
    severity: str = Field(..., description="Severity: critical, high, medium, low, informational")
    endpoint: str = Field(default="", description="Affected API endpoint")
    method: str = Field(default="", description="HTTP method")
    description: str = Field(default="", description="Detailed description")
    evidence: str = Field(default="", description="Evidence and PoC")
    payload: str = Field(default="", description="Attack payload used")
    remediation: str = Field(default="", description="Remediation steps")
    cvss_score: Optional[float] = Field(default=None, description="CVSS 3.1 score")
    cwe_id: str = Field(default="", description="CWE identifier")
    owasp_api_category: str = Field(default="", description="OWASP API Top 10 category")
    confidence: float = Field(default=0.0, description="Confidence 0.0-1.0")
    request: str = Field(default="", description="Full request")
    response_snippet: str = Field(default="", description="Response snippet")


class APIEndpointInfo(BaseModel):
    """Discovered API endpoint information."""
    path: str
    method: str
    parameters: List[Dict[str, Any]] = Field(default_factory=list)
    auth_required: bool = False
    rate_limited: bool = False
    response_schema: Dict[str, Any] = Field(default_factory=dict)


class APIOutput(BaseModel):
    """Validated output from the API Security Agent."""
    target: str = Field(..., description="API base URL as provided")
    api_type: str = Field(default="rest", description="Detected API type")
    vulnerabilities: List[APIVulnerability] = Field(
        default_factory=list,
        description="All API vulnerabilities discovered",
    )
    endpoints_discovered: List[APIEndpointInfo] = Field(
        default_factory=list,
        description="All API endpoints discovered and tested",
    )
    schema_info: Dict[str, Any] = Field(
        default_factory=dict,
        description="API schema/spec information extracted",
    )
    authentication_assessment: Dict[str, Any] = Field(
        default_factory=dict,
        description="API authentication mechanism assessment",
    )
    rate_limiting_assessment: Dict[str, Any] = Field(
        default_factory=dict,
        description="Rate limiting effectiveness assessment",
    )
    data_exposure_findings: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Excessive data exposure findings",
    )
    total_endpoints_tested: int = Field(default=0)
    total_requests_made: int = Field(default=0)
    summary: str = Field(default="", description="Executive summary")
    risk_score: float = Field(default=0.0, description="Overall API risk 0.0-10.0")


# ---------------------------------------------------------------------------
# Tool Definitions
# ---------------------------------------------------------------------------
API_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "api_discover",
            "description": (
                "Discover API endpoints through common path patterns, documentation paths, "
                "and response analysis. Identifies REST, GraphQL, and gRPC endpoints."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "base_url": {"type": "string", "description": "API base URL"},
                    "wordlist": {"type": "string", "description": "Endpoint wordlist: common, api-specific, large"},
                    "api_type": {"type": "string", "description": "API type hint: rest, graphql, grpc, auto"},
                },
                "required": ["base_url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "openapi_parse",
            "description": (
                "Fetch and parse an OpenAPI/Swagger specification. Extracts all endpoints, "
                "parameters, schemas, and authentication requirements."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "spec_url": {"type": "string", "description": "URL to OpenAPI/Swagger spec (JSON or YAML)"},
                    "auth_header": {"type": "string", "description": "Auth header to use when fetching spec"},
                },
                "required": ["spec_url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "graphql_introspect",
            "description": (
                "Perform GraphQL introspection to discover the full schema including "
                "types, queries, mutations, and subscriptions."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "GraphQL endpoint URL"},
                    "auth_header": {"type": "string", "description": "Authorization header value"},
                    "depth": {"type": "integer", "description": "Introspection depth (default: 5)"},
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "bola_test",
            "description": (
                "Test for Broken Object Level Authorization (BOLA/IDOR). "
                "Attempts to access resources belonging to other users by manipulating "
                "object identifiers in API requests."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "API endpoint with object identifier"},
                    "method": {"type": "string", "description": "HTTP method"},
                    "id_parameter": {"type": "string", "description": "Parameter containing the object ID"},
                    "current_id": {"type": "string", "description": "Current user's object ID"},
                    "target_ids": {"type": "array", "items": {"type": "string"}, "description": "IDs to try"},
                    "auth_token": {"type": "string", "description": "Auth token of current user"},
                    "id_type": {"type": "string", "description": "ID type: numeric, uuid, sequential"},
                },
                "required": ["url", "id_parameter"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "bfla_test",
            "description": (
                "Test for Broken Function Level Authorization (BFLA). "
                "Attempts to access administrative or privileged API functions "
                "using a regular user's credentials."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Admin/privileged endpoint URL"},
                    "method": {"type": "string", "description": "HTTP method"},
                    "auth_token": {"type": "string", "description": "Regular user's auth token"},
                    "admin_endpoints": {"type": "array", "items": {"type": "string"}, "description": "Admin endpoints to test"},
                    "body": {"type": "object", "description": "Request body"},
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "mass_assignment_test",
            "description": (
                "Test for mass assignment vulnerabilities by including extra properties "
                "in API requests that shouldn't be user-modifiable (role, isAdmin, etc.)."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "API endpoint that accepts object data"},
                    "method": {"type": "string", "description": "HTTP method: POST, PUT, PATCH"},
                    "base_data": {"type": "object", "description": "Normal request data"},
                    "extra_fields": {"type": "object", "description": "Extra fields to inject (role, isAdmin, etc.)"},
                    "auth_token": {"type": "string", "description": "Auth token"},
                },
                "required": ["url", "method", "base_data", "extra_fields"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "rate_limit_test",
            "description": (
                "Test API rate limiting effectiveness. Sends requests at increasing rates "
                "to determine limits and test for bypass techniques."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "API endpoint to test"},
                    "method": {"type": "string", "description": "HTTP method"},
                    "requests_per_second": {"type": "integer", "description": "Starting rate (default: 10)"},
                    "duration_seconds": {"type": "integer", "description": "Test duration (default: 30)"},
                    "bypass_techniques": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Bypass: ip_rotation, header_manipulation, path_normalization",
                    },
                    "auth_token": {"type": "string", "description": "Auth token if needed"},
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "http_request",
            "description": "Send a custom HTTP request for manual API testing.",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Target URL"},
                    "method": {"type": "string", "description": "HTTP method"},
                    "headers": {"type": "object", "description": "Custom headers"},
                    "body": {"type": "string", "description": "Request body (JSON string)"},
                    "params": {"type": "object", "description": "Query parameters"},
                    "content_type": {"type": "string", "description": "Content-Type header"},
                },
                "required": ["url"],
            },
        },
    },
]


# ---------------------------------------------------------------------------
# Brain Class
# ---------------------------------------------------------------------------
class APIBrain(AgentBrain):
    """API Security Agent Brain — tests REST, GraphQL, and gRPC APIs."""

    AGENT_TYPE: ClassVar[str] = "api"
    LLM_MODEL: ClassVar[str] = "claude-3-5-sonnet"
    MAX_STEPS: ClassVar[int] = 90
    TOKEN_BUDGET: ClassVar[int] = 225_000

    SYSTEM_PROMPT: ClassVar[str] = (
        "You are the Lucifer API Security Agent — an expert in API penetration testing "
        "specialising in OWASP API Security Top 10.\n\n"
        "## Your Mission\n"
        "Perform comprehensive security testing of the target's APIs:\n"
        "1. **API Discovery** — Map all API endpoints through documentation, introspection, "
        "and brute-force. Parse OpenAPI specs and GraphQL schemas.\n"
        "2. **Broken Object Level Authorization (BOLA)** — Test every endpoint with object IDs "
        "for IDOR vulnerabilities. Attempt cross-user resource access.\n"
        "3. **Broken Function Level Authorization (BFLA)** — Test admin/privileged endpoints "
        "with regular user tokens.\n"
        "4. **Mass Assignment** — Inject privileged fields (role, isAdmin, price, etc.) into "
        "API requests to test for improper property filtering.\n"
        "5. **Excessive Data Exposure** — Analyse API responses for unnecessary data leakage.\n"
        "6. **Rate Limiting** — Test rate limiting effectiveness and bypass techniques.\n"
        "7. **Authentication** — Test API auth mechanisms for token leakage, insecure "
        "transmission, and improper validation.\n"
        "8. **GraphQL-Specific** — If GraphQL: test introspection, query depth limits, "
        "batch query abuse, and field suggestion enumeration.\n\n"
        "## Methodology\n"
        "- Start with API discovery and schema extraction.\n"
        "- Map all endpoints, methods, parameters, and auth requirements.\n"
        "- Systematically test each endpoint category in the OWASP API Top 10.\n"
        "- Use the discovered schema to craft precise test payloads.\n"
        "- Log every request-response pair as evidence.\n"
        "- Provide OWASP API Top 10 category mapping for each finding.\n\n"
        "## Output Requirements\n"
        "Provide detailed vulnerability findings with OWASP API category mapping, "
        "full endpoint inventory, authentication assessment, rate limiting analysis, "
        "and data exposure findings."
    )

    APPROVAL_REQUIRED_TOOLS: ClassVar[List[str]] = [
        "bola_test",
        "bfla_test",
        "mass_assignment_test",
    ]

    def get_tools(self) -> List[Dict[str, Any]]:
        return API_TOOLS

    def get_input_schema(self) -> Type[BaseModel]:
        return APIInput

    def get_output_schema(self) -> Type[BaseModel]:
        return APIOutput
