"""
agents/brains/auth.py — Authentication & Authorization Agent Brain
===================================================================
Agent Type : auth
LLM Model  : Claude 3.5 Sonnet
Loop Type  : ReAct
Max Steps  : 80
Token Budget: 200,000

Purpose: Test authentication mechanisms, session management, password
policies, multi-factor authentication, OAuth/OIDC flows, and
authorization controls including privilege escalation.
"""

from __future__ import annotations

from typing import Any, ClassVar, Dict, List, Optional, Type

from pydantic import BaseModel, Field

from agents.base import AgentBrain


# ---------------------------------------------------------------------------
# Input Schema
# ---------------------------------------------------------------------------
class AuthInput(BaseModel):
    """Validated input for the Authentication & Authorization Agent."""
    run_id: str = Field(..., description="Unique run identifier")
    task_id: str = Field(..., description="Unique task identifier")
    target: str = Field(..., description="Target URL or application base URL")
    scope: Dict[str, Any] = Field(default_factory=dict, description="Engagement scope")
    login_urls: List[str] = Field(
        default_factory=list,
        description="Login page URLs discovered by recon/web agents",
    )
    registration_urls: List[str] = Field(
        default_factory=list,
        description="Registration page URLs",
    )
    entry_points: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Entry points from recon agent",
    )
    technologies: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Technology stack (auth framework detection)",
    )
    test_credentials: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Test credentials provided for authenticated testing",
    )
    oauth_endpoints: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Discovered OAuth/OIDC endpoints",
    )


# ---------------------------------------------------------------------------
# Output Schema
# ---------------------------------------------------------------------------
class AuthVulnerability(BaseModel):
    """An authentication or authorization vulnerability."""
    finding_id: str = Field(default="", description="Unique finding ID")
    title: str = Field(..., description="Finding title")
    vuln_type: str = Field(
        ...,
        description="Type: weak_password, default_creds, brute_force_possible, session_fixation, "
                    "session_hijack, insecure_token, no_mfa, mfa_bypass, oauth_misconfig, "
                    "idor, privilege_escalation, forced_browsing, jwt_weakness, password_reset_flaw",
    )
    severity: str = Field(..., description="Severity: critical, high, medium, low, informational")
    url: str = Field(default="", description="Affected URL")
    description: str = Field(default="", description="Detailed technical description")
    evidence: str = Field(default="", description="Evidence and proof of concept")
    remediation: str = Field(default="", description="Specific remediation steps")
    cvss_score: Optional[float] = Field(default=None, description="CVSS 3.1 base score")
    cwe_id: str = Field(default="", description="CWE identifier")
    confidence: float = Field(default=0.0, description="Confidence 0.0-1.0")


class SessionAnalysis(BaseModel):
    """Session management analysis."""
    session_mechanism: str = Field(default="", description="Session mechanism: cookie, token, jwt, etc.")
    token_entropy: Optional[float] = Field(default=None, description="Token entropy in bits")
    token_length: int = Field(default=0, description="Token length in characters")
    predictable: bool = Field(default=False, description="Token is predictable")
    secure_flag: bool = Field(default=False, description="Secure flag set")
    httponly_flag: bool = Field(default=False, description="HttpOnly flag set")
    samesite: str = Field(default="", description="SameSite attribute value")
    expiration: str = Field(default="", description="Session expiration policy")
    idle_timeout: str = Field(default="", description="Idle timeout policy")
    fixation_vulnerable: bool = Field(default=False, description="Vulnerable to session fixation")
    issues: List[str] = Field(default_factory=list, description="Identified issues")


class PasswordPolicyAnalysis(BaseModel):
    """Password policy analysis."""
    min_length: Optional[int] = Field(default=None, description="Minimum password length")
    requires_uppercase: Optional[bool] = Field(default=None)
    requires_lowercase: Optional[bool] = Field(default=None)
    requires_digits: Optional[bool] = Field(default=None)
    requires_special: Optional[bool] = Field(default=None)
    allows_common_passwords: Optional[bool] = Field(default=None)
    lockout_mechanism: str = Field(default="", description="Account lockout policy")
    lockout_threshold: Optional[int] = Field(default=None, description="Failed attempts before lockout")
    issues: List[str] = Field(default_factory=list)


class AuthOutput(BaseModel):
    """Validated output from the Authentication & Authorization Agent."""
    target: str = Field(..., description="Target as provided")
    vulnerabilities: List[AuthVulnerability] = Field(
        default_factory=list,
        description="All authentication/authorization vulnerabilities found",
    )
    session_analysis: Optional[SessionAnalysis] = Field(
        default=None,
        description="Session management analysis results",
    )
    password_policy: Optional[PasswordPolicyAnalysis] = Field(
        default=None,
        description="Password policy analysis results",
    )
    mfa_assessment: Dict[str, Any] = Field(
        default_factory=dict,
        description="Multi-factor authentication assessment",
    )
    oauth_findings: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="OAuth/OIDC specific findings",
    )
    default_credentials_found: List[Dict[str, str]] = Field(
        default_factory=list,
        description="Default or weak credentials that worked",
    )
    privilege_escalation_paths: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Identified privilege escalation paths",
    )
    summary: str = Field(default="", description="Executive summary")
    risk_score: float = Field(default=0.0, description="Overall auth risk score 0.0-10.0")


# ---------------------------------------------------------------------------
# Tool Definitions
# ---------------------------------------------------------------------------
AUTH_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "login_bruteforce",
            "description": (
                "Attempt credential brute-force against a login endpoint using common "
                "username/password combinations. Uses rate limiting and jitter to avoid lockout."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Login endpoint URL"},
                    "username_field": {"type": "string", "description": "Username form field name"},
                    "password_field": {"type": "string", "description": "Password form field name"},
                    "usernames": {"type": "array", "items": {"type": "string"}, "description": "Usernames to test"},
                    "password_list": {"type": "string", "description": "Password list: top-100, top-1000, default_creds"},
                    "method": {"type": "string", "description": "HTTP method: POST, GET"},
                    "success_indicator": {"type": "string", "description": "String indicating successful login"},
                    "failure_indicator": {"type": "string", "description": "String indicating failed login"},
                    "rate_limit": {"type": "integer", "description": "Requests per second limit"},
                    "csrf_token_field": {"type": "string", "description": "CSRF token field name if present"},
                },
                "required": ["url", "username_field", "password_field"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "session_analyze",
            "description": (
                "Analyse session tokens for entropy, predictability, and security attributes. "
                "Collects multiple tokens and performs statistical analysis."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "URL that issues session tokens"},
                    "cookie_name": {"type": "string", "description": "Session cookie name"},
                    "sample_size": {"type": "integer", "description": "Number of tokens to collect (default: 50)"},
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "token_analyze",
            "description": (
                "Analyse JWT or other authentication tokens. Decode payload, check signature, "
                "test for algorithm confusion, none algorithm, and key brute-force."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "token": {"type": "string", "description": "The token to analyse"},
                    "token_type": {"type": "string", "description": "Token type: jwt, opaque, paseto"},
                    "test_none_alg": {"type": "boolean", "description": "Test for 'none' algorithm vulnerability"},
                    "test_alg_confusion": {"type": "boolean", "description": "Test for algorithm confusion (RS256→HS256)"},
                    "wordlist": {"type": "string", "description": "Wordlist for secret brute-force"},
                },
                "required": ["token"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "password_policy_check",
            "description": (
                "Test the password policy of a registration or password change form. "
                "Tries various password combinations to determine policy rules."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Registration or password change URL"},
                    "password_field": {"type": "string", "description": "Password field name"},
                    "confirm_field": {"type": "string", "description": "Password confirm field name"},
                    "additional_fields": {"type": "object", "description": "Other required form fields"},
                },
                "required": ["url", "password_field"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "mfa_bypass_test",
            "description": (
                "Test multi-factor authentication for bypass vulnerabilities. "
                "Tests direct endpoint access, response manipulation, rate limiting, "
                "and backup code weaknesses."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "mfa_url": {"type": "string", "description": "MFA verification URL"},
                    "post_mfa_url": {"type": "string", "description": "URL after successful MFA"},
                    "session_token": {"type": "string", "description": "Session token from first factor"},
                    "bypass_techniques": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Techniques: direct_access, response_manipulation, null_code, rate_limit, backup_code",
                    },
                },
                "required": ["mfa_url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "privilege_escalation_test",
            "description": (
                "Test for horizontal and vertical privilege escalation. "
                "Attempts to access other users' resources or admin functionality."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "URL to test"},
                    "auth_token": {"type": "string", "description": "Current user's auth token"},
                    "escalation_type": {"type": "string", "description": "Type: horizontal (IDOR), vertical (admin access)"},
                    "target_resource": {"type": "string", "description": "Resource identifier to attempt access to"},
                    "parameter": {"type": "string", "description": "Parameter containing the resource ID"},
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "oauth_test",
            "description": (
                "Test OAuth 2.0 / OpenID Connect flows for security issues. "
                "Checks for open redirects in redirect_uri, state parameter validation, "
                "PKCE enforcement, and token leakage."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "authorize_url": {"type": "string", "description": "OAuth authorization endpoint"},
                    "token_url": {"type": "string", "description": "OAuth token endpoint"},
                    "client_id": {"type": "string", "description": "Client ID (if known)"},
                    "redirect_uri": {"type": "string", "description": "Registered redirect URI"},
                    "tests": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Tests: redirect_uri_manipulation, state_validation, pkce, token_leakage, scope_abuse",
                    },
                },
                "required": ["authorize_url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "http_request",
            "description": "Send a custom HTTP request for manual auth testing.",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Target URL"},
                    "method": {"type": "string", "description": "HTTP method"},
                    "headers": {"type": "object", "description": "Custom headers"},
                    "body": {"type": "string", "description": "Request body"},
                    "params": {"type": "object", "description": "Query parameters"},
                },
                "required": ["url"],
            },
        },
    },
]


# ---------------------------------------------------------------------------
# Brain Class
# ---------------------------------------------------------------------------
class AuthBrain(AgentBrain):
    """Authentication & Authorization Agent Brain — tests auth mechanisms."""

    AGENT_TYPE: ClassVar[str] = "auth"
    LLM_MODEL: ClassVar[str] = "claude-3-5-sonnet"
    MAX_STEPS: ClassVar[int] = 80
    TOKEN_BUDGET: ClassVar[int] = 200_000

    SYSTEM_PROMPT: ClassVar[str] = (
        "You are the Lucifer Authentication & Authorization Agent — an expert in "
        "authentication security, session management, and access control testing.\n\n"
        "## Your Mission\n"
        "Systematically assess the target's authentication and authorization mechanisms:\n"
        "1. **Credential Testing** — Test for default credentials, weak passwords, and "
        "brute-force susceptibility. Check account lockout mechanisms.\n"
        "2. **Session Management** — Analyse session tokens for entropy, predictability, "
        "fixation vulnerability, and proper lifecycle management.\n"
        "3. **Token Security** — Decode and analyse JWT/auth tokens for algorithm confusion, "
        "'none' algorithm attacks, weak secrets, and improper validation.\n"
        "4. **Password Policy** — Evaluate password complexity requirements, history checks, "
        "and reset mechanisms.\n"
        "5. **Multi-Factor Authentication** — Assess MFA implementation for bypass "
        "vulnerabilities, rate limiting, and backup code weaknesses.\n"
        "6. **OAuth/OIDC** — Test OAuth 2.0 flows for redirect_uri manipulation, state "
        "parameter validation, PKCE enforcement, and token leakage.\n"
        "7. **Privilege Escalation** — Test for horizontal (IDOR) and vertical (admin access) "
        "privilege escalation.\n\n"
        "## Methodology\n"
        "- Map all authentication endpoints and flows first.\n"
        "- Test credential strength before moving to session analysis.\n"
        "- Analyse both authenticated and unauthenticated access paths.\n"
        "- Test authorization by attempting cross-user and role-elevation access.\n"
        "- Be thorough but respect rate limits to avoid service disruption.\n"
        "- Document every finding with clear reproduction steps.\n\n"
        "## Output Requirements\n"
        "Provide detailed findings for each vulnerability, session analysis results, "
        "password policy assessment, MFA evaluation, OAuth findings, and any privilege "
        "escalation paths discovered."
    )

    # High-risk tools requiring approval
    APPROVAL_REQUIRED_TOOLS: ClassVar[List[str]] = [
        "login_bruteforce",
        "privilege_escalation_test",
        "mfa_bypass_test",
    ]

    def get_tools(self) -> List[Dict[str, Any]]:
        return AUTH_TOOLS

    def get_input_schema(self) -> Type[BaseModel]:
        return AuthInput

    def get_output_schema(self) -> Type[BaseModel]:
        return AuthOutput
