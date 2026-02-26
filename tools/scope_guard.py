"""Scope enforcement guard — validates every tool call target against approved scope.

Before any offensive tool is executed, call `enforce_scope()` with the
run_id and the target value (IP, CIDR, domain, or URL).  The guard:

1. Resolves the target to a canonical form (IP / CIDR / domain).
2. Checks the target against the Run's approved Target list (in_scope=True).
3. Blocks and logs any out-of-scope attempt.
4. Raises `ScopeViolationError` on violation.

Usage:
    from tools.scope_guard import enforce_scope, ScopeViolationError
    await enforce_scope(db_session, run_id, "192.168.1.10")
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse
from uuid import UUID

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.models.target import Target

logger = structlog.stdlib.get_logger(__name__)


class ScopeViolationError(Exception):
    """Raised when a tool call targets something outside the approved scope."""

    def __init__(self, run_id: UUID, target_value: str, reason: str = ""):
        self.run_id = run_id
        self.target_value = target_value
        self.reason = reason
        super().__init__(
            f"SCOPE VIOLATION — run={run_id} target={target_value!r} reason={reason}"
        )


# ── Internal helpers ─────────────────────────────────────────────────────────

def _extract_host(value: str) -> str:
    """Extract the hostname or IP from a URL, or return the value as-is."""
    if re.match(r"^https?://", value, re.IGNORECASE):
        parsed = urlparse(value)
        return parsed.hostname or value
    return value.strip().lower()


def _is_ip(value: str) -> bool:
    """Return True if value is a valid IPv4/IPv6 address."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _is_cidr(value: str) -> bool:
    """Return True if value is a valid CIDR network."""
    try:
        ipaddress.ip_network(value, strict=False)
        return "/" in value
    except ValueError:
        return False


def _ip_in_cidr(ip_str: str, cidr_str: str) -> bool:
    """Check whether an IP address falls inside a CIDR range."""
    try:
        return ipaddress.ip_address(ip_str) in ipaddress.ip_network(cidr_str, strict=False)
    except ValueError:
        return False


def _domain_matches(candidate: str, scope_domain: str) -> bool:
    """Check if candidate is the scope domain or a subdomain of it."""
    candidate = candidate.lower().rstrip(".")
    scope_domain = scope_domain.lower().rstrip(".")
    return candidate == scope_domain or candidate.endswith("." + scope_domain)


# ── Main enforcement function ────────────────────────────────────────────────

async def enforce_scope(
    session: AsyncSession,
    run_id: UUID,
    target_value: str,
) -> None:
    """Validate that *target_value* is within the approved scope for *run_id*.

    Raises ScopeViolationError if the target is not in scope.
    """
    canonical = _extract_host(target_value)

    # Fetch all in-scope targets for this run
    stmt = select(Target).where(Target.run_id == run_id, Target.in_scope.is_(True))
    result = await session.execute(stmt)
    scope_targets = result.scalars().all()

    if not scope_targets:
        logger.warning("scope_guard.no_targets", run_id=str(run_id))
        raise ScopeViolationError(run_id, target_value, "No in-scope targets defined for run")

    for t in scope_targets:
        scope_val = t.value.strip().lower()

        # Exact match
        if canonical == scope_val:
            logger.info("scope_guard.allowed", run_id=str(run_id), target=target_value, matched=scope_val)
            return

        # IP-in-CIDR match
        if t.target_type.value == "cidr" and _is_ip(canonical):
            if _ip_in_cidr(canonical, scope_val):
                logger.info("scope_guard.allowed_cidr", run_id=str(run_id), target=target_value, cidr=scope_val)
                return

        # Domain / subdomain match
        if t.target_type.value == "domain" and not _is_ip(canonical):
            if _domain_matches(canonical, scope_val):
                logger.info("scope_guard.allowed_domain", run_id=str(run_id), target=target_value, domain=scope_val)
                return

        # URL-based target: extract host and compare
        if t.target_type.value == "url":
            scope_host = _extract_host(scope_val)
            if canonical == scope_host or _domain_matches(canonical, scope_host):
                logger.info("scope_guard.allowed_url", run_id=str(run_id), target=target_value, url=scope_val)
                return

    # No match found → violation
    logger.error(
        "scope_guard.violation",
        run_id=str(run_id),
        target=target_value,
        scope_count=len(scope_targets),
    )
    raise ScopeViolationError(run_id, target_value, "Target not in approved scope")
