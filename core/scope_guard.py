"""
core/scope_guard.py — Scope enforcement for all outbound traffic.

Every outbound request (HTTP, browser navigation, OAST payload,
port scan, etc.) **must** pass through `check_scope()` before
execution.  Violations raise `ScopeViolation`.

Scope is loaded from a YAML file (default: ./scope.yaml):

```yaml
scope:
  includes:
    - "*.example.com"
    - "10.0.0.0/8"
  excludes:
    - "admin.example.com"
    - "10.0.0.1"
```
"""
from __future__ import annotations

import fnmatch
import ipaddress
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Set
from urllib.parse import urlparse

import yaml

from core.config import settings

logger = logging.getLogger(__name__)


class ScopeViolation(Exception):
    """Raised when a target is outside the authorised scope."""


@dataclass
class ScopeRule:
    includes: List[str] = field(default_factory=list)
    excludes: List[str] = field(default_factory=list)


class ScopeGuard:
    """Stateless scope validator — initialised once per engagement."""

    def __init__(self, scope_file: Optional[str] = None) -> None:
        path = Path(scope_file or settings.scope_file)
        if path.exists():
            with open(path, "r") as fh:
                data = yaml.safe_load(fh) or {}
            scope_block = data.get("scope", {})
            self._rule = ScopeRule(
                includes=scope_block.get("includes", []),
                excludes=scope_block.get("excludes", []),
            )
        else:
            logger.warning("Scope file %s not found — defaulting to DENY ALL", path)
            self._rule = ScopeRule()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check_url(self, url: str) -> None:
        """Raise `ScopeViolation` if *url* is out of scope."""
        parsed = urlparse(url)
        host = parsed.hostname or ""
        self._check(host)

    def check_host(self, host: str) -> None:
        """Raise `ScopeViolation` if *host* (name or IP) is out of scope."""
        self._check(host)

    def is_in_scope(self, target: str) -> bool:
        """Return True when *target* is permitted."""
        try:
            self._check(target)
            return True
        except ScopeViolation:
            return False

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _check(self, target: str) -> None:
        target = target.strip().lower()

        # Explicit exclude always wins
        for pattern in self._rule.excludes:
            if self._match(target, pattern):
                raise ScopeViolation(
                    f"Target '{target}' matches exclude pattern '{pattern}'"
                )

        # Must match at least one include
        if not self._rule.includes:
            raise ScopeViolation("No include rules defined — scope denies all")

        for pattern in self._rule.includes:
            if self._match(target, pattern):
                return

        raise ScopeViolation(
            f"Target '{target}' does not match any include pattern"
        )

    @staticmethod
    def _match(target: str, pattern: str) -> bool:
        pattern = pattern.strip().lower()

        # CIDR match (e.g. 10.0.0.0/8)
        if "/" in pattern:
            try:
                network = ipaddress.ip_network(pattern, strict=False)
                addr = ipaddress.ip_address(target)
                return addr in network
            except ValueError:
                pass

        # Exact IP match
        try:
            return ipaddress.ip_address(target) == ipaddress.ip_address(pattern)
        except ValueError:
            pass

        # Glob / wildcard hostname match (e.g. *.example.com)
        return fnmatch.fnmatch(target, pattern)


# Module-level convenience -------------------------------------------------

_guard: Optional[ScopeGuard] = None


def get_scope_guard() -> ScopeGuard:
    """Return (and lazily create) the singleton ScopeGuard."""
    global _guard
    if _guard is None:
        _guard = ScopeGuard()
    return _guard


def check_scope(url_or_host: str) -> None:
    """Convenience — raises ScopeViolation if target is out of scope."""
    guard = get_scope_guard()
    if "://" in url_or_host:
        guard.check_url(url_or_host)
    else:
        guard.check_host(url_or_host)


def reset_scope_guard(scope_file: Optional[str] = None) -> ScopeGuard:
    """Re-initialise the singleton (useful in tests)."""
    global _guard
    _guard = ScopeGuard(scope_file)
    return _guard
