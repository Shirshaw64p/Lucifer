"""
tools/specialized/dns_recon.py — DNS reconnaissance using dnspython + subfinder.

Enumerates subdomains, resolves records, and checks for zone transfers.
"""
from __future__ import annotations

import asyncio
import json
import logging
import shutil
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from core.scope_guard import check_scope

logger = logging.getLogger(__name__)


@dataclass
class DNSRecord:
    name: str
    record_type: str   # A, AAAA, CNAME, MX, TXT, NS, SOA, …
    value: str
    ttl: int = 0


@dataclass
class SubdomainResult:
    domain: str
    subdomains: List[str] = field(default_factory=list)
    source: str = ""     # subfinder / brute / zone_transfer


@dataclass
class DNSReconResult:
    target: str
    records: List[DNSRecord] = field(default_factory=list)
    subdomains: List[SubdomainResult] = field(default_factory=list)
    zone_transfer_possible: bool = False
    zone_transfer_data: str = ""


class DNSRecon:
    """
    DNS reconnaissance tool.

    * ``resolve()``          — query specific record types
    * ``enumerate_subs()``   — passive subdomain enumeration via subfinder
    * ``zone_transfer()``    — attempt AXFR against nameservers
    * ``full_recon()``       — all of the above in one call
    """

    def __init__(self, subfinder_path: Optional[str] = None):
        self._subfinder = subfinder_path or shutil.which("subfinder") or "subfinder"

    # ------------------------------------------------------------------
    # DNS resolution
    # ------------------------------------------------------------------

    async def resolve(
        self,
        domain: str,
        record_types: Optional[List[str]] = None,
    ) -> List[DNSRecord]:
        """Resolve DNS records for *domain*."""
        check_scope(domain)
        import dns.resolver  # type: ignore[import-untyped]

        rtypes = record_types or ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA"]
        records: List[DNSRecord] = []

        for rtype in rtypes:
            try:
                answers = await asyncio.to_thread(
                    lambda rt=rtype: dns.resolver.resolve(domain, rt)
                )
                for rdata in answers:
                    records.append(
                        DNSRecord(
                            name=domain,
                            record_type=rtype,
                            value=rdata.to_text(),
                            ttl=answers.rrset.ttl if answers.rrset else 0,
                        )
                    )
            except Exception:
                pass  # NXDOMAIN, NoAnswer, etc.

        return records

    # ------------------------------------------------------------------
    # Subdomain enumeration
    # ------------------------------------------------------------------

    async def enumerate_subs(
        self,
        domain: str,
        timeout: int = 120,
    ) -> SubdomainResult:
        """Passive subdomain enumeration via subfinder."""
        check_scope(domain)

        cmd = [self._subfinder, "-d", domain, "-silent", "-json"]
        subdomains: List[str] = []

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            for line in stdout.decode().strip().splitlines():
                try:
                    data = json.loads(line)
                    host = data.get("host", line.strip())
                except json.JSONDecodeError:
                    host = line.strip()
                if host:
                    subdomains.append(host)
        except FileNotFoundError:
            logger.warning("subfinder not found — skipping passive enum")
        except asyncio.TimeoutError:
            logger.warning("subfinder timed out")

        return SubdomainResult(domain=domain, subdomains=subdomains, source="subfinder")

    # ------------------------------------------------------------------
    # Zone transfer
    # ------------------------------------------------------------------

    async def zone_transfer(self, domain: str) -> tuple[bool, str]:
        """Attempt AXFR against all authoritative nameservers."""
        check_scope(domain)
        import dns.query  # type: ignore[import-untyped]
        import dns.resolver  # type: ignore[import-untyped]
        import dns.zone  # type: ignore[import-untyped]

        output_lines: List[str] = []
        success = False

        try:
            ns_answers = await asyncio.to_thread(
                lambda: dns.resolver.resolve(domain, "NS")
            )
            for ns in ns_answers:
                ns_str = ns.to_text().rstrip(".")
                try:
                    z = await asyncio.to_thread(
                        lambda s=ns_str: dns.zone.from_xfr(
                            dns.query.xfr(s, domain, timeout=10)
                        )
                    )
                    names = z.nodes.keys()
                    for n in sorted(names):
                        output_lines.append(z[n].to_text(n))
                    success = True
                    logger.info("dns.zone_transfer_success", extra={"ns": ns_str})
                except Exception:
                    pass
        except Exception:
            pass

        return success, "\n".join(output_lines)

    # ------------------------------------------------------------------
    # Full recon
    # ------------------------------------------------------------------

    async def full_recon(self, domain: str) -> DNSReconResult:
        """Run all DNS reconnaissance in one call."""
        records = await self.resolve(domain)
        subs = await self.enumerate_subs(domain)
        zt_ok, zt_data = await self.zone_transfer(domain)

        return DNSReconResult(
            target=domain,
            records=records,
            subdomains=[subs],
            zone_transfer_possible=zt_ok,
            zone_transfer_data=zt_data,
        )
