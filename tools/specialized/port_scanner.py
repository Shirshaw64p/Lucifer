"""
tools/specialized/port_scanner.py — PortScanner: nmap + masscan wrapper
for TCP/UDP port discovery and service detection.
"""
from __future__ import annotations

import asyncio
import json
import logging
import shutil
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from core.scope_guard import check_scope

logger = logging.getLogger(__name__)


@dataclass
class PortResult:
    host: str
    port: int
    protocol: str        # tcp / udp
    state: str           # open / closed / filtered
    service: str = ""
    version: str = ""
    banner: str = ""


@dataclass
class ScanResult:
    target: str
    ports: List[PortResult] = field(default_factory=list)
    raw_output: str = ""


class PortScanner:
    """
    Wraps nmap and masscan for port scanning.

    * ``scan_nmap()``    — full service-version scan (slower, richer)
    * ``scan_masscan()`` — high-speed SYN scan (faster, less detail)
    * ``quick_scan()``   — top-1000 TCP ports via nmap
    """

    def __init__(self, nmap_path: Optional[str] = None, masscan_path: Optional[str] = None):
        self._nmap = nmap_path or shutil.which("nmap") or "nmap"
        self._masscan = masscan_path or shutil.which("masscan") or "masscan"

    # ------------------------------------------------------------------
    # nmap
    # ------------------------------------------------------------------

    async def scan_nmap(
        self,
        target: str,
        ports: str = "1-65535",
        arguments: str = "-sV -sC -T4",
        timeout: int = 600,
    ) -> ScanResult:
        """Run an nmap scan against *target*."""
        check_scope(target)

        cmd = [self._nmap, target, "-p", ports, *arguments.split(), "-oX", "-"]
        raw = await self._run(cmd, timeout)
        results = self._parse_nmap_xml(raw, target)
        return results

    async def quick_scan(self, target: str, timeout: int = 120) -> ScanResult:
        """Top-1000 TCP ports with service detection."""
        check_scope(target)
        cmd = [self._nmap, target, "--top-ports", "1000", "-sV", "-T4", "-oX", "-"]
        raw = await self._run(cmd, timeout)
        return self._parse_nmap_xml(raw, target)

    # ------------------------------------------------------------------
    # masscan
    # ------------------------------------------------------------------

    async def scan_masscan(
        self,
        target: str,
        ports: str = "1-65535",
        rate: int = 10000,
        timeout: int = 300,
    ) -> ScanResult:
        """Run a masscan SYN scan against *target*."""
        check_scope(target)

        cmd = [
            self._masscan, target,
            "-p", ports,
            "--rate", str(rate),
            "--open-only",
            "-oJ", "-",
        ]
        raw = await self._run(cmd, timeout)
        return self._parse_masscan_json(raw, target)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    async def _run(self, cmd: List[str], timeout: int) -> str:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            raise TimeoutError(f"Scan timed out after {timeout}s")
        if proc.returncode and proc.returncode not in (0, 1):
            raise RuntimeError(f"Scan failed (rc={proc.returncode}): {stderr.decode()}")
        return stdout.decode(errors="replace")

    def _parse_nmap_xml(self, xml_str: str, target: str) -> ScanResult:
        ports: List[PortResult] = []
        try:
            root = ET.fromstring(xml_str)
            for host in root.findall(".//host"):
                addr_el = host.find("address")
                host_addr = addr_el.get("addr", target) if addr_el is not None else target
                for port_el in host.findall(".//port"):
                    state_el = port_el.find("state")
                    svc_el = port_el.find("service")
                    ports.append(
                        PortResult(
                            host=host_addr,
                            port=int(port_el.get("portid", 0)),
                            protocol=port_el.get("protocol", "tcp"),
                            state=state_el.get("state", "unknown") if state_el is not None else "unknown",
                            service=svc_el.get("name", "") if svc_el is not None else "",
                            version=svc_el.get("version", "") if svc_el is not None else "",
                        )
                    )
        except ET.ParseError:
            logger.warning("nmap xml parse error")
        return ScanResult(target=target, ports=ports, raw_output=xml_str)

    def _parse_masscan_json(self, json_str: str, target: str) -> ScanResult:
        ports: List[PortResult] = []
        try:
            # masscan json output can have trailing comma — strip it
            cleaned = json_str.strip().rstrip(",")
            if not cleaned.startswith("["):
                cleaned = "[" + cleaned + "]"
            entries = json.loads(cleaned)
            for entry in entries:
                for p in entry.get("ports", []):
                    ports.append(
                        PortResult(
                            host=entry.get("ip", target),
                            port=p.get("port", 0),
                            protocol=p.get("proto", "tcp"),
                            state=p.get("status", "open"),
                            service=p.get("service", {}).get("name", ""),
                        )
                    )
        except (json.JSONDecodeError, KeyError):
            logger.warning("masscan json parse error")
        return ScanResult(target=target, ports=ports, raw_output=json_str)
