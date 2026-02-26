"""
Tests for tools/specialized/port_scanner.py — PortScanner.

All subprocess calls are mocked — no real nmap or masscan executed.
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from core.scope_guard import ScopeViolation, reset_scope_guard
from tools.specialized.port_scanner import PortScanner, ScanResult


@pytest.fixture(autouse=True)
def _scope(tmp_path: Path):
    sf = tmp_path / "scope.yaml"
    sf.write_text("scope:\n  includes:\n    - '10.0.0.0/8'\n    - '*.example.com'\n")
    reset_scope_guard(str(sf))
    yield
    reset_scope_guard(str(sf))


NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" version="nginx 1.19"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

MASSCAN_JSON = """[
  {"ip": "10.0.0.1", "ports": [{"port": 80, "proto": "tcp", "status": "open"}]},
  {"ip": "10.0.0.1", "ports": [{"port": 443, "proto": "tcp", "status": "open"}]}
]"""


class TestPortScannerNmap:
    @pytest.mark.asyncio
    async def test_scan_nmap_parses_xml(self) -> None:
        scanner = PortScanner()

        with patch.object(scanner, "_run", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = NMAP_XML
            result = await scanner.scan_nmap("10.0.0.1", ports="80,443")

        assert isinstance(result, ScanResult)
        assert len(result.ports) == 2
        assert result.ports[0].port == 80
        assert result.ports[0].state == "open"

    @pytest.mark.asyncio
    async def test_scope_violation(self) -> None:
        scanner = PortScanner()
        with pytest.raises(ScopeViolation):
            await scanner.scan_nmap("192.168.1.1")


class TestPortScannerMasscan:
    @pytest.mark.asyncio
    async def test_scan_masscan_parses_json(self) -> None:
        scanner = PortScanner()

        with patch.object(scanner, "_run", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = MASSCAN_JSON
            result = await scanner.scan_masscan("10.0.0.1")

        assert len(result.ports) == 2
        assert result.ports[0].protocol == "tcp"


class TestPortScannerQuick:
    @pytest.mark.asyncio
    async def test_quick_scan(self) -> None:
        scanner = PortScanner()

        with patch.object(scanner, "_run", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = NMAP_XML
            result = await scanner.quick_scan("10.0.0.1")

        assert result.target == "10.0.0.1"
        assert len(result.ports) >= 1
