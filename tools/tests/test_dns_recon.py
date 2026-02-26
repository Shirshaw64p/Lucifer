"""
Tests for tools/specialized/dns_recon.py — DNSRecon.

All DNS and subprocess calls are mocked.
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from core.scope_guard import ScopeViolation, reset_scope_guard
from tools.specialized.dns_recon import DNSRecon, DNSRecord


@pytest.fixture(autouse=True)
def _scope(tmp_path: Path):
    sf = tmp_path / "scope.yaml"
    sf.write_text("scope:\n  includes:\n    - '*.example.com'\n    - 'example.com'\n")
    reset_scope_guard(str(sf))
    yield
    reset_scope_guard(str(sf))


class TestDNSReconResolve:
    @pytest.mark.asyncio
    async def test_resolve_returns_records(self) -> None:
        recon = DNSRecon()

        mock_answer = MagicMock()
        mock_answer.__iter__ = MagicMock(return_value=iter([MagicMock(to_text=lambda: "93.184.216.34")]))
        mock_answer.rrset = MagicMock(ttl=300)

        with patch("tools.specialized.dns_recon.asyncio.to_thread", new_callable=AsyncMock) as mock_thread:
            mock_thread.return_value = mock_answer
            records = await recon.resolve("example.com", record_types=["A"])

        assert len(records) >= 1
        assert records[0].record_type == "A"
        assert records[0].value == "93.184.216.34"

    @pytest.mark.asyncio
    async def test_resolve_scope_violation(self) -> None:
        recon = DNSRecon()
        with pytest.raises(ScopeViolation):
            await recon.resolve("evil.net")


class TestDNSReconSubdomains:
    @pytest.mark.asyncio
    async def test_enumerate_subs_parses_output(self) -> None:
        recon = DNSRecon()

        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(
            return_value=(b'{"host":"sub1.example.com"}\n{"host":"sub2.example.com"}\n', b"")
        )
        mock_proc.returncode = 0

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            result = await recon.enumerate_subs("example.com")

        assert len(result.subdomains) == 2
        assert "sub1.example.com" in result.subdomains

    @pytest.mark.asyncio
    async def test_enumerate_subs_missing_subfinder(self) -> None:
        recon = DNSRecon()

        with patch("asyncio.create_subprocess_exec", side_effect=FileNotFoundError):
            result = await recon.enumerate_subs("example.com")

        assert result.subdomains == []


class TestDNSReconZoneTransfer:
    @pytest.mark.asyncio
    async def test_zone_transfer_not_possible(self) -> None:
        recon = DNSRecon()

        with patch("tools.specialized.dns_recon.asyncio.to_thread", side_effect=Exception("refused")):
            ok, data = await recon.zone_transfer("example.com")

        assert ok is False
        assert data == ""
