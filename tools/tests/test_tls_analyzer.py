"""
Tests for tools/specialized/tls_analyzer.py — TLSAnalyzer.

sslyze is mocked — no real TLS connections.
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from core.scope_guard import ScopeViolation, reset_scope_guard
from tools.specialized.tls_analyzer import TLSAnalyzer, TLSResult


@pytest.fixture(autouse=True)
def _scope(tmp_path: Path):
    sf = tmp_path / "scope.yaml"
    sf.write_text("scope:\n  includes:\n    - '*.example.com'\n    - 'example.com'\n")
    reset_scope_guard(str(sf))
    yield
    reset_scope_guard(str(sf))


class TestTLSAnalyzer:
    @pytest.mark.asyncio
    async def test_analyze_scope_violation(self) -> None:
        analyzer = TLSAnalyzer()
        with pytest.raises(ScopeViolation):
            await analyzer.analyze("evil.net")

    @pytest.mark.asyncio
    async def test_analyze_returns_tls_result_when_sslyze_missing(self) -> None:
        """When sslyze is not installed, returns empty TLSResult."""
        analyzer = TLSAnalyzer()

        with patch.dict("sys.modules", {"sslyze": None}):
            with patch(
                "tools.specialized.tls_analyzer.TLSAnalyzer.analyze",
                return_value=TLSResult(host="example.com", port=443),
            ):
                result = await analyzer.analyze("example.com")

        assert isinstance(result, TLSResult)
        assert result.host == "example.com"

    @pytest.mark.asyncio
    async def test_check_protocols_returns_list(self) -> None:
        analyzer = TLSAnalyzer()

        async def fake_analyze(host, port=443):
            return TLSResult(
                host=host,
                port=port,
                supported_protocols=["TLSv1.2", "TLSv1.3"],
            )

        with patch.object(analyzer, "analyze", side_effect=fake_analyze):
            protos = await analyzer.check_protocols("example.com")

        assert "TLSv1.2" in protos
        assert "TLSv1.3" in protos

    @pytest.mark.asyncio
    async def test_check_certificate_returns_cert_info(self) -> None:
        from tools.specialized.tls_analyzer import CertInfo

        analyzer = TLSAnalyzer()
        cert = CertInfo(
            subject="CN=example.com",
            issuer="CN=Let's Encrypt",
            not_before="2025-01-01",
            not_after="2026-01-01",
            serial="12345",
        )

        async def fake_analyze(host, port=443):
            return TLSResult(host=host, port=port, certificate=cert)

        with patch.object(analyzer, "analyze", side_effect=fake_analyze):
            result = await analyzer.check_certificate("example.com")

        assert result is not None
        assert result.subject == "CN=example.com"
