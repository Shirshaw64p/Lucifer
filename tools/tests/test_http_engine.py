"""
Tests for tools/http_engine.py — HttpEngine.

All network calls are mocked via httpx's MockTransport.
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
import pytest_asyncio

from core.models import ArtifactType
from core.scope_guard import ScopeViolation, reset_scope_guard
from tools.evidence_store import EvidenceStore
from tools.http_engine import HttpEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_evidence(tmp_path: Path) -> EvidenceStore:
    return EvidenceStore(backend="filesystem", root=str(tmp_path / "ev"))


@pytest.fixture(autouse=True)
def _scope_allow_all(tmp_path: Path):
    """Create a scope file that allows *.example.com."""
    scope_file = tmp_path / "scope.yaml"
    scope_file.write_text(
        "scope:\n  includes:\n    - '*.example.com'\n    - 'example.com'\n"
    )
    reset_scope_guard(str(scope_file))
    yield
    reset_scope_guard(str(scope_file))


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestHttpEngineRequest:
    @pytest.mark.asyncio
    async def test_get_captures_har(self, tmp_evidence: EvidenceStore) -> None:
        """A simple GET should produce a valid HAR entry."""

        async def mock_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text="OK", headers={"X-Test": "1"})

        transport = httpx.MockTransport(mock_handler)
        engine = HttpEngine(evidence_store=tmp_evidence, max_rps=100)
        engine._client = httpx.AsyncClient(transport=transport)

        result = await engine.get("https://app.example.com/health")

        assert result.har_entry.response_status == 200
        assert result.har_entry.url == "https://app.example.com/health"
        assert "X-Test" in result.har_entry.response_headers or "x-test" in result.har_entry.response_headers

        await engine.close()

    @pytest.mark.asyncio
    async def test_scope_violation_blocks_request(self, tmp_evidence: EvidenceStore) -> None:
        """Requests to out-of-scope targets must be rejected."""
        engine = HttpEngine(evidence_store=tmp_evidence)

        with pytest.raises(ScopeViolation):
            await engine.get("https://evil.attacker.com/steal")

        await engine.close()

    @pytest.mark.asyncio
    async def test_save_evidence_stores_har(self, tmp_evidence: EvidenceStore) -> None:
        """When run_id is supplied the HAR is persisted to evidence store."""

        async def mock_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text='{"ok":true}')

        transport = httpx.MockTransport(mock_handler)
        engine = HttpEngine(evidence_store=tmp_evidence, max_rps=100)
        engine._client = httpx.AsyncClient(transport=transport)

        result = await engine.get(
            "https://api.example.com/data",
            run_id="run-001",
            finding_id="f-001",
        )

        assert result.evidence_ref is not None
        assert result.evidence_ref.artifact_type == ArtifactType.HAR

        # Verify the evidence can be retrieved
        artifact = tmp_evidence.get(sha256=result.evidence_ref.sha256)
        data = json.loads(artifact.content)
        assert data["url"] == "https://api.example.com/data"

        await engine.close()


class TestHttpEngineRedirects:
    @pytest.mark.asyncio
    async def test_redirect_chain_tracked(self, tmp_evidence: EvidenceStore) -> None:
        """Redirect chain should be captured in the HAR entry."""
        call_count = 0

        async def mock_handler(request: httpx.Request) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return httpx.Response(
                    302,
                    headers={"Location": "https://app.example.com/final"},
                )
            return httpx.Response(200, text="final")

        transport = httpx.MockTransport(mock_handler)
        engine = HttpEngine(evidence_store=tmp_evidence, max_rps=100)
        engine._client = httpx.AsyncClient(transport=transport)

        result = await engine.get(
            "https://app.example.com/start", follow_redirects=True
        )

        assert result.har_entry.response_status == 200
        assert len(result.har_entry.redirect_chain) >= 1

        await engine.close()
