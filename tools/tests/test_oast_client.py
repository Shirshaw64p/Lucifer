"""
Tests for tools/oast_client.py — OASTClient.

All Interactsh server calls are mocked. No real external services.
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from core.models import ArtifactType, OASTCallback
from tools.evidence_store import EvidenceStore
from tools.oast_client import OASTClient


@pytest.fixture
def store(tmp_path: Path) -> EvidenceStore:
    return EvidenceStore(backend="filesystem", root=str(tmp_path / "ev"))


@pytest.fixture
def client(store: EvidenceStore) -> OASTClient:
    return OASTClient(
        evidence_store=store,
        server_url="https://interact.example.com",
        auth_token="test-token",
    )


class TestOASTPayload:
    def test_get_payload_returns_unique_url(self, client: OASTClient) -> None:
        url1 = client.get_payload("run-1", "agent-1", "finding-1")
        url2 = client.get_payload("run-1", "agent-1", "finding-2")

        assert url1 != url2
        assert "interact.example.com" in url1
        assert url1.startswith("http://")

    def test_get_payload_registers_internally(self, client: OASTClient) -> None:
        client.get_payload("run-1", "agent-1", "finding-1")
        payloads = client.get_registered_payloads()

        assert len(payloads) == 1
        info = list(payloads.values())[0]
        assert info["run_id"] == "run-1"
        assert info["finding_id"] == "finding-1"

    def test_same_inputs_produce_same_subdomain(self, client: OASTClient) -> None:
        url1 = client.get_payload("run-1", "agent-1", "finding-1")
        url2 = client.get_payload("run-1", "agent-1", "finding-1")
        assert url1 == url2


class TestOASTConfirm:
    def test_confirm_finding_stores_evidence(self, client: OASTClient, store: EvidenceStore) -> None:
        cb = OASTCallback(
            callback_id="cb-1",
            finding_id="f-1",
            subdomain="abc123.interact.example.com",
            protocol="http",
            remote_address="1.2.3.4",
            raw_request="GET / HTTP/1.1\r\nHost: abc123.interact.example.com\r\n",
        )

        ref = client.confirm_finding("f-1", cb)

        assert ref.artifact_type == ArtifactType.OAST_CALLBACK
        artifact = store.get(sha256=ref.sha256)
        data = json.loads(artifact.content)
        assert data["finding_id"] == "f-1"
        assert data["protocol"] == "http"


class TestOASTPoll:
    @pytest.mark.asyncio
    async def test_poll_callbacks_empty(self, client: OASTClient) -> None:
        """Polling with mocked empty response."""

        async def mock_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"data": []})

        transport = httpx.MockTransport(mock_handler)
        client._http = httpx.AsyncClient(transport=transport)
        client._session_id = "sess-1"

        cbs = await client.poll_callbacks("run-1")
        assert cbs == []
