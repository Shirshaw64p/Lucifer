"""
Tests for tools/replay_harness.py — ReplayHarness.

All HTTP replay calls are mocked via httpx MockTransport.
"""
from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from core.models import ArtifactType, HAREntry
from tools.evidence_store import EvidenceStore
from tools.replay_harness import ReplayHarness


@pytest.fixture
def store(tmp_path: Path) -> EvidenceStore:
    return EvidenceStore(backend="filesystem", root=str(tmp_path / "ev"))


@pytest.fixture
def harness(store: EvidenceStore) -> ReplayHarness:
    return ReplayHarness(evidence_store=store)


def _sample_har() -> HAREntry:
    return HAREntry(
        method="GET",
        url="https://api.example.com/test",
        request_headers={"Accept": "application/json"},
        request_body=None,
        response_status=200,
        response_headers={"Content-Type": "application/json"},
        response_body='{"status":"ok"}',
        cookies=[{"name": "sid", "value": "abc"}],
    )


class TestReplayHarnessLoad:
    def test_load_har_from_evidence(self, harness: ReplayHarness, store: EvidenceStore) -> None:
        from dataclasses import asdict

        original = _sample_har()
        content = json.dumps(asdict(original), default=str).encode()
        ref = store.save(ArtifactType.HAR, content, {"test": True})

        loaded = harness.load_har(ref.evidence_id)
        assert loaded.method == "GET"
        assert loaded.url == "https://api.example.com/test"
        assert loaded.response_status == 200

    def test_load_har_not_found(self, harness: ReplayHarness) -> None:
        with pytest.raises(FileNotFoundError):
            harness.load_har("nonexistent-id")


class TestReplayHarnessReplay:
    @pytest.mark.asyncio
    async def test_replay_sends_same_request(self, harness: ReplayHarness) -> None:
        original = _sample_har()
        captured_requests = []

        async def mock_handler(request: httpx.Request) -> httpx.Response:
            captured_requests.append(request)
            return httpx.Response(200, text='{"status":"ok"}')

        transport = httpx.MockTransport(mock_handler)
        session = httpx.AsyncClient(transport=transport)

        result = await harness.replay(original, session=session)

        assert result.har_entry.response_status == 200
        assert result.evidence_ref is not None
        assert len(captured_requests) == 1
        assert str(captured_requests[0].url) == "https://api.example.com/test"

        await session.aclose()


class TestReplayHarnessCompare:
    def test_compare_identical(self, harness: ReplayHarness) -> None:
        original = _sample_har()
        replayed = _sample_har()

        comparison = harness.compare(original, replayed)
        assert comparison.status_match is True
        assert comparison.body_diff_ratio == 0.0
        assert comparison.deterministic is True

    def test_compare_different_status(self, harness: ReplayHarness) -> None:
        original = _sample_har()
        replayed = _sample_har()
        replayed.response_status = 403

        comparison = harness.compare(original, replayed)
        assert comparison.status_match is False
        assert comparison.deterministic is False

    def test_compare_different_body(self, harness: ReplayHarness) -> None:
        original = _sample_har()
        replayed = _sample_har()
        replayed.response_body = '{"status":"error","code":500}'

        comparison = harness.compare(original, replayed)
        assert comparison.body_diff_ratio > 0.0
