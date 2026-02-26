"""
Tests for tools/mitm_recorder.py — MITMRecorder.

No real mitmproxy instance is started. Uses stub mode / record_flow.
"""
from __future__ import annotations

import uuid
from pathlib import Path

import pytest

from core.models import ArtifactType, Flow
from tools.evidence_store import EvidenceStore
from tools.mitm_recorder import MITMRecorder


@pytest.fixture
def store(tmp_path: Path) -> EvidenceStore:
    return EvidenceStore(backend="filesystem", root=str(tmp_path / "ev"))


@pytest.fixture
def recorder(store: EvidenceStore) -> MITMRecorder:
    return MITMRecorder(evidence_store=store)


def _make_flow(url: str = "https://app.example.com/api") -> Flow:
    return Flow(
        flow_id=str(uuid.uuid4()),
        method="GET",
        url=url,
        request_headers={"Accept": "application/json"},
        request_body=None,
        response_status=200,
        response_headers={"Content-Type": "application/json"},
        response_body='{"ok":true}',
    )


class TestMITMRecorderFlows:
    @pytest.mark.asyncio
    async def test_start_returns_session_id(self, recorder: MITMRecorder) -> None:
        session_id = await recorder.start(port=19999)
        assert session_id
        assert recorder.is_running
        await recorder.stop()

    def test_record_flow_stores_evidence(self, recorder: MITMRecorder, store: EvidenceStore) -> None:
        session_id = "test-session"
        flow = _make_flow()
        recorder.record_flow(session_id, flow)

        flows = recorder.get_flows(session_id)
        assert len(flows) == 1
        assert flows[0].url == "https://app.example.com/api"

    def test_get_flows_with_filter(self, recorder: MITMRecorder) -> None:
        session_id = "sess-filter"
        recorder.record_flow(session_id, _make_flow("https://app.example.com/api/users"))
        recorder.record_flow(session_id, _make_flow("https://app.example.com/api/admin"))
        recorder.record_flow(session_id, _make_flow("https://app.example.com/health"))

        filtered = recorder.get_flows(session_id, url_filter="/api/")
        assert len(filtered) == 2


class TestMITMRecorderExport:
    def test_export_har_creates_har_file(self, recorder: MITMRecorder, store: EvidenceStore) -> None:
        session_id = "sess-export"
        recorder.record_flow(session_id, _make_flow())
        recorder.record_flow(session_id, _make_flow("https://app.example.com/other"))

        har = recorder.export_har(session_id)
        assert har.session_id == session_id
        assert len(har.entries) == 2
