"""
Tests for tools/evidence_store.py — EvidenceStore.

All tests use local filesystem backend. No external services.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from core.models import ArtifactType
from tools.evidence_store import EvidenceStore


@pytest.fixture
def store(tmp_path: Path) -> EvidenceStore:
    return EvidenceStore(backend="filesystem", root=str(tmp_path / "evidence"))


class TestEvidenceStoreSave:
    def test_save_returns_evidence_ref(self, store: EvidenceStore) -> None:
        content = b"some test content"
        ref = store.save(ArtifactType.RAW, content, {"tag": "test"})

        assert ref.evidence_id
        assert ref.sha256
        assert ref.artifact_type == ArtifactType.RAW
        assert ref.metadata["tag"] == "test"

    def test_save_content_addressed_dedup(self, store: EvidenceStore) -> None:
        content = b"identical payload"
        ref1 = store.save(ArtifactType.HAR, content)
        ref2 = store.save(ArtifactType.HAR, content)

        # Same SHA but distinct evidence IDs
        assert ref1.sha256 == ref2.sha256
        assert ref1.evidence_id != ref2.evidence_id

    def test_save_different_content_different_sha(self, store: EvidenceStore) -> None:
        ref1 = store.save(ArtifactType.RAW, b"aaa")
        ref2 = store.save(ArtifactType.RAW, b"bbb")

        assert ref1.sha256 != ref2.sha256


class TestEvidenceStoreGet:
    def test_get_by_sha256(self, store: EvidenceStore) -> None:
        content = b"retrieve me by sha"
        ref = store.save(ArtifactType.SCREENSHOT, content)

        artifact = store.get(sha256=ref.sha256)
        assert artifact.content == content
        assert artifact.ref.sha256 == ref.sha256

    def test_get_by_evidence_ref_id(self, store: EvidenceStore) -> None:
        content = b"retrieve me by id"
        ref = store.save(ArtifactType.LOG, content, {"run_id": "r123"})

        artifact = store.get(evidence_ref_id=ref.evidence_id)
        assert artifact.content == content

    def test_get_not_found_raises(self, store: EvidenceStore) -> None:
        with pytest.raises(FileNotFoundError):
            store.get(evidence_ref_id="nonexistent-id")


class TestEvidenceStoreImmutability:
    def test_no_update_api(self, store: EvidenceStore) -> None:
        """EvidenceStore exposes no update or delete methods."""
        assert not hasattr(store, "update")
        assert not hasattr(store, "delete")
