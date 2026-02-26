"""
Tests for kb/memory.py — AgentMemory.

ChromaDB and embedding calls are mocked.
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from core.models import ChunkResult
from kb.memory import AgentMemory


@pytest.fixture
def memory(tmp_path: Path) -> AgentMemory:
    return AgentMemory(
        agent_type="recon",
        target_id="target_abc",
        chroma_persist_dir=str(tmp_path / "chroma"),
        embedding_model="text-embedding-3-small",
    )


def _mock_collection():
    coll = MagicMock()
    coll.upsert = MagicMock()
    coll.query.return_value = {
        "ids": [["mem_1", "mem_2"]],
        "documents": [["Found open port 80", "Login form at /admin"]],
        "metadatas": [[
            {"key": "ports", "namespace": "recon_target_abc"},
            {"key": "forms", "namespace": "recon_target_abc"},
        ]],
        "distances": [[0.1, 0.3]],
    }
    coll.get.return_value = {
        "ids": ["mem_1", "mem_2"],
        "documents": ["Found open port 80", "Login form at /admin"],
        "metadatas": [
            {"key": "ports", "namespace": "recon_target_abc"},
            {"key": "forms", "namespace": "recon_target_abc"},
        ],
    }
    return coll


class TestAgentMemoryNamespace:
    def test_namespace_format(self, memory: AgentMemory) -> None:
        assert memory.namespace == "recon_target_abc"


class TestAgentMemorySave:
    def test_save_returns_id(self, memory: AgentMemory) -> None:
        coll = _mock_collection()

        with patch.object(memory, "_get_collection", return_value=coll):
            with patch.object(memory, "_embed", return_value=[[0.1] * 128]):
                mem_id = memory.save("open_ports", "Port 80, 443 open on target")

        assert mem_id.startswith("recon_target_abc_open_ports_")
        coll.upsert.assert_called_once()

    def test_save_with_metadata(self, memory: AgentMemory) -> None:
        coll = _mock_collection()

        with patch.object(memory, "_get_collection", return_value=coll):
            with patch.object(memory, "_embed", return_value=[[0.1] * 128]):
                mem_id = memory.save(
                    "credential_pattern",
                    "admin:admin default credentials found",
                    metadata={"severity": "high"},
                )

        assert mem_id
        call_args = coll.upsert.call_args
        meta = call_args.kwargs.get("metadatas") or call_args[1].get("metadatas")
        assert meta[0]["severity"] == "high"


class TestAgentMemoryRetrieve:
    def test_retrieve_returns_chunk_results(self, memory: AgentMemory) -> None:
        coll = _mock_collection()

        with patch.object(memory, "_get_collection", return_value=coll):
            with patch.object(memory, "_embed", return_value=[[0.1] * 128]):
                results = memory.retrieve("open ports", k=2)

        assert len(results) == 2
        assert all(isinstance(r, ChunkResult) for r in results)
        assert results[0].relevance_score >= results[1].relevance_score

    def test_retrieve_empty(self, memory: AgentMemory) -> None:
        coll = MagicMock()
        coll.query.return_value = {"ids": [[]], "documents": [[]], "metadatas": [[]], "distances": [[]]}

        with patch.object(memory, "_get_collection", return_value=coll):
            with patch.object(memory, "_embed", return_value=[[0.1] * 128]):
                results = memory.retrieve("nonexistent")

        assert results == []


class TestAgentMemoryUtils:
    def test_get_all(self, memory: AgentMemory) -> None:
        coll = _mock_collection()

        with patch.object(memory, "_get_collection", return_value=coll):
            all_mems = memory.get_all()

        assert len(all_mems) == 2
        assert all_mems[0]["content"] == "Found open port 80"

    def test_clear(self, memory: AgentMemory) -> None:
        coll = _mock_collection()

        with patch.object(memory, "_get_collection", return_value=coll):
            count = memory.clear()

        assert count == 2
        coll.delete.assert_called_once()
