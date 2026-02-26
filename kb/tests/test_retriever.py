"""
Tests for kb/retriever.py — HybridRetriever.

ChromaDB and embedding calls are mocked.
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from core.models import ChunkResult
from kb.retriever import HybridRetriever


@pytest.fixture
def retriever(tmp_path: Path) -> HybridRetriever:
    return HybridRetriever(
        chroma_persist_dir=str(tmp_path / "chroma"),
        embedding_model="text-embedding-3-small",
    )


def _mock_collection(docs, metas=None):
    """Build a mock ChromaDB collection."""
    ids = [f"chunk_{i}" for i in range(len(docs))]
    if metas is None:
        metas = [{"doc_id": f"doc_{i}", "source": "test"} for i in range(len(docs))]

    coll = MagicMock()
    coll.query.return_value = {
        "ids": [ids],
        "documents": [docs],
        "metadatas": [metas],
        "distances": [[0.1 * (i + 1) for i in range(len(docs))]],
    }
    coll.get.return_value = {
        "ids": ids,
        "documents": docs,
        "metadatas": metas,
    }
    return coll


class TestSemanticSearch:
    def test_semantic_search_returns_chunks(self, retriever: HybridRetriever) -> None:
        docs = ["SQL injection is a web vulnerability", "XSS allows script injection"]
        coll = _mock_collection(docs)

        with patch.object(retriever, "_get_collection", return_value=coll):
            with patch.object(retriever, "_embed", return_value=[[0.1] * 128]):
                results = retriever.semantic_search("sql injection", "test_coll", k=2)

        assert len(results) == 2
        assert all(isinstance(r, ChunkResult) for r in results)
        assert results[0].relevance_score >= results[1].relevance_score

    def test_semantic_search_empty_collection(self, retriever: HybridRetriever) -> None:
        coll = MagicMock()
        coll.query.return_value = {"ids": [[]], "documents": [[]], "metadatas": [[]], "distances": [[]]}

        with patch.object(retriever, "_get_collection", return_value=coll):
            with patch.object(retriever, "_embed", return_value=[[0.1] * 128]):
                results = retriever.semantic_search("test", "empty_coll")

        assert results == []


class TestKeywordSearch:
    def test_bm25_finds_relevant_docs(self, retriever: HybridRetriever) -> None:
        docs = [
            "SQL injection testing methodology",
            "Cross-site scripting XSS attacks",
            "Buffer overflow exploitation",
        ]
        coll = _mock_collection(docs)

        with patch.object(retriever, "_get_collection", return_value=coll):
            results = retriever.keyword_search("SQL injection", "test_coll", k=3)

        assert len(results) >= 1
        # First result should be the SQL injection doc
        assert "SQL" in results[0].content or "sql" in results[0].content.lower()

    def test_bm25_tokenizer(self) -> None:
        tokens = HybridRetriever._bm25_tokenize("The quick brown fox")
        assert "quick" in tokens
        assert "brown" in tokens
        assert "the" not in tokens  # stop word


class TestHybridRetrieve:
    def test_rrf_merges_results(self, retriever: HybridRetriever) -> None:
        docs = [
            "SQL injection is dangerous",
            "XSS cross-site scripting",
            "Command injection shells",
        ]
        coll = _mock_collection(docs)

        with patch.object(retriever, "_get_collection", return_value=coll):
            with patch.object(retriever, "_embed", return_value=[[0.1] * 128]):
                results = retriever.retrieve("injection attack", "test_coll", k=3)

        assert len(results) >= 1
        # All results should have positive RRF scores
        assert all(r.relevance_score > 0 for r in results)
        # Results should be sorted by score descending
        for i in range(len(results) - 1):
            assert results[i].relevance_score >= results[i + 1].relevance_score
