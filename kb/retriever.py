"""
kb/retriever.py — HybridRetriever: semantic + keyword (BM25) search
with Reciprocal Rank Fusion (RRF) merging.

Every retrieval returns: doc_id, chunk_id, content, relevance_score for citation.
"""
from __future__ import annotations

import logging
import math
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from core.config import settings
from core.models import ChunkResult

logger = logging.getLogger(__name__)


class HybridRetriever:
    """
    Hybrid (semantic + BM25) retrieval over ChromaDB collections.

    * ``semantic_search()`` — vector similarity search
    * ``keyword_search()``  — BM25 full-text search
    * ``retrieve()``        — merged via Reciprocal Rank Fusion
    """

    def __init__(
        self,
        chroma_persist_dir: Optional[str] = None,
        embedding_model: Optional[str] = None,
        rrf_k: int = 60,
    ) -> None:
        self._chroma_dir = chroma_persist_dir or settings.chroma_persist_dir
        self._embedding_model = embedding_model or settings.embedding_model
        self._rrf_k = rrf_k
        self._chroma_client: Any = None

    # ------------------------------------------------------------------
    # ChromaDB access
    # ------------------------------------------------------------------

    def _get_chroma(self) -> Any:
        if self._chroma_client is None:
            import chromadb  # type: ignore[import-untyped]

            self._chroma_client = chromadb.PersistentClient(path=self._chroma_dir)
        return self._chroma_client

    def _get_collection(self, collection: str) -> Any:
        return self._get_chroma().get_or_create_collection(
            name=collection,
            metadata={"hnsw:space": "cosine"},
        )

    # ------------------------------------------------------------------
    # Semantic search
    # ------------------------------------------------------------------

    def semantic_search(
        self,
        query: str,
        collection: str,
        k: int = 8,
    ) -> List[ChunkResult]:
        """Vector similarity search using the embedding model."""
        coll = self._get_collection(collection)
        query_embedding = self._embed([query])[0]

        results = coll.query(
            query_embeddings=[query_embedding],
            n_results=k,
            include=["documents", "metadatas", "distances"],
        )

        chunks: List[ChunkResult] = []
        if not results or not results["ids"] or not results["ids"][0]:
            return chunks

        for i, chunk_id in enumerate(results["ids"][0]):
            meta = results["metadatas"][0][i] if results["metadatas"] else {}
            doc = results["documents"][0][i] if results["documents"] else ""
            distance = results["distances"][0][i] if results["distances"] else 1.0

            # ChromaDB cosine distance → similarity score
            score = max(0.0, 1.0 - distance)

            chunks.append(
                ChunkResult(
                    doc_id=meta.get("doc_id", ""),
                    chunk_id=chunk_id,
                    content=doc,
                    relevance_score=round(score, 4),
                    metadata=meta,
                )
            )

        return chunks

    # ------------------------------------------------------------------
    # BM25 keyword search
    # ------------------------------------------------------------------

    def keyword_search(
        self,
        query: str,
        collection: str,
        k: int = 8,
    ) -> List[ChunkResult]:
        """BM25 keyword search over stored documents."""
        coll = self._get_collection(collection)

        # Retrieve all documents for BM25 scoring
        all_data = coll.get(include=["documents", "metadatas"])
        if not all_data or not all_data["ids"]:
            return []

        ids = all_data["ids"]
        docs = all_data["documents"] or [""] * len(ids)
        metas = all_data["metadatas"] or [{}] * len(ids)

        # Tokenize
        query_terms = self._bm25_tokenize(query)
        if not query_terms:
            return []

        corpus_tokens = [self._bm25_tokenize(doc) for doc in docs]

        # BM25 parameters
        k1 = 1.5
        b = 0.75
        avg_dl = sum(len(t) for t in corpus_tokens) / max(len(corpus_tokens), 1)
        n = len(corpus_tokens)

        # Document frequency
        df: Dict[str, int] = defaultdict(int)
        for tokens in corpus_tokens:
            seen = set(tokens)
            for term in seen:
                df[term] += 1

        scores: List[Tuple[int, float]] = []
        for idx, tokens in enumerate(corpus_tokens):
            tf_map: Dict[str, int] = defaultdict(int)
            for t in tokens:
                tf_map[t] += 1

            dl = len(tokens)
            score = 0.0
            for term in query_terms:
                if df[term] == 0:
                    continue
                idf = math.log((n - df[term] + 0.5) / (df[term] + 0.5) + 1.0)
                tf = tf_map.get(term, 0)
                numerator = tf * (k1 + 1)
                denominator = tf + k1 * (1 - b + b * dl / avg_dl)
                score += idf * numerator / denominator

            scores.append((idx, score))

        # Sort descending by score
        scores.sort(key=lambda x: x[1], reverse=True)

        results: List[ChunkResult] = []
        for idx, score in scores[:k]:
            if score <= 0:
                break
            results.append(
                ChunkResult(
                    doc_id=metas[idx].get("doc_id", "") if metas[idx] else "",
                    chunk_id=ids[idx],
                    content=docs[idx],
                    relevance_score=round(score, 4),
                    metadata=metas[idx] if metas[idx] else {},
                )
            )

        return results

    # ------------------------------------------------------------------
    # Hybrid retrieval (RRF)
    # ------------------------------------------------------------------

    def retrieve(
        self,
        query: str,
        collection: str,
        k: int = 8,
    ) -> List[ChunkResult]:
        """
        Hybrid retrieve via Reciprocal Rank Fusion.

        Merges results from ``semantic_search`` and ``keyword_search``
        using RRF scoring: ``score = Σ 1 / (k + rank)``.
        """
        semantic = self.semantic_search(query, collection, k=k * 2)
        keyword = self.keyword_search(query, collection, k=k * 2)

        # Aggregate RRF scores
        rrf_scores: Dict[str, float] = defaultdict(float)
        chunk_map: Dict[str, ChunkResult] = {}

        for rank, chunk in enumerate(semantic):
            rrf_scores[chunk.chunk_id] += 1.0 / (self._rrf_k + rank + 1)
            chunk_map[chunk.chunk_id] = chunk

        for rank, chunk in enumerate(keyword):
            rrf_scores[chunk.chunk_id] += 1.0 / (self._rrf_k + rank + 1)
            if chunk.chunk_id not in chunk_map:
                chunk_map[chunk.chunk_id] = chunk

        # Sort by fused score, take top-k
        sorted_ids = sorted(rrf_scores, key=rrf_scores.get, reverse=True)[:k]  # type: ignore[arg-type]

        results: List[ChunkResult] = []
        for cid in sorted_ids:
            chunk = chunk_map[cid]
            results.append(
                ChunkResult(
                    doc_id=chunk.doc_id,
                    chunk_id=chunk.chunk_id,
                    content=chunk.content,
                    relevance_score=round(rrf_scores[cid], 6),
                    metadata=chunk.metadata,
                )
            )

        return results

    # ------------------------------------------------------------------
    # Embedding
    # ------------------------------------------------------------------

    def _embed(self, texts: List[str]) -> List[List[float]]:
        from litellm import embedding as litellm_embedding  # type: ignore[import-untyped]

        response = litellm_embedding(model=self._embedding_model, input=texts)
        return [item["embedding"] for item in response.data]

    # ------------------------------------------------------------------
    # BM25 tokenizer
    # ------------------------------------------------------------------

    @staticmethod
    def _bm25_tokenize(text: str) -> List[str]:
        """Simple whitespace + punctuation tokenizer for BM25."""
        text = text.lower()
        tokens = re.findall(r"\b\w+\b", text)
        # Remove very short tokens and stop words
        stop = {"a", "an", "the", "is", "are", "was", "were", "in", "on", "at", "to", "for", "of", "and", "or", "not"}
        return [t for t in tokens if len(t) > 1 and t not in stop]
