"""
kb/memory.py — AgentMemory: per-agent working memory backed by ChromaDB.

Namespace: ``{agent_type}_{target_id}``
Used by every agent brain for lessons learned, discovered assets,
credential patterns, and contextual recall.
"""
from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from core.config import settings
from core.models import ChunkResult

logger = logging.getLogger(__name__)


class AgentMemory:
    """
    Persistent, searchable working memory for a single agent instance.

    Backed by a ChromaDB collection namespaced to
    ``{agent_type}_{target_id}``.

    * ``save(key, value, metadata)``   — store a memory
    * ``retrieve(query, k=5)``         — find relevant memories
    * ``get_all()``                    — dump entire namespace
    * ``clear()``                      — wipe the namespace
    """

    def __init__(
        self,
        agent_type: str,
        target_id: str,
        chroma_persist_dir: Optional[str] = None,
        embedding_model: Optional[str] = None,
    ) -> None:
        self._agent_type = agent_type
        self._target_id = target_id
        self._namespace = f"{agent_type}_{target_id}"
        self._chroma_dir = chroma_persist_dir or settings.chroma_persist_dir
        self._embedding_model = embedding_model or settings.embedding_model
        self._chroma_client: Any = None
        self._collection: Any = None

    # ------------------------------------------------------------------
    # ChromaDB helpers
    # ------------------------------------------------------------------

    @property
    def namespace(self) -> str:
        return self._namespace

    def _get_chroma(self) -> Any:
        if self._chroma_client is None:
            import chromadb  # type: ignore[import-untyped]

            self._chroma_client = chromadb.PersistentClient(path=self._chroma_dir)
        return self._chroma_client

    def _get_collection(self) -> Any:
        if self._collection is None:
            client = self._get_chroma()
            # Collection name must be 3-63 chars, [a-zA-Z0-9_-]
            safe_name = self._namespace[:63].replace(".", "_").replace("/", "_")
            self._collection = client.get_or_create_collection(
                name=safe_name,
                metadata={"hnsw:space": "cosine"},
            )
        return self._collection

    # ------------------------------------------------------------------
    # Embedding
    # ------------------------------------------------------------------

    def _embed(self, texts: List[str]) -> List[List[float]]:
        from litellm import embedding as litellm_embedding  # type: ignore[import-untyped]

        response = litellm_embedding(model=self._embedding_model, input=texts)
        return [item["embedding"] for item in response.data]

    # ------------------------------------------------------------------
    # Save
    # ------------------------------------------------------------------

    def save(
        self,
        key: str,
        value: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Store a memory entry.

        Parameters
        ----------
        key : str
            Unique identifier for this memory (e.g. ``"discovered_endpoints"``).
        value : str
            The content to remember.
        metadata : dict, optional
            Extra metadata (e.g. finding_id, timestamp).

        Returns
        -------
        str
            The ID of the stored memory.
        """
        coll = self._get_collection()

        memory_id = f"{self._namespace}_{key}_{uuid.uuid4().hex[:8]}"
        meta = {
            "key": key,
            "agent_type": self._agent_type,
            "target_id": self._target_id,
            "namespace": self._namespace,
            "stored_utc": datetime.now(timezone.utc).isoformat(),
        }
        if metadata:
            meta.update({k: str(v) for k, v in metadata.items()})

        embedding = self._embed([value])[0]

        coll.upsert(
            ids=[memory_id],
            embeddings=[embedding],
            documents=[value],
            metadatas=[meta],
        )

        logger.info(
            "memory.saved",
            extra={"namespace": self._namespace, "key": key, "id": memory_id},
        )
        return memory_id

    # ------------------------------------------------------------------
    # Retrieve
    # ------------------------------------------------------------------

    def retrieve(
        self,
        query: str,
        k: int = 5,
        filter_key: Optional[str] = None,
    ) -> List[ChunkResult]:
        """
        Retrieve the *k* most relevant memories for *query*.
        """
        coll = self._get_collection()

        query_embedding = self._embed([query])[0]

        where_filter = None
        if filter_key:
            where_filter = {"key": filter_key}

        results = coll.query(
            query_embeddings=[query_embedding],
            n_results=k,
            include=["documents", "metadatas", "distances"],
            where=where_filter,
        )

        memories: List[ChunkResult] = []
        if not results or not results["ids"] or not results["ids"][0]:
            return memories

        for i, mem_id in enumerate(results["ids"][0]):
            meta = results["metadatas"][0][i] if results["metadatas"] else {}
            doc = results["documents"][0][i] if results["documents"] else ""
            dist = results["distances"][0][i] if results["distances"] else 1.0
            score = max(0.0, 1.0 - dist)

            memories.append(
                ChunkResult(
                    doc_id=meta.get("namespace", self._namespace),
                    chunk_id=mem_id,
                    content=doc,
                    relevance_score=round(score, 4),
                    metadata=meta,
                )
            )

        return memories

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------

    def get_all(self) -> List[Dict[str, Any]]:
        """Return all memories in this namespace."""
        coll = self._get_collection()
        data = coll.get(include=["documents", "metadatas"])
        results: List[Dict[str, Any]] = []
        if data and data["ids"]:
            for i, mid in enumerate(data["ids"]):
                results.append({
                    "id": mid,
                    "content": data["documents"][i] if data["documents"] else "",
                    "metadata": data["metadatas"][i] if data["metadatas"] else {},
                })
        return results

    def clear(self) -> int:
        """Delete all memories in this namespace. Returns count deleted."""
        coll = self._get_collection()
        data = coll.get()
        count = len(data["ids"]) if data and data["ids"] else 0
        if count > 0:
            coll.delete(ids=data["ids"])
        logger.info("memory.cleared", extra={"namespace": self._namespace, "deleted": count})
        return count
