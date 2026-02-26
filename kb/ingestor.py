"""
kb/ingestor.py — DocumentIngestor: Extract → Chunk → Embed → Store pipeline.

Supports PDF (pdfminer), TXT, MD, and URL (requests + BeautifulSoup).
Chunks via recursive text splitting (512 tokens, 50 overlap, tiktoken).
Embeds via text-embedding-3-small or nomic-embed-text through LiteLLM.
Stores in ChromaDB with full metadata (doc_id, chunk_id, source, scope, project_id).
"""
from __future__ import annotations

import hashlib
import logging
import os
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.config import settings

logger = logging.getLogger(__name__)


@dataclass
class DocumentChunk:
    doc_id: str
    chunk_id: str
    content: str
    source: str
    scope: str               # "global" or "project"
    project_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class IngestResult:
    doc_id: str
    source: str
    total_chunks: int
    collection_name: str
    metadata: Dict[str, Any] = field(default_factory=dict)


class DocumentIngestor:
    """
    Ingest documents into the knowledge base.

    Pipeline: Extract text → Chunk → Embed → Store in ChromaDB.
    """

    def __init__(
        self,
        chroma_persist_dir: Optional[str] = None,
        embedding_model: Optional[str] = None,
        chunk_size: int = 512,
        chunk_overlap: int = 50,
        collection_prefix: str = "lucifer_kb",
    ) -> None:
        self._chroma_dir = chroma_persist_dir or settings.chroma_persist_dir
        self._embedding_model = embedding_model or settings.embedding_model
        self._chunk_size = chunk_size
        self._chunk_overlap = chunk_overlap
        self._collection_prefix = collection_prefix
        self._chroma_client: Any = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def ingest(
        self,
        file_path_or_url: str,
        scope: str = "global",
        project_id: Optional[str] = None,
    ) -> IngestResult:
        """
        Full ingest pipeline: Extract → Chunk → Embed → Store.

        Parameters
        ----------
        file_path_or_url : str
            Local file path or HTTP(S) URL.
        scope : str
            ``"global"`` or ``"project"``.
        project_id : str | None
            Required when scope is ``"project"``.

        Returns
        -------
        IngestResult
        """
        source = file_path_or_url
        doc_id = hashlib.sha256(source.encode()).hexdigest()[:16]

        # 1. Extract
        text = self._extract(file_path_or_url)
        if not text.strip():
            raise ValueError(f"No text extracted from {source}")

        # 2. Chunk
        chunks = self._chunk(text, doc_id, source, scope, project_id)

        # 3. Embed + Store
        collection_name = self._collection_name(scope, project_id)
        self._store_chunks(chunks, collection_name)

        logger.info(
            "kb.ingested",
            extra={"doc_id": doc_id, "chunks": len(chunks), "source": source},
        )
        return IngestResult(
            doc_id=doc_id,
            source=source,
            total_chunks=len(chunks),
            collection_name=collection_name,
        )

    # ------------------------------------------------------------------
    # Extraction
    # ------------------------------------------------------------------

    def _extract(self, source: str) -> str:
        if source.startswith(("http://", "https://")):
            return self._extract_url(source)

        path = Path(source)
        suffix = path.suffix.lower()

        if suffix == ".pdf":
            return self._extract_pdf(path)
        elif suffix in (".txt", ".md", ".markdown"):
            return path.read_text(encoding="utf-8", errors="replace")
        else:
            # Best-effort plain text
            return path.read_text(encoding="utf-8", errors="replace")

    @staticmethod
    def _extract_pdf(path: Path) -> str:
        from pdfminer.high_level import extract_text  # type: ignore[import-untyped]

        return extract_text(str(path))

    @staticmethod
    def _extract_url(url: str) -> str:
        import requests  # type: ignore[import-untyped]
        from bs4 import BeautifulSoup  # type: ignore[import-untyped]

        resp = requests.get(url, timeout=30, verify=False)
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, "html.parser")

        # Remove script and style tags
        for tag in soup(["script", "style", "nav", "footer", "header"]):
            tag.decompose()

        return soup.get_text(separator="\n", strip=True)

    # ------------------------------------------------------------------
    # Chunking (recursive token-based)
    # ------------------------------------------------------------------

    def _chunk(
        self,
        text: str,
        doc_id: str,
        source: str,
        scope: str,
        project_id: Optional[str],
    ) -> List[DocumentChunk]:
        tokens = self._tokenize(text)
        chunks: List[DocumentChunk] = []
        start = 0

        while start < len(tokens):
            end = min(start + self._chunk_size, len(tokens))
            chunk_tokens = tokens[start:end]
            chunk_text = self._detokenize(chunk_tokens)
            chunk_id = f"{doc_id}_{len(chunks):04d}"

            chunks.append(
                DocumentChunk(
                    doc_id=doc_id,
                    chunk_id=chunk_id,
                    content=chunk_text,
                    source=source,
                    scope=scope,
                    project_id=project_id,
                    metadata={
                        "token_start": start,
                        "token_end": end,
                    },
                )
            )

            step = self._chunk_size - self._chunk_overlap
            start += max(step, 1)

        return chunks

    @staticmethod
    def _tokenize(text: str) -> List[int]:
        import tiktoken  # type: ignore[import-untyped]

        enc = tiktoken.get_encoding("cl100k_base")
        return enc.encode(text)

    @staticmethod
    def _detokenize(tokens: List[int]) -> str:
        import tiktoken  # type: ignore[import-untyped]

        enc = tiktoken.get_encoding("cl100k_base")
        return enc.decode(tokens)

    # ------------------------------------------------------------------
    # Embedding + ChromaDB Storage
    # ------------------------------------------------------------------

    def _get_chroma(self) -> Any:
        if self._chroma_client is None:
            import chromadb  # type: ignore[import-untyped]

            self._chroma_client = chromadb.PersistentClient(
                path=self._chroma_dir
            )
        return self._chroma_client

    def _collection_name(self, scope: str, project_id: Optional[str]) -> str:
        if scope == "project" and project_id:
            return f"{self._collection_prefix}_{project_id}"
        return f"{self._collection_prefix}_global"

    def _embed(self, texts: List[str]) -> List[List[float]]:
        """Embed texts via LiteLLM (supports OpenAI, Ollama, etc.)."""
        from litellm import embedding as litellm_embedding  # type: ignore[import-untyped]

        response = litellm_embedding(
            model=self._embedding_model,
            input=texts,
        )
        return [item["embedding"] for item in response.data]

    def _store_chunks(self, chunks: List[DocumentChunk], collection_name: str) -> None:
        chroma = self._get_chroma()
        collection = chroma.get_or_create_collection(
            name=collection_name,
            metadata={"hnsw:space": "cosine"},
        )

        # Batch embed (max 96 per call to avoid rate limits)
        batch_size = 96
        for i in range(0, len(chunks), batch_size):
            batch = chunks[i : i + batch_size]
            texts = [c.content for c in batch]
            embeddings = self._embed(texts)

            ids = [c.chunk_id for c in batch]
            documents = texts
            metadatas = [
                {
                    "doc_id": c.doc_id,
                    "chunk_id": c.chunk_id,
                    "source": c.source,
                    "scope": c.scope,
                    "project_id": c.project_id or "",
                }
                for c in batch
            ]

            collection.upsert(
                ids=ids,
                embeddings=embeddings,
                documents=documents,
                metadatas=metadatas,
            )

        logger.info(
            "kb.stored",
            extra={"collection": collection_name, "chunk_count": len(chunks)},
        )
