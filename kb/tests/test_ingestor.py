"""
Tests for kb/ingestor.py — DocumentIngestor.

All embedding and ChromaDB calls are mocked.
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from kb.ingestor import DocumentIngestor, IngestResult


@pytest.fixture
def ingestor(tmp_path: Path) -> DocumentIngestor:
    return DocumentIngestor(
        chroma_persist_dir=str(tmp_path / "chroma"),
        embedding_model="text-embedding-3-small",
        chunk_size=50,
        chunk_overlap=10,
    )


class TestExtraction:
    def test_extract_txt(self, ingestor: DocumentIngestor, tmp_path: Path) -> None:
        txt_file = tmp_path / "test.txt"
        txt_file.write_text("Hello world. This is a test document.")

        text = ingestor._extract(str(txt_file))
        assert "Hello world" in text

    def test_extract_md(self, ingestor: DocumentIngestor, tmp_path: Path) -> None:
        md_file = tmp_path / "readme.md"
        md_file.write_text("# Title\n\nSome **bold** text.")

        text = ingestor._extract(str(md_file))
        assert "Title" in text
        assert "bold" in text

    def test_extract_nonexistent_raises(self, ingestor: DocumentIngestor) -> None:
        with pytest.raises(FileNotFoundError):
            ingestor._extract("/nonexistent/path.txt")


class TestChunking:
    def test_chunks_have_correct_metadata(self, ingestor: DocumentIngestor, tmp_path: Path) -> None:
        txt = tmp_path / "doc.txt"
        txt.write_text("word " * 200)  # ~200 tokens

        # Mock tokenize/detokenize to use simple whitespace splitting
        with patch.object(ingestor, "_tokenize", side_effect=lambda t: t.split()):
            with patch.object(ingestor, "_detokenize", side_effect=lambda t: " ".join(t)):
                chunks = ingestor._chunk("word " * 200, "doc1", str(txt), "global", None)

        assert len(chunks) >= 2
        assert chunks[0].doc_id == "doc1"
        assert chunks[0].scope == "global"
        assert chunks[0].chunk_id.startswith("doc1_")

    def test_chunks_overlap(self, ingestor: DocumentIngestor) -> None:
        """Consecutive chunks should overlap by chunk_overlap tokens."""
        with patch.object(ingestor, "_tokenize", side_effect=lambda t: list(range(100))):
            with patch.object(ingestor, "_detokenize", side_effect=lambda t: str(t)):
                chunks = ingestor._chunk("x" * 100, "d", "src", "global", None)

        assert len(chunks) >= 2


class TestIngestPipeline:
    def test_ingest_txt_full_pipeline(self, ingestor: DocumentIngestor, tmp_path: Path) -> None:
        """Full pipeline with mocked embedding + ChromaDB."""
        txt = tmp_path / "doc.txt"
        txt.write_text("Security testing is important for web applications. " * 20)

        mock_collection = MagicMock()

        with patch.object(ingestor, "_tokenize", side_effect=lambda t: t.split()):
            with patch.object(ingestor, "_detokenize", side_effect=lambda t: " ".join(t)):
                with patch.object(ingestor, "_embed", return_value=[[0.1] * 128]):
                    with patch.object(ingestor, "_get_chroma") as mock_chroma:
                        mock_chroma.return_value.get_or_create_collection.return_value = mock_collection
                        result = ingestor.ingest(str(txt), scope="global")

        assert isinstance(result, IngestResult)
        assert result.total_chunks >= 1
        assert result.collection_name == "lucifer_kb_global"
        mock_collection.upsert.assert_called()

    def test_ingest_empty_raises(self, ingestor: DocumentIngestor, tmp_path: Path) -> None:
        empty = tmp_path / "empty.txt"
        empty.write_text("")

        with pytest.raises(ValueError, match="No text extracted"):
            ingestor.ingest(str(empty))
