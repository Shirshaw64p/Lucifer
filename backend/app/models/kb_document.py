"""KBDocument model — knowledge-base document (CVEs, playbooks, techniques).

Documents can optionally have a ChromaDB embedding_id for semantic search.
"""

from __future__ import annotations

import enum

from sqlalchemy import Enum, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.models.base import Base, TimestampMixin, UUIDPrimaryKey


class DocType(str, enum.Enum):
    """Types of knowledge base documents."""
    cve = "cve"
    playbook = "playbook"
    technique = "technique"
    reference = "reference"


class KBDocument(UUIDPrimaryKey, TimestampMixin, Base):
    """A knowledge-base entry used by agents for context and planning."""

    __tablename__ = "kb_documents"

    title: Mapped[str] = mapped_column(String(512), nullable=False)
    doc_type: Mapped[DocType] = mapped_column(
        Enum(DocType, name="doc_type", create_constraint=True), nullable=False
    )
    content: Mapped[str] = mapped_column(Text, nullable=False)
    embedding_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    metadata_: Mapped[dict | None] = mapped_column("metadata", JSONB, default=dict)
