"""EvidenceArtifact model — screenshot, pcap, log, or file tied to a Finding.

Actual bytes live in MinIO; this table stores the object key and metadata.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import BigInteger, DateTime, Enum, ForeignKey, String, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.models.base import Base, UUIDPrimaryKey


class ArtifactType(str, enum.Enum):
    """Categories of evidence artifacts."""
    screenshot = "screenshot"
    pcap = "pcap"
    log = "log"
    report = "report"
    other = "other"


class EvidenceArtifact(UUIDPrimaryKey, Base):
    """Metadata record for an evidence file stored in MinIO."""

    __tablename__ = "evidence_artifacts"

    finding_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False
    )
    artifact_type: Mapped[ArtifactType] = mapped_column(
        Enum(ArtifactType, name="artifact_type", create_constraint=True), nullable=False
    )
    storage_path: Mapped[str] = mapped_column(String(1024), nullable=False)
    mime_type: Mapped[str] = mapped_column(String(255), nullable=False)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        server_default=text("now()"),
        nullable=False,
    )

    # ── relationships ────────────────────────────────────────────────────
    finding = relationship("Finding", back_populates="evidence_artifacts")
