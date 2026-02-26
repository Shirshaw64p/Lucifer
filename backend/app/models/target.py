"""Target model — an IP, CIDR, domain, or URL in scope for a Run.

The scope guard validates every tool invocation against in-scope Targets.
"""

from __future__ import annotations

import enum
import uuid

from sqlalchemy import Boolean, Enum, ForeignKey, String
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.models.base import Base, TimestampMixin, UUIDPrimaryKey


class TargetType(str, enum.Enum):
    """Types of targets that can be in scope."""
    ip = "ip"
    cidr = "cidr"
    domain = "domain"
    url = "url"


class Target(UUIDPrimaryKey, TimestampMixin, Base):
    """A single target within a Run's scope."""

    __tablename__ = "targets"

    run_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("runs.id", ondelete="CASCADE"), nullable=False
    )
    target_type: Mapped[TargetType] = mapped_column(
        Enum(TargetType, name="target_type", create_constraint=True), nullable=False
    )
    value: Mapped[str] = mapped_column(String(2048), nullable=False)
    in_scope: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    metadata_: Mapped[dict | None] = mapped_column("metadata", JSONB, default=dict)

    # ── relationships ────────────────────────────────────────────────────
    run = relationship("Run", back_populates="targets")
    findings = relationship("Finding", back_populates="target")
