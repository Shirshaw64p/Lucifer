"""Run model — represents a single pentest engagement / campaign.

A Run owns Targets, Findings, ApprovalEvents, and AgentMemory records.
"""

from __future__ import annotations

import enum
import uuid

from sqlalchemy import Enum, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.models.base import Base, TimestampMixin, UUIDPrimaryKey


class RunStatus(str, enum.Enum):
    """Lifecycle states of a Run."""
    pending = "pending"
    running = "running"
    paused = "paused"
    completed = "completed"
    failed = "failed"
    cancelled = "cancelled"


class Run(UUIDPrimaryKey, TimestampMixin, Base):
    """A single red-team engagement / campaign."""

    __tablename__ = "runs"

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[RunStatus] = mapped_column(
        Enum(RunStatus, name="run_status", create_constraint=True),
        default=RunStatus.pending,
        nullable=False,
    )
    config: Mapped[dict | None] = mapped_column(JSONB, default=dict)
    owner_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)

    # ── relationships ────────────────────────────────────────────────────
    targets = relationship("Target", back_populates="run", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="run", cascade="all, delete-orphan")
    approval_events = relationship("ApprovalEvent", back_populates="run", cascade="all, delete-orphan")
    agent_memories = relationship("AgentMemory", back_populates="run")
