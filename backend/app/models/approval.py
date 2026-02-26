"""ApprovalEvent model — human approve / deny record for risky agent actions.

High-risk actions (exploit, brute_force, exfil) are gated behind human
approval. This table records the request and the reviewer's decision.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, Enum, ForeignKey, String, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.models.base import Base, UUIDPrimaryKey


class ApprovalStatus(str, enum.Enum):
    """Approval lifecycle states."""
    pending = "pending"
    approved = "approved"
    denied = "denied"


class ApprovalEvent(UUIDPrimaryKey, Base):
    """Records a human approve / deny decision for a risky agent action."""

    __tablename__ = "approval_events"

    run_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("runs.id", ondelete="CASCADE"), nullable=False
    )
    agent_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("agents.id", ondelete="SET NULL"), nullable=True
    )
    action_type: Mapped[str] = mapped_column(String(128), nullable=False)
    action_detail: Mapped[dict | None] = mapped_column(JSONB, default=dict)
    status: Mapped[ApprovalStatus] = mapped_column(
        Enum(ApprovalStatus, name="approval_status", create_constraint=True),
        default=ApprovalStatus.pending,
        nullable=False,
    )
    reviewer: Mapped[str | None] = mapped_column(String(255), nullable=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        server_default=text("now()"),
        nullable=False,
    )

    # ── relationships ────────────────────────────────────────────────────
    run = relationship("Run", back_populates="approval_events")
    agent = relationship("Agent", back_populates="approval_events")
