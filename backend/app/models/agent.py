"""Agent model — a registered AI agent (recon, exploit, report, orchestrator, etc.).

Each agent has a type, config blob, and can be enabled/disabled.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Enum, String, Text, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.models.base import Base, TimestampMixin, UUIDPrimaryKey


class Agent(UUIDPrimaryKey, TimestampMixin, Base):
    """An AI agent registered in the platform."""

    __tablename__ = "agents"

    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    agent_type: Mapped[str] = mapped_column(String(64), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    config: Mapped[dict | None] = mapped_column(JSONB, default=dict)

    # ── relationships ────────────────────────────────────────────────────
    findings = relationship("Finding", back_populates="agent")
    approval_events = relationship("ApprovalEvent", back_populates="agent")
    memories = relationship("AgentMemory", back_populates="agent", cascade="all, delete-orphan")
