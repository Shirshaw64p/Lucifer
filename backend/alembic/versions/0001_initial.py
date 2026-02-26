"""Initial schema — all core models.

Revision ID: 0001_initial
Revises: None
Create Date: 2026-02-25

Creates tables: runs, targets, findings, evidence_artifacts,
approval_events, agents, agent_memories, kb_documents.
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

# revision identifiers
revision: str = "0001_initial"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── Enum types ───────────────────────────────────────────────────────
    run_status = sa.Enum(
        "pending", "running", "paused", "completed", "failed", "cancelled",
        name="run_status",
    )
    target_type = sa.Enum("ip", "cidr", "domain", "url", name="target_type")
    severity = sa.Enum("info", "low", "medium", "high", "critical", name="severity")
    artifact_type = sa.Enum("screenshot", "pcap", "log", "report", "other", name="artifact_type")
    approval_status = sa.Enum("pending", "approved", "denied", name="approval_status")
    doc_type = sa.Enum("cve", "playbook", "technique", "reference", name="doc_type")

    # ── agents (referenced by findings, approval_events, agent_memories) ─
    op.create_table(
        "agents",
        sa.Column("id", UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), primary_key=True),
        sa.Column("name", sa.String(255), unique=True, nullable=False),
        sa.Column("agent_type", sa.String(64), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("enabled", sa.Boolean, server_default=sa.text("true"), nullable=False),
        sa.Column("config", JSONB, server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
    )

    # ── runs ─────────────────────────────────────────────────────────────
    op.create_table(
        "runs",
        sa.Column("id", UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("status", run_status, server_default="pending", nullable=False),
        sa.Column("config", JSONB, server_default=sa.text("'{}'::jsonb")),
        sa.Column("owner_id", UUID(as_uuid=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
    )

    # ── targets ──────────────────────────────────────────────────────────
    op.create_table(
        "targets",
        sa.Column("id", UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), primary_key=True),
        sa.Column("run_id", UUID(as_uuid=True), sa.ForeignKey("runs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("target_type", target_type, nullable=False),
        sa.Column("value", sa.String(2048), nullable=False),
        sa.Column("in_scope", sa.Boolean, server_default=sa.text("true"), nullable=False),
        sa.Column("metadata", JSONB, server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
    )

    # ── findings ─────────────────────────────────────────────────────────
    op.create_table(
        "findings",
        sa.Column("id", UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), primary_key=True),
        sa.Column("run_id", UUID(as_uuid=True), sa.ForeignKey("runs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("target_id", UUID(as_uuid=True), sa.ForeignKey("targets.id", ondelete="SET NULL"), nullable=True),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("severity", severity, nullable=False),
        sa.Column("cvss_score", sa.Float, nullable=True),
        sa.Column("description", sa.Text, nullable=False),
        sa.Column("remediation", sa.Text, nullable=True),
        sa.Column("raw_output", sa.Text, nullable=True),
        sa.Column("agent_id", UUID(as_uuid=True), sa.ForeignKey("agents.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
    )

    # ── evidence_artifacts ───────────────────────────────────────────────
    op.create_table(
        "evidence_artifacts",
        sa.Column("id", UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), primary_key=True),
        sa.Column("finding_id", UUID(as_uuid=True), sa.ForeignKey("findings.id", ondelete="CASCADE"), nullable=False),
        sa.Column("artifact_type", artifact_type, nullable=False),
        sa.Column("storage_path", sa.String(1024), nullable=False),
        sa.Column("mime_type", sa.String(255), nullable=False),
        sa.Column("size_bytes", sa.BigInteger, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
    )

    # ── approval_events ──────────────────────────────────────────────────
    op.create_table(
        "approval_events",
        sa.Column("id", UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), primary_key=True),
        sa.Column("run_id", UUID(as_uuid=True), sa.ForeignKey("runs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("agent_id", UUID(as_uuid=True), sa.ForeignKey("agents.id", ondelete="SET NULL"), nullable=True),
        sa.Column("action_type", sa.String(128), nullable=False),
        sa.Column("action_detail", JSONB, server_default=sa.text("'{}'::jsonb")),
        sa.Column("status", approval_status, server_default="pending", nullable=False),
        sa.Column("reviewer", sa.String(255), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
    )

    # ── agent_memories ───────────────────────────────────────────────────
    op.create_table(
        "agent_memories",
        sa.Column("id", UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), primary_key=True),
        sa.Column("agent_id", UUID(as_uuid=True), sa.ForeignKey("agents.id", ondelete="CASCADE"), nullable=False),
        sa.Column("run_id", UUID(as_uuid=True), sa.ForeignKey("runs.id", ondelete="SET NULL"), nullable=True),
        sa.Column("collection_name", sa.String(255), nullable=False),
        sa.Column("content_hash", sa.String(128), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
    )

    # ── kb_documents ─────────────────────────────────────────────────────
    op.create_table(
        "kb_documents",
        sa.Column("id", UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), primary_key=True),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("doc_type", doc_type, nullable=False),
        sa.Column("content", sa.Text, nullable=False),
        sa.Column("embedding_id", sa.String(255), nullable=True),
        sa.Column("metadata", JSONB, server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("kb_documents")
    op.drop_table("agent_memories")
    op.drop_table("approval_events")
    op.drop_table("evidence_artifacts")
    op.drop_table("findings")
    op.drop_table("targets")
    op.drop_table("runs")
    op.drop_table("agents")

    # Drop enum types
    sa.Enum(name="doc_type").drop(op.get_bind(), checkfirst=True)
    sa.Enum(name="approval_status").drop(op.get_bind(), checkfirst=True)
    sa.Enum(name="artifact_type").drop(op.get_bind(), checkfirst=True)
    sa.Enum(name="severity").drop(op.get_bind(), checkfirst=True)
    sa.Enum(name="target_type").drop(op.get_bind(), checkfirst=True)
    sa.Enum(name="run_status").drop(op.get_bind(), checkfirst=True)
