"""Run coordinator — the glue layer that orchestrates agent execution.

Provides the `start_run` Celery task that:
  1. Loads run and scope from DB
  2. Instantiates agent brains
  3. Runs the orchestration graph
  4. Broadcasts journal/finding/approval events via WebSocket
  5. Triggers report assembly on completion

This module uses sync DB access (for Celery worker context) and
fires WebSocket broadcasts via asyncio event loop bridging.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone

import structlog

from backend.app.tasks.celery_app import celery_app

logger = structlog.stdlib.get_logger(__name__)


def _get_or_create_loop():
    """Get or create an asyncio event loop for the current thread."""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            raise RuntimeError
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop


def _broadcast_sync(coro):
    """Run an async broadcast coroutine from sync Celery context."""
    try:
        loop = _get_or_create_loop()
        loop.run_until_complete(coro)
    except Exception as e:
        logger.warning("broadcast_failed", error=str(e))


@celery_app.task(bind=True, name="lucifer.start_run")
def start_run(self, run_id: str) -> dict:
    """Main run orchestration task.

    This is the entry point triggered by POST /api/v1/runs.
    In a full implementation, each step would invoke the actual
    agent brains (ReconBrain, WebBrain, etc.) via LangGraph.
    For the MVP we simulate the orchestration flow to verify
    the full pipeline works end-to-end.
    """
    from backend.websocket_manager import ws_manager

    logger.info("run.starting", run_id=run_id, task_id=self.request.id)

    try:
        # Phase 1: Update run status to running
        _update_run_status(run_id, "running")

        # Phase 2: Register the orchestrator agent
        agent_id = _ensure_orchestrator_agent(run_id)

        # Phase 3: Broadcast agent status - running
        _broadcast_sync(ws_manager.broadcast_agent_status(run_id, {
            "agent_id": str(agent_id),
            "agent_name": "Orchestrator",
            "llm_model": "claude-3.5-sonnet",
            "status": "running",
            "current_step": "Initializing",
            "tokens_used": 0,
            "token_budget": 100000,
        }))

        # Phase 4: Write initial journal entry
        journal_entry = {
            "agent_name": "Orchestrator",
            "entry_type": "thought",
            "content": f"Starting orchestration for run {run_id}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        _write_journal(run_id, journal_entry)
        _broadcast_sync(ws_manager.broadcast_journal(run_id, journal_entry))

        # Phase 5: Simulate reconnaissance phase
        _broadcast_sync(ws_manager.broadcast_agent_status(run_id, {
            "agent_id": str(agent_id),
            "agent_name": "Orchestrator",
            "llm_model": "claude-3.5-sonnet",
            "status": "running",
            "current_step": "Reconnaissance",
            "tokens_used": 1500,
            "token_budget": 100000,
        }))

        recon_journal = {
            "agent_name": "ReconBrain",
            "entry_type": "action",
            "content": "Scanning target scope for active hosts and services",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        _write_journal(run_id, recon_journal)
        _broadcast_sync(ws_manager.broadcast_journal(run_id, recon_journal))

        # Phase 6: Create a sample finding
        finding = _create_sample_finding(run_id, agent_id)
        if finding:
            _broadcast_sync(ws_manager.broadcast_finding(run_id, {
                "finding_id": str(finding["id"]),
                "title": finding["title"],
                "severity": finding["severity"],
                "agent_name": "ReconBrain",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }))

        # Phase 7: Complete the run
        _broadcast_sync(ws_manager.broadcast_agent_status(run_id, {
            "agent_id": str(agent_id),
            "agent_name": "Orchestrator",
            "llm_model": "claude-3.5-sonnet",
            "status": "complete",
            "current_step": "Done",
            "tokens_used": 5000,
            "token_budget": 100000,
        }))

        completion_journal = {
            "agent_name": "Orchestrator",
            "entry_type": "observation",
            "content": f"Run {run_id} completed successfully",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        _write_journal(run_id, completion_journal)
        _broadcast_sync(ws_manager.broadcast_journal(run_id, completion_journal))

        _update_run_status(run_id, "completed")

        logger.info("run.completed", run_id=run_id)
        return {"status": "completed", "run_id": run_id}

    except Exception as exc:
        logger.exception("run.failed", run_id=run_id, error=str(exc))
        _update_run_status(run_id, "failed")
        return {"status": "failed", "run_id": run_id, "error": str(exc)}


def _update_run_status(run_id: str, status: str) -> None:
    """Update run status using sync DB access."""
    try:
        from sqlalchemy import create_engine, text
        from backend.app.core.config import get_settings
        settings = get_settings()
        sync_url = settings.async_database_url.replace("+asyncpg", "+psycopg2")
        engine = create_engine(sync_url)
        with engine.connect() as conn:
            conn.execute(
                text("UPDATE runs SET status = :status WHERE id = :id"),
                {"status": status, "id": run_id},
            )
            conn.commit()
        engine.dispose()
    except Exception as e:
        logger.warning("db.update_failed", run_id=run_id, error=str(e))


def _ensure_orchestrator_agent(run_id: str) -> str:
    """Ensure an orchestrator agent exists in the DB, return its ID."""
    try:
        from sqlalchemy import create_engine, text
        from backend.app.core.config import get_settings
        settings = get_settings()
        sync_url = settings.async_database_url.replace("+asyncpg", "+psycopg2")
        engine = create_engine(sync_url)
        with engine.connect() as conn:
            result = conn.execute(
                text("SELECT id FROM agents WHERE name = 'Orchestrator' LIMIT 1")
            ).fetchone()
            if result:
                agent_id = str(result[0])
            else:
                agent_id = str(uuid.uuid4())
                conn.execute(
                    text(
                        "INSERT INTO agents (id, name, agent_type, enabled, config, created_at, updated_at) "
                        "VALUES (:id, :name, :type, true, '{}'::jsonb, now(), now())"
                    ),
                    {"id": agent_id, "name": "Orchestrator", "type": "orchestrator"},
                )
                conn.commit()
        engine.dispose()
        return agent_id
    except Exception as e:
        logger.warning("agent.create_failed", error=str(e))
        return str(uuid.uuid4())


def _write_journal(run_id: str, entry: dict) -> None:
    """Write a journal entry — stored in-memory for now, broadcast via WS."""
    logger.info("journal.write", run_id=run_id, entry_type=entry.get("entry_type"))


def _create_sample_finding(run_id: str, agent_id: str) -> dict | None:
    """Create a sample finding in the DB for testing."""
    try:
        from sqlalchemy import create_engine, text
        from backend.app.core.config import get_settings
        settings = get_settings()
        sync_url = settings.async_database_url.replace("+asyncpg", "+psycopg2")
        engine = create_engine(sync_url)
        finding_id = str(uuid.uuid4())
        with engine.connect() as conn:
            conn.execute(
                text(
                    "INSERT INTO findings (id, run_id, title, severity, description, agent_id, created_at) "
                    "VALUES (:id, :run_id, :title, :severity, :description, :agent_id, now())"
                ),
                {
                    "id": finding_id,
                    "run_id": run_id,
                    "title": "Open port detected",
                    "severity": "info",
                    "description": "Port 80 (HTTP) is open and serving content.",
                    "agent_id": agent_id,
                },
            )
            conn.commit()
        engine.dispose()
        return {
            "id": finding_id,
            "title": "Open port detected",
            "severity": "info",
        }
    except Exception as e:
        logger.warning("finding.create_failed", error=str(e))
        return None
