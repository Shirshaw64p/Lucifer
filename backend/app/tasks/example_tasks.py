"""Example / placeholder Celery tasks.

These demonstrate the task queue is wired correctly.
Replace with real agent-orchestration tasks later.
"""

from __future__ import annotations

import structlog

from backend.app.tasks.celery_app import celery_app

logger = structlog.stdlib.get_logger(__name__)


@celery_app.task(bind=True, name="lucifer.ping")
def ping(self) -> str:
    """Simple health-check task — returns 'pong'."""
    logger.info("task.ping", task_id=self.request.id)
    return "pong"


@celery_app.task(bind=True, name="lucifer.run_agent")
def run_agent(self, run_id: str, agent_id: str) -> dict:
    """Stub task for launching an agent against a run.

    In a full implementation this would:
    1. Load the Run and Agent from the DB
    2. Initialize the LangChain/LangGraph agent
    3. Execute the agent's workflow
    4. Store findings and evidence
    """
    logger.info("task.run_agent", task_id=self.request.id, run_id=run_id, agent_id=agent_id)
    return {"status": "stub", "run_id": run_id, "agent_id": agent_id}
