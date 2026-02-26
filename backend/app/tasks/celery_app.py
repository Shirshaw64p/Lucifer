"""Celery application instance for Lucifer task queue.

Uses Redis as broker and result backend. Workers are started with:
    celery -A backend.app.tasks.celery_app worker --loglevel=info

All task modules should be listed in `include` so they are auto-discovered.
"""

from __future__ import annotations

from celery import Celery

from backend.app.core.config import get_settings

settings = get_settings()

celery_app = Celery(
    "lucifer",
    broker=settings.effective_celery_broker,
    backend=settings.effective_celery_backend,
    include=[
        "backend.app.tasks.example_tasks",
        "backend.run_coordinator",
    ],
)

# ── Celery configuration ────────────────────────────────────────────────────
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    result_expires=3600,  # 1 hour
    broker_connection_retry_on_startup=True,
)
