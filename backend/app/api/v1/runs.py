"""Runs CRUD routes."""

from __future__ import annotations

import uuid
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from backend.app.core.database import get_db
from backend.app.models import Run, RunStatus, Target, TargetType, Finding, Agent
from backend.app.schemas.schemas import (
    RunCreate,
    RunUpdate,
    RunResponse,
    RunDetailResponse,
    TargetResponse,
)

router = APIRouter()


@router.get("", response_model=List[RunResponse])
async def list_runs(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Run).order_by(Run.created_at.desc()))
    return result.scalars().all()


@router.post("", response_model=RunDetailResponse, status_code=status.HTTP_201_CREATED)
async def create_run(body: RunCreate, db: AsyncSession = Depends(get_db)):
    run = Run(name=body.name, config=body.config or {}, status=RunStatus.pending)
    db.add(run)
    await db.flush()

    if body.targets:
        for t in body.targets:
            target = Target(
                run_id=run.id,
                target_type=TargetType(t.target_type),
                value=t.value,
                in_scope=t.in_scope,
            )
            db.add(target)

    await db.flush()
    await db.refresh(run, attribute_names=["targets", "findings"])

    # Trigger async run start via Celery
    try:
        from backend.app.tasks.celery_app import celery_app
        celery_app.send_task("lucifer.start_run", args=[str(run.id)])
    except Exception:
        pass  # Celery may not be running in dev

    return RunDetailResponse(
        id=run.id,
        name=run.name,
        status=run.status.value,
        config=run.config,
        owner_id=run.owner_id,
        created_at=run.created_at,
        updated_at=run.updated_at,
        targets=[TargetResponse(
            id=t.id, run_id=t.run_id, target_type=t.target_type.value,
            value=t.value, in_scope=t.in_scope, created_at=t.created_at,
        ) for t in run.targets],
        findings_count=0,
        agents_count=0,
    )


@router.get("/{run_id}", response_model=RunDetailResponse)
async def get_run(run_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Run)
        .options(selectinload(Run.targets), selectinload(Run.findings))
        .where(Run.id == run_id)
    )
    run = result.scalar_one_or_none()
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")

    findings_count = len(run.findings) if run.findings else 0
    return RunDetailResponse(
        id=run.id,
        name=run.name,
        status=run.status.value,
        config=run.config,
        owner_id=run.owner_id,
        created_at=run.created_at,
        updated_at=run.updated_at,
        targets=[TargetResponse(
            id=t.id, run_id=t.run_id, target_type=t.target_type.value,
            value=t.value, in_scope=t.in_scope, created_at=t.created_at,
        ) for t in run.targets],
        findings_count=findings_count,
        agents_count=0,
    )


@router.patch("/{run_id}", response_model=RunResponse)
async def update_run(run_id: uuid.UUID, body: RunUpdate, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Run).where(Run.id == run_id))
    run = result.scalar_one_or_none()
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")

    if body.name is not None:
        run.name = body.name
    if body.status is not None:
        run.status = RunStatus(body.status)
    if body.config is not None:
        run.config = body.config

    await db.flush()
    await db.refresh(run)
    return run


@router.delete("/{run_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_run(run_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Run).where(Run.id == run_id))
    run = result.scalar_one_or_none()
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    await db.delete(run)


@router.post("/{run_id}/start", response_model=RunResponse)
async def start_run(run_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Run).where(Run.id == run_id))
    run = result.scalar_one_or_none()
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    run.status = RunStatus.running
    await db.flush()
    await db.refresh(run)

    try:
        from backend.app.tasks.celery_app import celery_app
        celery_app.send_task("lucifer.start_run", args=[str(run.id)])
    except Exception:
        pass

    return run


@router.post("/{run_id}/pause", response_model=RunResponse)
async def pause_run(run_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Run).where(Run.id == run_id))
    run = result.scalar_one_or_none()
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    run.status = RunStatus.paused
    await db.flush()
    await db.refresh(run)
    return run


@router.post("/{run_id}/cancel", response_model=RunResponse)
async def cancel_run(run_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Run).where(Run.id == run_id))
    run = result.scalar_one_or_none()
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    if run.status not in (RunStatus.running, RunStatus.pending, RunStatus.paused):
        raise HTTPException(
            status_code=400,
            detail=f"Cannot cancel run in '{run.status.value}' state",
        )
    run.status = RunStatus.cancelled
    await db.flush()
    await db.refresh(run)

    # Attempt to revoke the Celery task
    try:
        from backend.app.tasks.celery_app import celery_app
        celery_app.control.revoke(str(run.id), terminate=True)
    except Exception:
        pass  # Best-effort revocation

    return run


@router.post("/{run_id}/approve", response_model=dict)
async def approve_action(run_id: uuid.UUID, body: dict, db: AsyncSession = Depends(get_db)):
    """Approve or reject a pending approval for a run."""
    from backend.app.models import ApprovalEvent, ApprovalStatus
    from datetime import datetime, timezone

    result = await db.execute(
        select(ApprovalEvent)
        .where(ApprovalEvent.run_id == run_id, ApprovalEvent.status == ApprovalStatus.pending)
        .order_by(ApprovalEvent.created_at.asc())
        .limit(1)
    )
    approval = result.scalar_one_or_none()
    if not approval:
        raise HTTPException(status_code=404, detail="No pending approval found")

    decision = body.get("status", "approved")
    approval.status = ApprovalStatus(decision)
    approval.reviewer = body.get("reviewer", "operator")
    approval.reviewed_at = datetime.now(timezone.utc)
    await db.flush()

    return {"status": "ok", "approval_id": str(approval.id), "decision": decision}
