"""Approval routes — request, list, approve/deny."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.database import get_db
from backend.app.models import ApprovalEvent, ApprovalStatus
from backend.app.schemas.schemas import (
    ApprovalCreate,
    ApprovalDecision,
    ApprovalResponse,
)

router = APIRouter()


@router.get("", response_model=List[ApprovalResponse])
async def list_approvals(
    run_id: uuid.UUID | None = None,
    db: AsyncSession = Depends(get_db),
):
    q = select(ApprovalEvent).order_by(ApprovalEvent.created_at.desc())
    if run_id:
        q = q.where(ApprovalEvent.run_id == run_id)
    result = await db.execute(q)
    return result.scalars().all()


@router.post("", response_model=ApprovalResponse, status_code=status.HTTP_201_CREATED)
async def request_approval(body: ApprovalCreate, db: AsyncSession = Depends(get_db)):
    event = ApprovalEvent(
        run_id=body.run_id,
        agent_id=body.agent_id,
        action_type=body.action_type,
        action_detail=body.action_detail or {},
        status=ApprovalStatus.pending,
    )
    db.add(event)
    await db.flush()
    await db.refresh(event)
    return event


@router.patch("/{approval_id}", response_model=ApprovalResponse)
async def decide_approval(
    approval_id: uuid.UUID,
    body: ApprovalDecision,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(ApprovalEvent).where(ApprovalEvent.id == approval_id)
    )
    event = result.scalar_one_or_none()
    if not event:
        raise HTTPException(status_code=404, detail="Approval event not found")

    if event.status != ApprovalStatus.pending:
        raise HTTPException(status_code=400, detail="Approval already decided")

    event.status = ApprovalStatus(body.status)
    event.reviewer = body.reviewer or "operator"
    event.reviewed_at = datetime.now(timezone.utc)
    await db.flush()
    await db.refresh(event)
    return event
