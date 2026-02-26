"""Targets CRUD routes — scoped under runs."""

from __future__ import annotations

import uuid
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.database import get_db
from backend.app.models import Target, TargetType
from backend.app.schemas.schemas import TargetCreate, TargetResponse

router = APIRouter()


@router.get("/runs/{run_id}/targets", response_model=List[TargetResponse])
async def list_targets(run_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Target).where(Target.run_id == run_id).order_by(Target.created_at.desc())
    )
    return result.scalars().all()


@router.post("/runs/{run_id}/targets", response_model=TargetResponse, status_code=status.HTTP_201_CREATED)
async def create_target(run_id: uuid.UUID, body: TargetCreate, db: AsyncSession = Depends(get_db)):
    target = Target(
        run_id=run_id,
        target_type=TargetType(body.target_type),
        value=body.value,
        in_scope=body.in_scope,
    )
    db.add(target)
    await db.flush()
    await db.refresh(target)
    return target


@router.delete("/runs/{run_id}/targets/{target_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_target(
    run_id: uuid.UUID, target_id: uuid.UUID, db: AsyncSession = Depends(get_db)
):
    result = await db.execute(
        select(Target).where(Target.id == target_id, Target.run_id == run_id)
    )
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    await db.delete(target)
