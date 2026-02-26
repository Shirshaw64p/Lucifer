"""Findings CRUD routes."""

from __future__ import annotations

import uuid
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from backend.app.core.database import get_db
from backend.app.models import Finding, Severity
from backend.app.schemas.schemas import (
    FindingCreate,
    FindingUpdate,
    FindingResponse,
    FindingDetailResponse,
)

router = APIRouter()


@router.get("/runs/{run_id}/findings", response_model=List[FindingResponse])
async def list_findings(
    run_id: uuid.UUID,
    severity: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
):
    q = select(Finding).where(Finding.run_id == run_id)
    if severity:
        q = q.where(Finding.severity == Severity(severity))
    q = q.order_by(Finding.created_at.desc())
    result = await db.execute(q)
    return result.scalars().all()


@router.post("/runs/{run_id}/findings", response_model=FindingResponse, status_code=status.HTTP_201_CREATED)
async def create_finding(
    run_id: uuid.UUID, body: FindingCreate, db: AsyncSession = Depends(get_db)
):
    finding = Finding(
        run_id=run_id,
        target_id=body.target_id,
        title=body.title,
        severity=Severity(body.severity),
        cvss_score=body.cvss_score,
        description=body.description,
        remediation=body.remediation,
        raw_output=body.raw_output,
        agent_id=body.agent_id,
    )
    db.add(finding)
    await db.flush()
    await db.refresh(finding)
    return finding


@router.get("/findings/{finding_id}", response_model=FindingDetailResponse)
async def get_finding(finding_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Finding)
        .options(selectinload(Finding.evidence_artifacts))
        .where(Finding.id == finding_id)
    )
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


@router.patch("/findings/{finding_id}", response_model=FindingResponse)
async def update_finding(
    finding_id: uuid.UUID, body: FindingUpdate, db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    if body.title is not None:
        finding.title = body.title
    if body.severity is not None:
        finding.severity = Severity(body.severity)
    if body.cvss_score is not None:
        finding.cvss_score = body.cvss_score
    if body.description is not None:
        finding.description = body.description
    if body.remediation is not None:
        finding.remediation = body.remediation

    await db.flush()
    await db.refresh(finding)
    return finding
