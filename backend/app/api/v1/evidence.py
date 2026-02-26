"""Evidence artifact routes — upload and download."""

from __future__ import annotations

import uuid
from typing import List

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, status
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.database import get_db
from backend.app.models import EvidenceArtifact, ArtifactType
from backend.app.schemas.schemas import EvidenceResponse

router = APIRouter()


@router.post(
    "/findings/{finding_id}/evidence",
    response_model=EvidenceResponse,
    status_code=status.HTTP_201_CREATED,
)
async def upload_evidence(
    finding_id: uuid.UUID,
    file: UploadFile = File(...),
    artifact_type: str = "other",
    db: AsyncSession = Depends(get_db),
):
    content = await file.read()
    storage_path = f"evidence/{finding_id}/{file.filename}"

    artifact = EvidenceArtifact(
        finding_id=finding_id,
        artifact_type=ArtifactType(artifact_type),
        storage_path=storage_path,
        mime_type=file.content_type or "application/octet-stream",
        size_bytes=len(content),
    )
    db.add(artifact)
    await db.flush()
    await db.refresh(artifact)
    return artifact


@router.get("/findings/{finding_id}/evidence", response_model=List[EvidenceResponse])
async def list_evidence(finding_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(EvidenceArtifact)
        .where(EvidenceArtifact.finding_id == finding_id)
        .order_by(EvidenceArtifact.created_at.desc())
    )
    return result.scalars().all()


@router.get("/evidence/{evidence_id}/download")
async def download_evidence(evidence_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(EvidenceArtifact).where(EvidenceArtifact.id == evidence_id)
    )
    artifact = result.scalar_one_or_none()
    if not artifact:
        raise HTTPException(status_code=404, detail="Evidence not found")
    # In production, stream from MinIO. For now return metadata.
    return {"storage_path": artifact.storage_path, "mime_type": artifact.mime_type}
