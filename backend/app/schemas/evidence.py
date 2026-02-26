"""Pydantic schemas for EvidenceArtifact operations."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, Field

from backend.app.models.evidence import ArtifactType


class EvidenceCreate(BaseModel):
    """Schema for uploading evidence (metadata portion)."""
    artifact_type: ArtifactType
    mime_type: str = Field(..., max_length=255)
    size_bytes: int = Field(..., ge=0)
    storage_path: str = Field(..., max_length=1024)


class EvidenceRead(BaseModel):
    """Schema for reading an EvidenceArtifact."""
    id: uuid.UUID
    finding_id: uuid.UUID
    artifact_type: ArtifactType
    storage_path: str
    mime_type: str
    size_bytes: int
    created_at: datetime

    model_config = {"from_attributes": True}
