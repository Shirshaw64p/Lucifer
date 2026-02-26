"""Pydantic schemas for Finding CRUD operations."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, Field

from backend.app.models.finding import Severity


class FindingCreate(BaseModel):
    """Schema for creating a Finding."""
    title: str = Field(..., min_length=1, max_length=512)
    severity: Severity
    cvss_score: float | None = Field(None, ge=0.0, le=10.0)
    description: str
    remediation: str | None = None
    raw_output: str | None = None
    target_id: uuid.UUID | None = None
    agent_id: uuid.UUID | None = None


class FindingUpdate(BaseModel):
    """Schema for updating a Finding (all fields optional)."""
    title: str | None = Field(None, min_length=1, max_length=512)
    severity: Severity | None = None
    cvss_score: float | None = Field(None, ge=0.0, le=10.0)
    description: str | None = None
    remediation: str | None = None


class FindingRead(BaseModel):
    """Schema for reading a Finding."""
    id: uuid.UUID
    run_id: uuid.UUID
    target_id: uuid.UUID | None
    title: str
    severity: Severity
    cvss_score: float | None
    description: str
    remediation: str | None
    raw_output: str | None
    agent_id: uuid.UUID | None
    created_at: datetime

    model_config = {"from_attributes": True}
