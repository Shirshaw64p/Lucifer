"""Pydantic schemas for Run CRUD operations."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from backend.app.models.run import RunStatus


class RunCreate(BaseModel):
    """Schema for creating a new Run."""
    name: str = Field(..., min_length=1, max_length=255)
    config: dict[str, Any] | None = None
    owner_id: uuid.UUID | None = None


class RunUpdate(BaseModel):
    """Schema for updating a Run (all fields optional)."""
    name: str | None = Field(None, min_length=1, max_length=255)
    status: RunStatus | None = None
    config: dict[str, Any] | None = None


class RunRead(BaseModel):
    """Schema for reading a Run."""
    id: uuid.UUID
    name: str
    status: RunStatus
    config: dict[str, Any] | None
    owner_id: uuid.UUID | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}
