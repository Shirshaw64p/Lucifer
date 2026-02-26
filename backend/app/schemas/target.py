"""Pydantic schemas for Target CRUD operations."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from backend.app.models.target import TargetType


class TargetCreate(BaseModel):
    """Schema for adding a target to a run."""
    target_type: TargetType
    value: str = Field(..., min_length=1, max_length=2048)
    in_scope: bool = True
    metadata_: dict[str, Any] | None = Field(None, alias="metadata")


class TargetRead(BaseModel):
    """Schema for reading a Target."""
    id: uuid.UUID
    run_id: uuid.UUID
    target_type: TargetType
    value: str
    in_scope: bool
    metadata_: dict[str, Any] | None = Field(None, alias="metadata")
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True, "populate_by_name": True}
