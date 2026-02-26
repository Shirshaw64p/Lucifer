"""Pydantic schemas for ApprovalEvent operations."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from backend.app.models.approval import ApprovalStatus


class ApprovalCreate(BaseModel):
    """Schema for requesting an approval."""
    run_id: uuid.UUID
    agent_id: uuid.UUID | None = None
    action_type: str = Field(..., min_length=1, max_length=128)
    action_detail: dict[str, Any] | None = None


class ApprovalUpdate(BaseModel):
    """Schema for approving or denying an action."""
    status: ApprovalStatus
    reviewer: str | None = Field(None, max_length=255)


class ApprovalRead(BaseModel):
    """Schema for reading an ApprovalEvent."""
    id: uuid.UUID
    run_id: uuid.UUID
    agent_id: uuid.UUID | None
    action_type: str
    action_detail: dict[str, Any] | None
    status: ApprovalStatus
    reviewer: str | None
    reviewed_at: datetime | None
    created_at: datetime

    model_config = {"from_attributes": True}
