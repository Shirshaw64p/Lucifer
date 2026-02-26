"""Pydantic schemas for Agent CRUD operations."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class AgentCreate(BaseModel):
    """Schema for registering a new Agent."""
    name: str = Field(..., min_length=1, max_length=255)
    agent_type: str = Field(..., min_length=1, max_length=64)
    description: str | None = None
    enabled: bool = True
    config: dict[str, Any] | None = None


class AgentUpdate(BaseModel):
    """Schema for updating an Agent."""
    name: str | None = Field(None, min_length=1, max_length=255)
    agent_type: str | None = Field(None, min_length=1, max_length=64)
    description: str | None = None
    enabled: bool | None = None
    config: dict[str, Any] | None = None


class AgentRead(BaseModel):
    """Schema for reading an Agent."""
    id: uuid.UUID
    name: str
    agent_type: str
    description: str | None
    enabled: bool
    config: dict[str, Any] | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}
