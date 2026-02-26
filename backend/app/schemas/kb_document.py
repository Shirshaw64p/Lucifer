"""Pydantic schemas for KBDocument CRUD operations."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from backend.app.models.kb_document import DocType


class KBDocumentCreate(BaseModel):
    """Schema for creating a knowledge-base document."""
    title: str = Field(..., min_length=1, max_length=512)
    doc_type: DocType
    content: str
    embedding_id: str | None = None
    metadata_: dict[str, Any] | None = Field(None, alias="metadata")


class KBDocumentRead(BaseModel):
    """Schema for reading a KBDocument."""
    id: uuid.UUID
    title: str
    doc_type: DocType
    content: str
    embedding_id: str | None
    metadata_: dict[str, Any] | None = Field(None, alias="metadata")
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True, "populate_by_name": True}
