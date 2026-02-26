"""Knowledge Base CRUD + search routes."""

from __future__ import annotations

import uuid
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.database import get_db
from backend.app.models import KBDocument, DocType
from backend.app.schemas.schemas import (
    KBDocumentCreate,
    KBDocumentResponse,
    KBSearchRequest,
    KBSearchResult,
)

router = APIRouter()


@router.get("", response_model=List[KBDocumentResponse])
async def list_kb_documents(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(KBDocument).order_by(KBDocument.created_at.desc()))
    return result.scalars().all()


@router.post("", response_model=KBDocumentResponse, status_code=status.HTTP_201_CREATED)
async def create_kb_document(body: KBDocumentCreate, db: AsyncSession = Depends(get_db)):
    doc = KBDocument(
        title=body.title,
        doc_type=DocType(body.doc_type),
        content=body.content,
        metadata_=body.metadata_ or {},
    )
    db.add(doc)
    await db.flush()
    await db.refresh(doc)
    return doc


@router.get("/search", response_model=List[KBSearchResult])
async def search_kb(query: str, limit: int = 3, db: AsyncSession = Depends(get_db)):
    """Simple text search — in production, use ChromaDB vector search."""
    result = await db.execute(
        select(KBDocument)
        .where(KBDocument.content.ilike(f"%{query}%"))
        .limit(limit)
    )
    docs = result.scalars().all()
    return [
        KBSearchResult(
            doc_id=doc.id,
            title=doc.title,
            chunk=doc.content[:500],
            score=1.0,
        )
        for doc in docs
    ]


@router.get("/{doc_id}", response_model=KBDocumentResponse)
async def get_kb_document(doc_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(KBDocument).where(KBDocument.id == doc_id))
    doc = result.scalar_one_or_none()
    if not doc:
        raise HTTPException(status_code=404, detail="KB document not found")
    return doc


@router.delete("/{doc_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_kb_document(doc_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(KBDocument).where(KBDocument.id == doc_id))
    doc = result.scalar_one_or_none()
    if not doc:
        raise HTTPException(status_code=404, detail="KB document not found")
    await db.delete(doc)
