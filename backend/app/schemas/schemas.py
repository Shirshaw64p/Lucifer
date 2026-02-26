"""Pydantic request / response schemas for the Lucifer API."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# ════════════════════════════════════════════════════════════════════════════
# Auth
# ════════════════════════════════════════════════════════════════════════════

class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class RefreshRequest(BaseModel):
    refresh_token: str


class APIKeyCreate(BaseModel):
    name: str


class APIKeyResponse(BaseModel):
    id: uuid.UUID
    name: str
    key: str
    created_at: datetime


# ════════════════════════════════════════════════════════════════════════════
# Runs
# ════════════════════════════════════════════════════════════════════════════

class RunCreate(BaseModel):
    name: str = Field(..., max_length=255)
    config: Optional[Dict[str, Any]] = None
    targets: Optional[List["TargetCreate"]] = None


class RunUpdate(BaseModel):
    name: Optional[str] = None
    status: Optional[str] = None
    config: Optional[Dict[str, Any]] = None


class RunResponse(BaseModel):
    id: uuid.UUID
    name: str
    status: str
    config: Optional[Dict[str, Any]] = None
    owner_id: Optional[uuid.UUID] = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class RunDetailResponse(RunResponse):
    targets: List["TargetResponse"] = []
    findings_count: int = 0
    agents_count: int = 0


# ════════════════════════════════════════════════════════════════════════════
# Targets
# ════════════════════════════════════════════════════════════════════════════

class TargetCreate(BaseModel):
    target_type: str  # ip, cidr, domain, url
    value: str = Field(..., max_length=2048)
    in_scope: bool = True
    metadata_: Optional[Dict[str, Any]] = Field(None, alias="metadata")


class TargetResponse(BaseModel):
    id: uuid.UUID
    run_id: uuid.UUID
    target_type: str
    value: str
    in_scope: bool
    metadata_: Optional[Dict[str, Any]] = Field(None, alias="metadata")
    created_at: datetime

    model_config = {"from_attributes": True, "populate_by_name": True}


# ════════════════════════════════════════════════════════════════════════════
# Findings
# ════════════════════════════════════════════════════════════════════════════

class FindingCreate(BaseModel):
    title: str = Field(..., max_length=512)
    severity: str  # info, low, medium, high, critical
    cvss_score: Optional[float] = None
    description: str
    remediation: Optional[str] = None
    raw_output: Optional[str] = None
    target_id: Optional[uuid.UUID] = None
    agent_id: Optional[uuid.UUID] = None


class FindingUpdate(BaseModel):
    title: Optional[str] = None
    severity: Optional[str] = None
    cvss_score: Optional[float] = None
    description: Optional[str] = None
    remediation: Optional[str] = None
    status: Optional[str] = None


class FindingResponse(BaseModel):
    id: uuid.UUID
    run_id: uuid.UUID
    target_id: Optional[uuid.UUID] = None
    title: str
    severity: str
    cvss_score: Optional[float] = None
    description: str
    remediation: Optional[str] = None
    raw_output: Optional[str] = None
    agent_id: Optional[uuid.UUID] = None
    created_at: datetime

    model_config = {"from_attributes": True}


class FindingDetailResponse(FindingResponse):
    evidence_artifacts: List["EvidenceResponse"] = []
    agent_name: Optional[str] = None
    target_value: Optional[str] = None


# ════════════════════════════════════════════════════════════════════════════
# Evidence
# ════════════════════════════════════════════════════════════════════════════

class EvidenceResponse(BaseModel):
    id: uuid.UUID
    finding_id: uuid.UUID
    artifact_type: str
    storage_path: str
    mime_type: str
    size_bytes: int
    created_at: datetime

    model_config = {"from_attributes": True}


# ════════════════════════════════════════════════════════════════════════════
# Approvals
# ════════════════════════════════════════════════════════════════════════════

class ApprovalCreate(BaseModel):
    run_id: uuid.UUID
    agent_id: Optional[uuid.UUID] = None
    action_type: str = Field(..., max_length=128)
    action_detail: Optional[Dict[str, Any]] = None


class ApprovalDecision(BaseModel):
    status: str  # approved or denied
    reviewer: Optional[str] = None
    notes: Optional[str] = None


class ApprovalResponse(BaseModel):
    id: uuid.UUID
    run_id: uuid.UUID
    agent_id: Optional[uuid.UUID] = None
    action_type: str
    action_detail: Optional[Dict[str, Any]] = None
    status: str
    reviewer: Optional[str] = None
    reviewed_at: Optional[datetime] = None
    created_at: datetime

    model_config = {"from_attributes": True}


# ════════════════════════════════════════════════════════════════════════════
# Agents
# ════════════════════════════════════════════════════════════════════════════

class AgentCreate(BaseModel):
    name: str = Field(..., max_length=255)
    agent_type: str = Field(..., max_length=64)
    description: Optional[str] = None
    enabled: bool = True
    config: Optional[Dict[str, Any]] = None


class AgentUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    enabled: Optional[bool] = None
    config: Optional[Dict[str, Any]] = None


class AgentResponse(BaseModel):
    id: uuid.UUID
    name: str
    agent_type: str
    description: Optional[str] = None
    enabled: bool
    config: Optional[Dict[str, Any]] = None
    created_at: datetime

    model_config = {"from_attributes": True}


# ════════════════════════════════════════════════════════════════════════════
# Knowledge Base
# ════════════════════════════════════════════════════════════════════════════

class KBDocumentCreate(BaseModel):
    title: str = Field(..., max_length=512)
    doc_type: str  # cve, playbook, technique, reference
    content: str
    metadata_: Optional[Dict[str, Any]] = Field(None, alias="metadata")


class KBDocumentResponse(BaseModel):
    id: uuid.UUID
    title: str
    doc_type: str
    content: str
    embedding_id: Optional[str] = None
    metadata_: Optional[Dict[str, Any]] = Field(None, alias="metadata")
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True, "populate_by_name": True}


class KBSearchRequest(BaseModel):
    query: str
    limit: int = 3


class KBSearchResult(BaseModel):
    doc_id: uuid.UUID
    title: str
    chunk: str
    score: float


# ════════════════════════════════════════════════════════════════════════════
# Reports
# ════════════════════════════════════════════════════════════════════════════

class ReportResponse(BaseModel):
    run_id: uuid.UUID
    run_name: str
    status: str
    findings_count: int
    generated_at: Optional[datetime] = None


# ════════════════════════════════════════════════════════════════════════════
# WebSocket messages
# ════════════════════════════════════════════════════════════════════════════

class WSJournalEntry(BaseModel):
    run_id: uuid.UUID
    agent_name: str
    entry_type: str  # thought, action, observation, error
    content: str
    timestamp: datetime
    metadata_: Optional[Dict[str, Any]] = Field(None, alias="metadata")


class WSAgentStatus(BaseModel):
    run_id: uuid.UUID
    agent_id: uuid.UUID
    agent_name: str
    llm_model: str
    status: str  # idle, running, complete, error
    current_step: Optional[str] = None
    tokens_used: int = 0
    token_budget: int = 0


class WSFindingEvent(BaseModel):
    run_id: uuid.UUID
    finding_id: uuid.UUID
    title: str
    severity: str
    agent_name: Optional[str] = None
    timestamp: datetime


class WSApprovalRequest(BaseModel):
    run_id: uuid.UUID
    approval_id: uuid.UUID
    agent_name: Optional[str] = None
    action_type: str
    action_detail: Optional[Dict[str, Any]] = None
    risk_level: str = "high"
    timestamp: datetime


# Rebuild forward refs
RunCreate.model_rebuild()
RunDetailResponse.model_rebuild()
FindingDetailResponse.model_rebuild()
