"""API v1 aggregate router — mounts all resource routers under /api/v1."""

from __future__ import annotations

from fastapi import APIRouter

from backend.app.api.v1 import (
    auth,
    runs,
    targets,
    findings,
    evidence,
    approvals,
    agents,
    kb,
)

api_v1_router = APIRouter()

api_v1_router.include_router(auth.router, prefix="/auth", tags=["auth"])
api_v1_router.include_router(runs.router, prefix="/runs", tags=["runs"])
api_v1_router.include_router(targets.router, tags=["targets"])
api_v1_router.include_router(findings.router, tags=["findings"])
api_v1_router.include_router(evidence.router, tags=["evidence"])
api_v1_router.include_router(approvals.router, prefix="/approvals", tags=["approvals"])
api_v1_router.include_router(agents.router, prefix="/agents", tags=["agents"])
api_v1_router.include_router(kb.router, prefix="/kb", tags=["knowledge-base"])
