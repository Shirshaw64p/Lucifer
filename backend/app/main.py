"""FastAPI application factory and ASGI entry-point for Lucifer.

Creates the FastAPI app with:
- CORS middleware (origins from settings)
- Global exception / error middleware
- structlog JSON logging
- All API v1 routers mounted under /api/v1
"""

from __future__ import annotations

import time
import uuid

import structlog
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from backend.app.core.config import get_settings
from backend.app.core.logging import setup_logging

settings = get_settings()
logger = structlog.stdlib.get_logger(__name__)


def create_app() -> FastAPI:
    """Application factory — returns a fully configured FastAPI instance."""

    setup_logging()

    app = FastAPI(
        title=settings.app_name,
        version="0.1.0",
        description="Autonomous AI Red-Team Platform",
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # ── CORS middleware ──────────────────────────────────────────────────
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ── Request logging / error middleware ────────────────────────────────
    @app.middleware("http")
    async def request_middleware(request: Request, call_next):
        """Log every request, catch unhandled errors, add request-id."""
        request_id = str(uuid.uuid4())
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(request_id=request_id)

        start = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception as exc:
            logger.exception("unhandled_error", path=request.url.path, error=str(exc))
            return JSONResponse(
                status_code=500,
                content={"detail": "Internal server error", "request_id": request_id},
            )
        elapsed = round(time.perf_counter() - start, 4)

        logger.info(
            "request_completed",
            method=request.method,
            path=request.url.path,
            status=response.status_code,
            elapsed_s=elapsed,
        )
        response.headers["X-Request-ID"] = request_id
        return response

    # ── Global exception handler ─────────────────────────────────────────
    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception):
        logger.exception("unhandled_exception", path=request.url.path, error=str(exc))
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error"},
        )

    # ── Health check ─────────────────────────────────────────────────────
    @app.get("/health", tags=["system"])
    async def healthcheck():
        return {"status": "ok", "service": settings.app_name}

    # ── Mount API v1 routers ─────────────────────────────────────────────
    from backend.app.api.v1.router import api_v1_router
    app.include_router(api_v1_router, prefix="/api/v1")

    # ── WebSocket routes ─────────────────────────────────────────────────
    from fastapi import WebSocket, WebSocketDisconnect
    from backend.websocket_manager import ws_manager

    @app.websocket("/ws/runs/{run_id}/journal")
    async def ws_journal(websocket: WebSocket, run_id: str):
        await ws_manager.connect(websocket, run_id, "journal")
        try:
            while True:
                await websocket.receive_text()
        except WebSocketDisconnect:
            ws_manager.disconnect(websocket, run_id, "journal")

    @app.websocket("/ws/runs/{run_id}/findings")
    async def ws_findings(websocket: WebSocket, run_id: str):
        await ws_manager.connect(websocket, run_id, "findings")
        try:
            while True:
                await websocket.receive_text()
        except WebSocketDisconnect:
            ws_manager.disconnect(websocket, run_id, "findings")

    @app.websocket("/ws/runs/{run_id}/approvals")
    async def ws_approvals(websocket: WebSocket, run_id: str):
        await ws_manager.connect(websocket, run_id, "approvals")
        try:
            while True:
                await websocket.receive_text()
        except WebSocketDisconnect:
            ws_manager.disconnect(websocket, run_id, "approvals")

    @app.websocket("/ws/runs/{run_id}/agent-status")
    async def ws_agent_status(websocket: WebSocket, run_id: str):
        await ws_manager.connect(websocket, run_id, "agent-status")
        try:
            while True:
                await websocket.receive_text()
        except WebSocketDisconnect:
            ws_manager.disconnect(websocket, run_id, "agent-status")

    # ── Reports endpoint ─────────────────────────────────────────────────
    @app.get("/api/v1/reports/{run_id}")
    async def get_report(run_id: str):
        """Generate and return a PDF report for the run."""
        from fastapi.responses import JSONResponse
        return JSONResponse(content={
            "run_id": run_id,
            "message": "Report generation placeholder — PDF would be streamed here",
        })

    return app


# ASGI entry-point used by `uvicorn backend.app.main:app`
app = create_app()
