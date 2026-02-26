"""WebSocket connection manager for live dashboard updates.

Manages 4 WebSocket channels per run:
  /ws/runs/{run_id}/journal       — live journal entries
  /ws/runs/{run_id}/findings      — new findings
  /ws/runs/{run_id}/approvals     — approval requests
  /ws/runs/{run_id}/agent-status  — agent status changes

All broadcast methods catch and silently discard errors from
disconnected clients — agent runs must never crash due to a
broken WebSocket.
"""

from __future__ import annotations

import json
from collections import defaultdict
from typing import Any, Dict, Set

import structlog
from fastapi import WebSocket

logger = structlog.stdlib.get_logger(__name__)


class ConnectionManager:
    """Manages WebSocket connections grouped by (run_id, channel)."""

    def __init__(self) -> None:
        # Key: (run_id, channel) → Set of WebSocket connections
        self._connections: Dict[str, Set[WebSocket]] = defaultdict(set)

    def _key(self, run_id: str, channel: str) -> str:
        return f"{run_id}:{channel}"

    async def connect(self, ws: WebSocket, run_id: str, channel: str) -> None:
        await ws.accept()
        key = self._key(run_id, channel)
        self._connections[key].add(ws)
        logger.info("ws.connected", run_id=run_id, channel=channel)

    def disconnect(self, ws: WebSocket, run_id: str, channel: str) -> None:
        key = self._key(run_id, channel)
        self._connections[key].discard(ws)
        logger.info("ws.disconnected", run_id=run_id, channel=channel)

    async def _broadcast(self, run_id: str, channel: str, data: dict) -> None:
        key = self._key(run_id, channel)
        dead: list[WebSocket] = []
        message = json.dumps(data, default=str)

        for ws in self._connections[key]:
            try:
                await ws.send_text(message)
            except Exception:
                dead.append(ws)

        for ws in dead:
            self._connections[key].discard(ws)

    # ── Typed broadcast helpers ──────────────────────────────────────────

    async def broadcast_journal(self, run_id: str, entry: dict) -> None:
        """Send a journal entry to all /ws/runs/{run_id}/journal subscribers."""
        await self._broadcast(run_id, "journal", {"type": "journal", "data": entry})

    async def broadcast_finding(self, run_id: str, finding: dict) -> None:
        """Send a finding to all /ws/runs/{run_id}/findings subscribers."""
        await self._broadcast(run_id, "findings", {"type": "finding", "data": finding})

    async def broadcast_approval(self, run_id: str, approval_request: dict) -> None:
        """Send an approval request to /ws/runs/{run_id}/approvals subscribers."""
        await self._broadcast(run_id, "approvals", {"type": "approval", "data": approval_request})

    async def broadcast_agent_status(self, run_id: str, agent_status: dict) -> None:
        """Send agent status to /ws/runs/{run_id}/agent-status subscribers."""
        await self._broadcast(run_id, "agent-status", {"type": "agent_status", "data": agent_status})


# Singleton instance used by the application
ws_manager = ConnectionManager()
