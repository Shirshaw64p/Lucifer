"""
tools/mitm_recorder.py — MITMRecorder: mitmproxy-based traffic interception and recording.

Uses mitmproxy's Python API in inline-script mode.
All intercepted traffic is automatically logged to the evidence store.
"""
from __future__ import annotations

import asyncio
import json
import logging
import uuid
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from core.models import ArtifactType, EvidenceRef, Flow, HAREntry, HARFile
from tools.evidence_store import EvidenceStore

logger = logging.getLogger(__name__)


class MITMRecorder:
    """
    mitmproxy Python API wrapper.

    * ``start(port)``  — launch mitmproxy on the given port
    * ``stop()``       — shut down the proxy
    * ``get_flows()``  — retrieve intercepted flows
    * ``export_har()`` — export a session as HAR
    * All traffic logged to evidence store automatically
    """

    def __init__(
        self,
        evidence_store: Optional[EvidenceStore] = None,
        listen_host: str = "127.0.0.1",
    ) -> None:
        self._store = evidence_store or EvidenceStore()
        self._listen_host = listen_host
        self._master: Any = None
        self._flows: Dict[str, List[Flow]] = {}    # session_id → flows
        self._running = False
        self._proxy_task: Optional[asyncio.Task[None]] = None
        self._current_session: Optional[str] = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def start(self, port: int = 8080) -> str:
        """
        Start the mitmproxy instance and return a ``session_id``.
        """
        session_id = str(uuid.uuid4())
        self._current_session = session_id
        self._flows[session_id] = []

        try:
            from mitmproxy.options import Options  # type: ignore[import-untyped]
            from mitmproxy.tools.dump import DumpMaster  # type: ignore[import-untyped]

            opts = Options(
                listen_host=self._listen_host,
                listen_port=port,
                ssl_insecure=True,
            )
            self._master = DumpMaster(opts)

            # Register addon to capture flows
            self._master.addons.add(_FlowCapture(self, session_id))
            self._running = True

            self._proxy_task = asyncio.create_task(self._run_master())
            logger.info("mitm.started", extra={"port": port, "session_id": session_id})

        except ImportError:
            logger.warning(
                "mitmproxy not installed — running in stub mode (flows must be "
                "added manually via record_flow)"
            )
            self._running = True

        return session_id

    async def _run_master(self) -> None:
        """Run the mitmproxy master in the event loop."""
        if self._master is None:
            return
        try:
            await asyncio.to_thread(self._master.run)
        except Exception:
            logger.debug("mitm.master_stopped")

    async def stop(self) -> None:
        """Shut down the proxy."""
        self._running = False
        if self._master is not None:
            self._master.shutdown()
            self._master = None
        if self._proxy_task is not None:
            self._proxy_task.cancel()
            try:
                await self._proxy_task
            except (asyncio.CancelledError, Exception):
                pass
            self._proxy_task = None
        logger.info("mitm.stopped")

    def get_flows(
        self,
        session_id: str,
        url_filter: Optional[str] = None,
    ) -> List[Flow]:
        """Return intercepted flows, optionally filtered by URL substring."""
        flows = self._flows.get(session_id, [])
        if url_filter:
            flows = [f for f in flows if url_filter in f.url]
        return flows

    def export_har(self, session_id: str) -> HARFile:
        """Export all flows for *session_id* as a HAR file and store it."""
        flows = self._flows.get(session_id, [])
        entries = [
            HAREntry(
                method=f.method,
                url=f.url,
                request_headers=f.request_headers,
                request_body=f.request_body,
                response_status=f.response_status,
                response_headers=f.response_headers,
                response_body=f.response_body,
                started_utc=f.timestamp_utc,
            )
            for f in flows
        ]
        har = HARFile(session_id=session_id, entries=entries)

        # Persist to evidence store
        har_json = json.dumps(asdict(har), indent=2, default=str).encode()
        self._store.save(
            ArtifactType.HAR,
            har_json,
            {"session_id": session_id, "flow_count": len(entries)},
        )

        return har

    def record_flow(self, session_id: str, flow: Flow) -> None:
        """Manually record a flow (used by the addon and for stub mode)."""
        if session_id not in self._flows:
            self._flows[session_id] = []
        self._flows[session_id].append(flow)

        # Auto-persist individual flow
        flow_json = json.dumps(asdict(flow), indent=2, default=str).encode()
        self._store.save(
            ArtifactType.FLOW,
            flow_json,
            {"session_id": session_id, "url": flow.url},
        )

    @property
    def is_running(self) -> bool:
        return self._running


class _FlowCapture:
    """mitmproxy addon that captures every flow into the recorder."""

    def __init__(self, recorder: MITMRecorder, session_id: str) -> None:
        self._recorder = recorder
        self._session_id = session_id

    def response(self, flow: Any) -> None:  # mitmproxy flow object
        try:
            f = Flow(
                flow_id=str(uuid.uuid4()),
                method=flow.request.method,
                url=flow.request.pretty_url,
                request_headers=dict(flow.request.headers),
                request_body=flow.request.get_text() if flow.request.content else None,
                response_status=flow.response.status_code,
                response_headers=dict(flow.response.headers),
                response_body=flow.response.get_text() if flow.response.content else None,
                timestamp_utc=datetime.now(timezone.utc).isoformat(),
            )
            self._recorder.record_flow(self._session_id, f)
        except Exception as exc:
            logger.error("mitm.capture_error", extra={"error": str(exc)})
