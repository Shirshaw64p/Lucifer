"""
tools/oast_client.py — OASTClient: out-of-band application security testing
via a self-hosted Interactsh server.

Generates unique subdomains per finding, polls for callbacks,
and stores all callback evidence.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import uuid
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx

from core.config import settings
from core.models import ArtifactType, EvidenceRef, OASTCallback
from tools.evidence_store import EvidenceStore

logger = logging.getLogger(__name__)


class OASTClient:
    """
    Interactsh client for out-of-band interaction detection.

    * ``get_payload()``       → unique subdomain URL for a finding
    * ``poll_callbacks()``    → retrieve new OOB interactions
    * ``confirm_finding()``   → persist callback as evidence
    """

    def __init__(
        self,
        evidence_store: Optional[EvidenceStore] = None,
        server_url: Optional[str] = None,
        auth_token: Optional[str] = None,
        poll_interval: int = 5,
    ) -> None:
        self._store = evidence_store or EvidenceStore()
        self._server_url = (server_url or settings.oast_server_url).rstrip("/")
        self._auth_token = auth_token or settings.oast_auth_token
        self._poll_interval = poll_interval

        # Registered payloads: correlation_id → {run_id, agent_id, finding_id, subdomain}
        self._payloads: Dict[str, Dict[str, str]] = {}
        # Collected callbacks keyed by run_id
        self._callbacks: Dict[str, List[OASTCallback]] = {}

        self._http: Optional[httpx.AsyncClient] = None
        self._session_id: Optional[str] = None
        self._secret_key: Optional[str] = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def _get_http(self) -> httpx.AsyncClient:
        if self._http is None or self._http.is_closed:
            hdrs: Dict[str, str] = {}
            if self._auth_token:
                hdrs["Authorization"] = f"Bearer {self._auth_token}"
            self._http = httpx.AsyncClient(
                base_url=self._server_url,
                headers=hdrs,
                timeout=httpx.Timeout(30),
            )
        return self._http

    async def register(self) -> str:
        """Register with the Interactsh server and obtain a session."""
        client = await self._get_http()
        try:
            resp = await client.post("/register")
            resp.raise_for_status()
            data = resp.json()
            self._session_id = data.get("session_id") or data.get("correlationID", "")
            self._secret_key = data.get("secretKey", "")
            logger.info("oast.registered", extra={"session_id": self._session_id})
            return self._session_id or ""
        except Exception as exc:
            logger.warning("oast.register_failed: %s — using local stub mode", exc)
            self._session_id = str(uuid.uuid4())
            return self._session_id

    async def close(self) -> None:
        if self._http and not self._http.is_closed:
            # Attempt deregister
            try:
                await self._http.post(
                    "/deregister", json={"correlationID": self._session_id}
                )
            except Exception:
                pass
            await self._http.aclose()
            self._http = None

    # ------------------------------------------------------------------
    # Payload generation
    # ------------------------------------------------------------------

    def get_payload(
        self,
        run_id: str,
        agent_id: str,
        finding_id: str,
    ) -> str:
        """
        Generate a unique OAST subdomain URL for this specific finding.

        The subdomain encodes a correlation ID so callbacks can be
        mapped back to the exact agent and finding.
        """
        correlation = hashlib.sha256(
            f"{run_id}:{agent_id}:{finding_id}".encode()
        ).hexdigest()[:16]

        base_domain = self._server_url.replace("https://", "").replace("http://", "")
        subdomain = f"{correlation}.{base_domain}"
        payload_url = f"http://{subdomain}"

        self._payloads[correlation] = {
            "run_id": run_id,
            "agent_id": agent_id,
            "finding_id": finding_id,
            "subdomain": subdomain,
        }

        logger.info(
            "oast.payload_generated",
            extra={"finding_id": finding_id, "subdomain": subdomain},
        )
        return payload_url

    # ------------------------------------------------------------------
    # Polling
    # ------------------------------------------------------------------

    async def poll_callbacks(self, run_id: str) -> List[OASTCallback]:
        """
        Poll the Interactsh server for new callbacks related to *run_id*.
        """
        client = await self._get_http()
        new_callbacks: List[OASTCallback] = []

        try:
            params: Dict[str, str] = {}
            if self._session_id:
                params["correlationID"] = self._session_id
            if self._secret_key:
                params["secret"] = self._secret_key

            resp = await client.get("/poll", params=params)
            resp.raise_for_status()
            data = resp.json()
            interactions = data.get("data", data.get("interactions", []))

            if not interactions:
                return new_callbacks

            for entry in interactions:
                correlation = self._extract_correlation(entry)
                payload_info = self._payloads.get(correlation, {})
                if payload_info.get("run_id") != run_id:
                    continue

                cb = OASTCallback(
                    callback_id=str(uuid.uuid4()),
                    finding_id=payload_info.get("finding_id", ""),
                    subdomain=payload_info.get("subdomain", ""),
                    protocol=entry.get("protocol", "unknown"),
                    remote_address=entry.get("remote-address", entry.get("remoteAddress", "")),
                    raw_request=entry.get("raw-request", entry.get("rawRequest", "")),
                    timestamp_utc=datetime.now(timezone.utc).isoformat(),
                )
                new_callbacks.append(cb)
                self._auto_store_callback(cb, run_id)

        except Exception as exc:
            logger.warning("oast.poll_error", extra={"error": str(exc)})

        if run_id not in self._callbacks:
            self._callbacks[run_id] = []
        self._callbacks[run_id].extend(new_callbacks)
        return new_callbacks

    def _extract_correlation(self, entry: Dict[str, Any]) -> str:
        """Extract the correlation portion from an Interactsh interaction."""
        fqdn = entry.get("full-id", entry.get("fullId", ""))
        return fqdn.split(".")[0] if fqdn else ""

    # ------------------------------------------------------------------
    # Confirmation
    # ------------------------------------------------------------------

    def confirm_finding(
        self,
        finding_id: str,
        callback: OASTCallback,
    ) -> EvidenceRef:
        """
        Persist a confirmed OAST callback as evidence.

        Returns an ``EvidenceRef`` with the full callback context.
        """
        content = json.dumps(asdict(callback), indent=2, default=str).encode()
        metadata = {
            "finding_id": finding_id,
            "protocol": callback.protocol,
            "subdomain": callback.subdomain,
            "remote_address": callback.remote_address,
        }
        ref = self._store.save(ArtifactType.OAST_CALLBACK, content, metadata)
        logger.info(
            "oast.finding_confirmed",
            extra={"finding_id": finding_id, "evidence_id": ref.evidence_id},
        )
        return ref

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _auto_store_callback(self, cb: OASTCallback, run_id: str) -> None:
        """Persist every received callback automatically."""
        content = json.dumps(asdict(cb), indent=2, default=str).encode()
        self._store.save(
            ArtifactType.OAST_CALLBACK,
            content,
            {"run_id": run_id, "finding_id": cb.finding_id, "auto": True},
        )

    def get_registered_payloads(self) -> Dict[str, Dict[str, str]]:
        """Return all registered payloads (for debugging)."""
        return dict(self._payloads)
