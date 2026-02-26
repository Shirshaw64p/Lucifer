"""
tools/replay_harness.py — ReplayHarness: deterministic HTTP replay from HAR evidence.

Loads a previously stored HAR entry, replays it with identical headers / body /
cookies / auth, and compares original vs replayed responses.
"""
from __future__ import annotations

import difflib
import json
import logging
from dataclasses import asdict
from typing import Any, Dict, Optional

from core.models import (
    ArtifactType,
    EvidenceRef,
    HAREntry,
    HttpEvidence,
    ReplayComparison,
)
from tools.evidence_store import EvidenceStore

logger = logging.getLogger(__name__)


class ReplayHarness:
    """
    Deterministic HTTP request replayer.

    * ``load_har()``  → deserialise a stored HAR entry
    * ``replay()``    → re-send the exact request
    * ``compare()``   → diff original vs replayed response
    """

    def __init__(
        self,
        evidence_store: Optional[EvidenceStore] = None,
    ) -> None:
        self._store = evidence_store or EvidenceStore()

    # ------------------------------------------------------------------
    # Load
    # ------------------------------------------------------------------

    def load_har(self, evidence_ref_id: str) -> HAREntry:
        """Retrieve and deserialise a HAR entry from the evidence store."""
        artifact = self._store.get(evidence_ref_id=evidence_ref_id)
        data = json.loads(artifact.content.decode())

        return HAREntry(
            method=data["method"],
            url=data["url"],
            request_headers=data.get("request_headers", {}),
            request_body=data.get("request_body"),
            response_status=data.get("response_status", 0),
            response_headers=data.get("response_headers", {}),
            response_body=data.get("response_body"),
            cookies=data.get("cookies", []),
            redirect_chain=data.get("redirect_chain", []),
            timings=data.get("timings", {}),
            started_utc=data.get("started_utc", ""),
        )

    # ------------------------------------------------------------------
    # Replay
    # ------------------------------------------------------------------

    async def replay(
        self,
        har_entry: HAREntry,
        session: Optional[Any] = None,
    ) -> HttpEvidence:
        """
        Replay the exact request from *har_entry*.

        Uses the provided httpx session or creates a fresh one.
        Deterministic: same method, headers, body, cookies.
        """
        import httpx

        if session is None:
            cookies_dict = {c["name"]: c["value"] for c in har_entry.cookies if "name" in c}
            session = httpx.AsyncClient(
                cookies=cookies_dict,
                timeout=httpx.Timeout(30),
                follow_redirects=False,
            )
            should_close = True
        else:
            should_close = False

        try:
            kwargs: Dict[str, Any] = {
                "headers": har_entry.request_headers,
            }
            if har_entry.request_body is not None:
                kwargs["content"] = har_entry.request_body

            resp = await session.request(
                har_entry.method,
                har_entry.url,
                **kwargs,
            )

            replayed = HAREntry(
                method=har_entry.method,
                url=str(resp.url),
                request_headers=dict(resp.request.headers),
                request_body=har_entry.request_body,
                response_status=resp.status_code,
                response_headers=dict(resp.headers),
                response_body=resp.text,
                cookies=har_entry.cookies,
                timings={"elapsed_ms": resp.elapsed.total_seconds() * 1000 if resp.elapsed else 0},
            )

            # Store replay evidence
            evidence_json = json.dumps(asdict(replayed), indent=2, default=str).encode()
            ref = self._store.save(
                ArtifactType.REPLAY,
                evidence_json,
                {"original_url": har_entry.url, "replayed": True},
            )

            return HttpEvidence(har_entry=replayed, evidence_ref=ref)
        finally:
            if should_close:
                await session.aclose()

    # ------------------------------------------------------------------
    # Compare
    # ------------------------------------------------------------------

    def compare(self, original: HAREntry, replayed: HAREntry) -> ReplayComparison:
        """Diff *original* vs *replayed* response."""

        status_match = original.response_status == replayed.response_status

        # Header diff
        orig_h = original.response_headers or {}
        repl_h = replayed.response_headers or {}
        all_keys = set(orig_h) | set(repl_h)
        header_diff: Dict[str, Any] = {}
        for k in all_keys:
            ov = orig_h.get(k)
            rv = repl_h.get(k)
            if ov != rv:
                header_diff[k] = {"original": ov, "replayed": rv}

        # Body similarity ratio
        orig_b = original.response_body or ""
        repl_b = replayed.response_body or ""
        ratio = difflib.SequenceMatcher(None, orig_b, repl_b).ratio()
        body_diff_ratio = round(1.0 - ratio, 4)

        # Timing diff
        orig_t = original.timings or {}
        repl_t = replayed.timings or {}
        timing_diff = {
            k: round(repl_t.get(k, 0) - orig_t.get(k, 0), 2)
            for k in set(orig_t) | set(repl_t)
        }

        deterministic = status_match and body_diff_ratio < 0.01 and not header_diff

        return ReplayComparison(
            status_match=status_match,
            header_diff=header_diff,
            body_diff_ratio=body_diff_ratio,
            timing_diff=timing_diff,
            deterministic=deterministic,
        )
