"""
tools/http_engine.py — HttpEngine: async HTTP client with HAR capture,
cookie persistence, redirect tracking, rate limiting, and scope enforcement.

Every outbound request is validated through scope_guard before sending.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import httpx

from core.models import ArtifactType, EvidenceRef, HAREntry, HttpEvidence
from core.scope_guard import check_scope, ScopeViolation
from tools.evidence_store import EvidenceStore

logger = logging.getLogger(__name__)


class _RateLimiter:
    """Token-bucket rate limiter — configurable max RPS per target host."""

    def __init__(self, max_rps: int = 10) -> None:
        self._max_rps = max_rps
        self._tokens: Dict[str, float] = {}
        self._last: Dict[str, float] = {}
        self._lock = asyncio.Lock()

    async def acquire(self, host: str) -> None:
        async with self._lock:
            now = time.monotonic()
            last = self._last.get(host, 0.0)
            min_interval = 1.0 / self._max_rps
            wait = max(0.0, min_interval - (now - last))
            if wait > 0:
                await asyncio.sleep(wait)
            self._last[host] = time.monotonic()


class HttpEngine:
    """
    Async HTTP client built on HTTPX.

    * Full HAR capture for every request
    * Cookie jar persistence across a session
    * Redirect chain tracking
    * Configurable rate limiter per target host
    * scope_guard enforcement before every outbound request
    * ``save_evidence()`` stores HAR to the evidence store
    """

    def __init__(
        self,
        evidence_store: Optional[EvidenceStore] = None,
        max_rps: int = 10,
        timeout: float = 30.0,
        max_redirects: int = 10,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
    ) -> None:
        self._store = evidence_store or EvidenceStore()
        self._rate_limiter = _RateLimiter(max_rps)
        self._timeout = timeout
        self._max_redirects = max_redirects
        self._default_headers = headers or {}
        self._cookie_jar = httpx.Cookies()
        if cookies:
            for k, v in cookies.items():
                self._cookie_jar.set(k, v)
        self._client: Optional[httpx.AsyncClient] = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(self._timeout),
                follow_redirects=False,   # we track manually
                cookies=self._cookie_jar,
                headers=self._default_headers,
            )
        return self._client

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

    # ------------------------------------------------------------------
    # Core request
    # ------------------------------------------------------------------

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        body: Optional[str] = None,
        json_body: Optional[Any] = None,
        run_id: Optional[str] = None,
        finding_id: Optional[str] = None,
        follow_redirects: bool = True,
    ) -> HttpEvidence:
        """
        Send an HTTP request with full HAR capture.

        Raises ``ScopeViolation`` if the target is out of scope.
        """
        # ── Scope enforcement ──
        check_scope(url)

        client = await self._get_client()

        parsed = urlparse(url)
        host = parsed.hostname or ""
        await self._rate_limiter.acquire(host)

        started = datetime.now(timezone.utc)
        redirect_chain: List[str] = []

        current_url = url
        final_response: Optional[httpx.Response] = None

        for _ in range(self._max_redirects + 1):
            check_scope(current_url)
            await self._rate_limiter.acquire(urlparse(current_url).hostname or host)

            req_kwargs: Dict[str, Any] = {"headers": headers or {}}
            if body is not None:
                req_kwargs["content"] = body
            elif json_body is not None:
                req_kwargs["json"] = json_body

            resp = await client.request(method, current_url, **req_kwargs)
            final_response = resp

            # Sync cookies
            self._cookie_jar.update(resp.cookies)

            if follow_redirects and resp.is_redirect:
                redirect_chain.append(current_url)
                location = resp.headers.get("location", "")
                if location:
                    # Resolve relative redirects
                    current_url = str(resp.url.join(location))
                    method = "GET"  # POST→GET on 3xx
                    body = None
                    json_body = None
                    continue
            break

        assert final_response is not None
        resp = final_response

        har_entry = HAREntry(
            method=method,
            url=str(resp.url),
            request_headers=dict(resp.request.headers),
            request_body=body,
            response_status=resp.status_code,
            response_headers=dict(resp.headers),
            response_body=resp.text,
            cookies=[{"name": k, "value": v} for k, v in self._cookie_jar.items()],
            redirect_chain=redirect_chain,
            timings={"elapsed_ms": resp.elapsed.total_seconds() * 1000 if resp.elapsed else 0},
            started_utc=started.isoformat(),
        )

        evidence_ref = None
        if run_id or finding_id:
            evidence_ref = self.save_evidence(
                har_entry, run_id=run_id, finding_id=finding_id
            )

        return HttpEvidence(har_entry=har_entry, evidence_ref=evidence_ref)

    # ------------------------------------------------------------------
    # Convenience verbs
    # ------------------------------------------------------------------

    async def get(self, url: str, **kwargs: Any) -> HttpEvidence:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> HttpEvidence:
        return await self.request("POST", url, **kwargs)

    async def put(self, url: str, **kwargs: Any) -> HttpEvidence:
        return await self.request("PUT", url, **kwargs)

    async def delete(self, url: str, **kwargs: Any) -> HttpEvidence:
        return await self.request("DELETE", url, **kwargs)

    # ------------------------------------------------------------------
    # Evidence
    # ------------------------------------------------------------------

    def save_evidence(
        self,
        har_entry: HAREntry,
        run_id: Optional[str] = None,
        finding_id: Optional[str] = None,
    ) -> EvidenceRef:
        """Serialise a HAR entry and store it in the evidence store."""
        from dataclasses import asdict

        har_json = json.dumps(asdict(har_entry), indent=2, default=str).encode()
        metadata: Dict[str, Any] = {}
        if run_id:
            metadata["run_id"] = run_id
        if finding_id:
            metadata["finding_id"] = finding_id
        metadata["url"] = har_entry.url
        metadata["status"] = har_entry.response_status
        return self._store.save(ArtifactType.HAR, har_json, metadata)
