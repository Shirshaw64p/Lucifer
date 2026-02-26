"""
core/models.py — Shared data models for the Lucifer platform.

All tool modules reference these canonical types so nothing is
duplicated across the codebase.
"""
from __future__ import annotations

import datetime as _dt
import enum
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Evidence Store
# ---------------------------------------------------------------------------

class ArtifactType(str, enum.Enum):
    HAR = "har"
    SCREENSHOT = "screenshot"
    FLOW = "flow"
    OAST_CALLBACK = "oast_callback"
    REPLAY = "replay"
    RAW = "raw"
    LOG = "log"
    REPORT = "report"


@dataclass(frozen=True)
class EvidenceRef:
    """Immutable pointer to an artefact in the evidence store."""
    evidence_id: str
    sha256: str
    artifact_type: ArtifactType
    stored_at: str                               # path or object key
    created_utc: str = field(
        default_factory=lambda: _dt.datetime.utcnow().isoformat()
    )
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Artifact:
    """Full artefact retrieved from the store."""
    ref: EvidenceRef
    content: bytes


# ---------------------------------------------------------------------------
# HTTP / HAR
# ---------------------------------------------------------------------------

@dataclass
class HAREntry:
    """Simplified HAR 1.2 entry."""
    method: str
    url: str
    request_headers: Dict[str, str]
    request_body: Optional[str]
    response_status: int
    response_headers: Dict[str, str]
    response_body: Optional[str]
    cookies: List[Dict[str, str]] = field(default_factory=list)
    redirect_chain: List[str] = field(default_factory=list)
    timings: Dict[str, float] = field(default_factory=dict)
    started_utc: str = field(
        default_factory=lambda: _dt.datetime.utcnow().isoformat()
    )


@dataclass
class HARFile:
    """Collection of HAR entries for a session."""
    session_id: str
    entries: List[HAREntry] = field(default_factory=list)


@dataclass
class HttpEvidence:
    """Result of an HTTP request with full evidence."""
    har_entry: HAREntry
    evidence_ref: Optional[EvidenceRef] = None


# ---------------------------------------------------------------------------
# Browser
# ---------------------------------------------------------------------------

@dataclass
class PageSnapshot:
    """Snapshot returned by the browser engine after navigation."""
    url: str
    title: str
    status: int
    dom_html: str
    cookies: List[Dict[str, str]] = field(default_factory=list)
    console_logs: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# MITM Proxy
# ---------------------------------------------------------------------------

@dataclass
class Flow:
    """Single intercepted flow from the MITM proxy."""
    flow_id: str
    method: str
    url: str
    request_headers: Dict[str, str]
    request_body: Optional[str]
    response_status: int
    response_headers: Dict[str, str]
    response_body: Optional[str]
    timestamp_utc: str = field(
        default_factory=lambda: _dt.datetime.utcnow().isoformat()
    )


# ---------------------------------------------------------------------------
# OAST / Out-of-band
# ---------------------------------------------------------------------------

@dataclass
class OASTCallback:
    """A single out-of-band callback received by Interactsh."""
    callback_id: str
    finding_id: str
    subdomain: str
    protocol: str                 # dns, http, smtp …
    remote_address: str
    raw_request: Optional[str]
    timestamp_utc: str = field(
        default_factory=lambda: _dt.datetime.utcnow().isoformat()
    )


# ---------------------------------------------------------------------------
# Replay
# ---------------------------------------------------------------------------

@dataclass
class ReplayComparison:
    """Diff between original and replayed response."""
    status_match: bool
    header_diff: Dict[str, Any]
    body_diff_ratio: float         # 0.0 = identical, 1.0 = totally different
    timing_diff: Dict[str, float]
    deterministic: bool


# ---------------------------------------------------------------------------
# KB / Memory
# ---------------------------------------------------------------------------

@dataclass
class ChunkResult:
    """Single chunk returned from a knowledge-base search."""
    doc_id: str
    chunk_id: str
    content: str
    relevance_score: float
    metadata: Dict[str, Any] = field(default_factory=dict)
