"""Finding Deduplicator — merges duplicate findings before reporting.

Groups findings by:
1. Same ``vuln_category``
2. Same endpoint URL (normalised)
3. Semantic similarity > 0.92 (based on title + description text)

When duplicates are found the deduplicator:
- Keeps the highest-severity instance as the canonical finding
- Merges all evidence references from duplicates
- Records all discovering agent IDs
- Logs deduplication decisions

Usage::

    dedup = FindingDeduplicator()
    unique_findings = dedup.deduplicate(findings)
"""

from __future__ import annotations

import hashlib
import logging
import re
from collections import defaultdict
from difflib import SequenceMatcher
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from reports.models import EvidenceRef, FindingRecord, Severity

logger = logging.getLogger(__name__)

# Severity rank — higher is more severe
_SEV_RANK: Dict[Severity, int] = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
}

# Minimum SequenceMatcher ratio to consider two findings semantically similar
_SIMILARITY_THRESHOLD = 0.92


class FindingDeduplicator:
    """Deduplicate a list of :class:`FindingRecord` objects.

    The algorithm is conservative — two findings are only considered
    duplicates if **all three** criteria match:

    1. Same ``vuln_category``
    2. Same normalised endpoint URL
    3. Semantic similarity of (title + description) ≥ 0.92
    """

    def __init__(self, similarity_threshold: float = _SIMILARITY_THRESHOLD):
        self.threshold = similarity_threshold

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def deduplicate(self, findings: List[FindingRecord]) -> List[FindingRecord]:
        """Return a deduplicated list of findings.

        Duplicate groups are merged; the canonical finding retains the
        highest severity, combined evidence, and notes all discovering
        agents.
        """
        if len(findings) <= 1:
            return list(findings)

        # Step 1: Group by (category, normalised URL)
        groups: Dict[str, List[FindingRecord]] = defaultdict(list)
        for f in findings:
            key = self._group_key(f)
            groups[key].append(f)

        result: List[FindingRecord] = []

        for key, group in groups.items():
            if len(group) == 1:
                result.append(group[0])
                continue

            # Step 2: Within each group, cluster by semantic similarity
            clusters = self._cluster_by_similarity(group)
            for cluster in clusters:
                if len(cluster) == 1:
                    result.append(cluster[0])
                else:
                    merged = self._merge_cluster(cluster)
                    result.append(merged)

        logger.info(
            "Deduplication: %d → %d findings (%d removed)",
            len(findings), len(result), len(findings) - len(result),
        )
        return result

    # ------------------------------------------------------------------
    # Grouping
    # ------------------------------------------------------------------

    @staticmethod
    def _group_key(finding: FindingRecord) -> str:
        """Compute a grouping key from category + normalised URL."""
        category = (finding.vuln_category or "UNKNOWN").upper().strip()
        url = FindingDeduplicator._normalise_url(finding.endpoint_url)
        return f"{category}||{url}"

    @staticmethod
    def _normalise_url(url: Optional[str]) -> str:
        """Normalise a URL for comparison.

        - Strip scheme, default ports, trailing slashes
        - Lowercase the host
        - Sort query parameters
        """
        if not url:
            return ""
        url = url.strip()
        try:
            parsed = urlparse(url)
            host = (parsed.hostname or "").lower()
            port = parsed.port
            # Drop default ports
            if port in (80, 443, None):
                port_str = ""
            else:
                port_str = f":{port}"
            path = (parsed.path or "/").rstrip("/") or "/"
            # Sort query params
            query = parsed.query
            if query:
                params = sorted(query.split("&"))
                query = "&".join(params)
            return f"{host}{port_str}{path}{'?' + query if query else ''}"
        except Exception:
            return url.lower().strip("/")

    # ------------------------------------------------------------------
    # Semantic similarity clustering
    # ------------------------------------------------------------------

    def _cluster_by_similarity(
        self, group: List[FindingRecord]
    ) -> List[List[FindingRecord]]:
        """Within a group, cluster findings whose (title+desc) similarity
        exceeds the threshold.  Uses greedy single-linkage clustering.
        """
        n = len(group)
        assigned = [False] * n
        clusters: List[List[FindingRecord]] = []

        for i in range(n):
            if assigned[i]:
                continue
            cluster = [group[i]]
            assigned[i] = True
            for j in range(i + 1, n):
                if assigned[j]:
                    continue
                sim = self._text_similarity(group[i], group[j])
                if sim >= self.threshold:
                    cluster.append(group[j])
                    assigned[j] = True
            clusters.append(cluster)

        return clusters

    @staticmethod
    def _text_similarity(a: FindingRecord, b: FindingRecord) -> float:
        """Compute similarity ratio between two findings' text content."""
        text_a = f"{a.title} {a.description}".lower().strip()
        text_b = f"{b.title} {b.description}".lower().strip()
        return SequenceMatcher(None, text_a, text_b).ratio()

    # ------------------------------------------------------------------
    # Merging
    # ------------------------------------------------------------------

    def _merge_cluster(self, cluster: List[FindingRecord]) -> FindingRecord:
        """Merge a cluster of duplicate findings into one canonical record."""
        # Pick the highest severity as canonical
        cluster.sort(key=lambda f: _SEV_RANK.get(f.severity, 0), reverse=True)
        canonical = cluster[0].model_copy(deep=True)

        # Combine evidence from all duplicates
        seen_evidence: Set[str] = set()
        merged_evidence: List[EvidenceRef] = []
        for f in cluster:
            for ev in f.evidence:
                ev_key = f"{ev.artifact_id}:{ev.storage_path}"
                if ev_key not in seen_evidence:
                    seen_evidence.add(ev_key)
                    merged_evidence.append(ev)
        canonical.evidence = merged_evidence

        # Record all discovering agents in description
        agent_names = set()
        for f in cluster:
            if f.agent_name:
                agent_names.add(f.agent_name)
            elif f.agent_id:
                agent_names.add(str(f.agent_id))

        if agent_names:
            canonical.description += (
                f"\n\n_Discovered by agents: {', '.join(sorted(agent_names))}_"
            )

        # Log the deduplication decision
        dup_ids = [str(f.id) for f in cluster[1:]]
        logger.info(
            "Merged %d duplicates into finding %s (severity=%s). "
            "Removed IDs: %s",
            len(cluster) - 1, canonical.id, canonical.severity.value,
            ", ".join(dup_ids),
        )

        return canonical
