"""
tools/evidence_store.py — EvidenceStore: content-addressed, immutable artifact storage.

Backend: local filesystem in dev, MinIO in production.
Every artifact is keyed by its SHA-256 digest — duplicate writes are no-ops.
No update or delete operations are exposed.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from core.config import settings
from core.models import Artifact, ArtifactType, EvidenceRef

logger = logging.getLogger(__name__)


class EvidenceStore:
    """
    Content-addressed, append-only evidence store.

    * ``save()``  → persist artefact, return ``EvidenceRef``
    * ``get()``   → retrieve full ``Artifact``
    """

    def __init__(
        self,
        backend: Optional[str] = None,
        root: Optional[str] = None,
        minio_endpoint: Optional[str] = None,
        minio_access_key: Optional[str] = None,
        minio_secret_key: Optional[str] = None,
        minio_bucket: Optional[str] = None,
        minio_secure: bool = False,
    ) -> None:
        self._backend = backend or settings.evidence_backend
        self._root = Path(root or settings.evidence_root)
        self._minio_endpoint = minio_endpoint or settings.minio_endpoint
        self._minio_access_key = minio_access_key or settings.minio_access_key
        self._minio_secret_key = minio_secret_key or settings.minio_secret_key
        self._minio_bucket = minio_bucket or settings.minio_bucket
        self._minio_secure = minio_secure
        self._minio_client: Any = None

        if self._backend == "filesystem":
            self._root.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def save(
        self,
        artifact_type: ArtifactType,
        content: bytes,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> EvidenceRef:
        """Persist *content* and return an immutable ``EvidenceRef``."""
        sha = hashlib.sha256(content).hexdigest()
        evidence_id = str(uuid.uuid4())
        meta = metadata or {}

        if self._backend == "minio":
            stored_at = self._write_minio(sha, content, artifact_type)
        else:
            stored_at = self._write_fs(sha, content, artifact_type)

        ref = EvidenceRef(
            evidence_id=evidence_id,
            sha256=sha,
            artifact_type=artifact_type,
            stored_at=stored_at,
            created_utc=datetime.now(timezone.utc).isoformat(),
            metadata=meta,
        )

        # Persist metadata sidecar
        self._write_meta(sha, ref)

        logger.info(
            "evidence.saved",
            extra={"evidence_id": evidence_id, "sha256": sha, "type": artifact_type.value},
        )
        return ref

    def get(self, evidence_ref_id: str | None = None, sha256: str | None = None) -> Artifact:
        """
        Retrieve an artifact by *evidence_ref_id* or *sha256*.

        At least one parameter is required.  When *sha256* is supplied
        it is used directly; otherwise the metadata sidecar for the
        given *evidence_ref_id* is read first to resolve the digest.
        """
        digest = sha256

        if digest is None:
            if evidence_ref_id is None:
                raise ValueError("Provide evidence_ref_id or sha256")
            digest = self._resolve_id(evidence_ref_id)

        if digest is None:
            raise FileNotFoundError(
                f"Artifact not found: evidence_ref_id={evidence_ref_id}"
            )

        ref = self._read_meta(digest)
        content = self._read_content(digest, ref.artifact_type)
        return Artifact(ref=ref, content=content)

    # ------------------------------------------------------------------
    # Filesystem backend
    # ------------------------------------------------------------------

    def _write_fs(self, sha: str, content: bytes, atype: ArtifactType) -> str:
        prefix = sha[:2]
        directory = self._root / prefix
        directory.mkdir(parents=True, exist_ok=True)
        blob_path = directory / sha
        if not blob_path.exists():
            blob_path.write_bytes(content)
        return str(blob_path)

    def _write_meta(self, sha: str, ref: EvidenceRef) -> None:
        if self._backend == "minio":
            self._write_meta_minio(sha, ref)
        else:
            prefix = sha[:2]
            meta_path = self._root / prefix / f"{sha}.meta.json"
            data = {
                "evidence_id": ref.evidence_id,
                "sha256": ref.sha256,
                "artifact_type": ref.artifact_type.value,
                "stored_at": ref.stored_at,
                "created_utc": ref.created_utc,
                "metadata": ref.metadata,
            }
            meta_path.write_text(json.dumps(data, indent=2))

    def _read_meta(self, sha: str) -> EvidenceRef:
        if self._backend == "minio":
            return self._read_meta_minio(sha)

        prefix = sha[:2]
        meta_path = self._root / prefix / f"{sha}.meta.json"
        if not meta_path.exists():
            raise FileNotFoundError(f"Metadata not found for {sha}")
        data = json.loads(meta_path.read_text())
        return EvidenceRef(
            evidence_id=data["evidence_id"],
            sha256=data["sha256"],
            artifact_type=ArtifactType(data["artifact_type"]),
            stored_at=data["stored_at"],
            created_utc=data["created_utc"],
            metadata=data.get("metadata", {}),
        )

    def _read_content(self, sha: str, atype: ArtifactType) -> bytes:
        if self._backend == "minio":
            return self._read_content_minio(sha, atype)
        prefix = sha[:2]
        blob_path = self._root / prefix / sha
        if not blob_path.exists():
            raise FileNotFoundError(f"Blob not found: {blob_path}")
        return blob_path.read_bytes()

    def _resolve_id(self, evidence_ref_id: str) -> Optional[str]:
        """Walk meta files to find the digest for a given evidence_ref_id."""
        if self._backend == "minio":
            return self._resolve_id_minio(evidence_ref_id)

        for meta_file in self._root.rglob("*.meta.json"):
            data = json.loads(meta_file.read_text())
            if data.get("evidence_id") == evidence_ref_id:
                return data["sha256"]
        return None

    # ------------------------------------------------------------------
    # MinIO backend
    # ------------------------------------------------------------------

    def _get_minio(self) -> Any:
        if self._minio_client is None:
            from minio import Minio  # type: ignore[import-untyped]

            self._minio_client = Minio(
                self._minio_endpoint,
                access_key=self._minio_access_key,
                secret_key=self._minio_secret_key,
                secure=self._minio_secure,
            )
            if not self._minio_client.bucket_exists(self._minio_bucket):
                self._minio_client.make_bucket(self._minio_bucket)
        return self._minio_client

    def _minio_object_key(self, sha: str) -> str:
        return f"{sha[:2]}/{sha}"

    def _write_minio(self, sha: str, content: bytes, atype: ArtifactType) -> str:
        import io

        client = self._get_minio()
        key = self._minio_object_key(sha)
        try:
            client.stat_object(self._minio_bucket, key)
        except Exception:
            client.put_object(
                self._minio_bucket,
                key,
                io.BytesIO(content),
                length=len(content),
            )
        return f"s3://{self._minio_bucket}/{key}"

    def _write_meta_minio(self, sha: str, ref: EvidenceRef) -> None:
        import io

        client = self._get_minio()
        key = f"{sha[:2]}/{sha}.meta.json"
        data = json.dumps(
            {
                "evidence_id": ref.evidence_id,
                "sha256": ref.sha256,
                "artifact_type": ref.artifact_type.value,
                "stored_at": ref.stored_at,
                "created_utc": ref.created_utc,
                "metadata": ref.metadata,
            }
        ).encode()
        client.put_object(self._minio_bucket, key, io.BytesIO(data), length=len(data))

    def _read_meta_minio(self, sha: str) -> EvidenceRef:
        client = self._get_minio()
        key = f"{sha[:2]}/{sha}.meta.json"
        resp = client.get_object(self._minio_bucket, key)
        data = json.loads(resp.read())
        resp.close()
        resp.release_conn()
        return EvidenceRef(
            evidence_id=data["evidence_id"],
            sha256=data["sha256"],
            artifact_type=ArtifactType(data["artifact_type"]),
            stored_at=data["stored_at"],
            created_utc=data["created_utc"],
            metadata=data.get("metadata", {}),
        )

    def _read_content_minio(self, sha: str, atype: ArtifactType) -> bytes:
        client = self._get_minio()
        key = self._minio_object_key(sha)
        resp = client.get_object(self._minio_bucket, key)
        content = resp.read()
        resp.close()
        resp.release_conn()
        return content

    def _resolve_id_minio(self, evidence_ref_id: str) -> Optional[str]:
        client = self._get_minio()
        for obj in client.list_objects(self._minio_bucket, recursive=True):
            if obj.object_name.endswith(".meta.json"):
                resp = client.get_object(self._minio_bucket, obj.object_name)
                data = json.loads(resp.read())
                resp.close()
                resp.release_conn()
                if data.get("evidence_id") == evidence_ref_id:
                    return data["sha256"]
        return None
