"""
core/config.py — Centralised configuration loaded from env / YAML.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Dict, Optional


@dataclass
class LuciferConfig:
    """Runtime configuration — populated from environment variables."""

    # Evidence store
    evidence_backend: str = os.getenv("LUCIFER_EVIDENCE_BACKEND", "filesystem")
    evidence_root: str = os.getenv("LUCIFER_EVIDENCE_ROOT", "./evidence_store")
    minio_endpoint: str = os.getenv("MINIO_ENDPOINT", "localhost:9000")
    minio_access_key: str = os.getenv("MINIO_ACCESS_KEY", "")
    minio_secret_key: str = os.getenv("MINIO_SECRET_KEY", "")
    minio_bucket: str = os.getenv("MINIO_BUCKET", "lucifer-evidence")

    # HTTP engine
    http_max_rps: int = int(os.getenv("LUCIFER_HTTP_MAX_RPS", "10"))
    http_timeout: float = float(os.getenv("LUCIFER_HTTP_TIMEOUT", "30"))
    http_max_redirects: int = int(os.getenv("LUCIFER_HTTP_MAX_REDIRECTS", "10"))

    # Browser engine
    browser_headless: bool = os.getenv("LUCIFER_BROWSER_HEADLESS", "1") == "1"
    browser_timeout: float = float(os.getenv("LUCIFER_BROWSER_TIMEOUT", "30000"))

    # MITM
    mitm_default_port: int = int(os.getenv("LUCIFER_MITM_PORT", "8080"))

    # OAST / Interactsh
    oast_server_url: str = os.getenv("LUCIFER_OAST_SERVER", "https://interact.sh")
    oast_auth_token: str = os.getenv("LUCIFER_OAST_TOKEN", "")
    oast_poll_interval: int = int(os.getenv("LUCIFER_OAST_POLL_INTERVAL", "5"))

    # Embeddings / KB
    embedding_model: str = os.getenv(
        "LUCIFER_EMBEDDING_MODEL", "text-embedding-3-small"
    )
    chroma_persist_dir: str = os.getenv("LUCIFER_CHROMA_DIR", "./chroma_db")
    chunk_size: int = int(os.getenv("LUCIFER_CHUNK_SIZE", "512"))
    chunk_overlap: int = int(os.getenv("LUCIFER_CHUNK_OVERLAP", "50"))

    # Scope
    scope_file: str = os.getenv("LUCIFER_SCOPE_FILE", "./scope.yaml")


# Singleton — import and use directly
settings = LuciferConfig()
