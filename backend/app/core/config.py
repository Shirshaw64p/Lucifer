"""Application settings loaded from environment variables via pydantic-settings.

All secrets and tunables are read from the .env file (or real env vars in
production). See .env.example for the full list of supported variables.
"""

from __future__ import annotations

from functools import lru_cache
from typing import List

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Central configuration object — populated from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Application ──────────────────────────────────────────────────────
    app_name: str = "Lucifer"
    app_env: str = "development"
    debug: bool = True
    log_level: str = "DEBUG"

    # ── Server ───────────────────────────────────────────────────────────
    host: str = "0.0.0.0"
    port: int = 8080
    cors_origins: List[str] = ["http://localhost:3000", "http://localhost:5173"]

    @field_validator("cors_origins", mode="before")
    @classmethod
    def _parse_cors(cls, v: str | List[str]) -> List[str]:
        if isinstance(v, str):
            import json
            return json.loads(v)
        return v

    # ── PostgreSQL ───────────────────────────────────────────────────────
    postgres_host: str = "localhost"
    postgres_port: int = 5432
    postgres_user: str = "lucifer"
    postgres_password: str = "changeme_pg_password"
    postgres_db: str = "lucifer"
    database_url: str = ""

    @property
    def async_database_url(self) -> str:
        """Build the async DB URL from components if DATABASE_URL is empty."""
        if self.database_url:
            return self.database_url
        return (
            f"postgresql+asyncpg://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    # ── Redis ────────────────────────────────────────────────────────────
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_password: str = "changeme_redis_password"
    redis_url: str = ""

    @property
    def effective_redis_url(self) -> str:
        if self.redis_url:
            return self.redis_url
        return f"redis://:{self.redis_password}@{self.redis_host}:{self.redis_port}/0"

    # ── Celery ───────────────────────────────────────────────────────────
    celery_broker_url: str = ""
    celery_result_backend: str = ""

    @property
    def effective_celery_broker(self) -> str:
        if self.celery_broker_url:
            return self.celery_broker_url
        return f"redis://:{self.redis_password}@{self.redis_host}:{self.redis_port}/1"

    @property
    def effective_celery_backend(self) -> str:
        if self.celery_result_backend:
            return self.celery_result_backend
        return f"redis://:{self.redis_password}@{self.redis_host}:{self.redis_port}/2"

    # ── JWT ──────────────────────────────────────────────────────────────
    jwt_secret_key: str = "changeme_jwt_secret_min_32_chars_long!!"
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 30
    jwt_refresh_token_expire_days: int = 7

    # ── API Key ──────────────────────────────────────────────────────────
    api_key_header: str = "X-API-Key"

    # ── MinIO ────────────────────────────────────────────────────────────
    minio_endpoint: str = "localhost:9000"
    minio_access_key: str = "minioadmin"
    minio_secret_key: str = "changeme_minio_secret"
    minio_bucket: str = "lucifer-artifacts"
    minio_use_ssl: bool = False

    # ── ChromaDB ─────────────────────────────────────────────────────────
    chroma_host: str = "localhost"
    chroma_port: int = 8000

    # ── Interactsh ───────────────────────────────────────────────────────
    interactsh_host: str = "localhost"
    interactsh_port: int = 8001

    # ── LLM API Keys ─────────────────────────────────────────────────────
    anthropic_api_key: str = ""
    openai_api_key: str = ""
    ollama_base_url: str = "http://localhost:11434"


@lru_cache
def get_settings() -> Settings:
    """Return a cached singleton of the application settings."""
    return Settings()
