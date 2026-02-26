"""JWT and API-key authentication utilities.

Provides:
- `create_access_token` / `create_refresh_token` — JWT generation
- `decode_token` — JWT verification
- `hash_api_key` — SHA-256 hashing for API key storage
- `get_current_user` — FastAPI dependency that validates JWT bearer token
- `get_api_key_user` — FastAPI dependency that validates X-API-Key header
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import Depends, HTTPException, Security, status
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt

from backend.app.core.config import get_settings

settings = get_settings()

# ── Security schemes ─────────────────────────────────────────────────────────
bearer_scheme = HTTPBearer(auto_error=False)
api_key_scheme = APIKeyHeader(name=settings.api_key_header, auto_error=False)


# ── JWT helpers ──────────────────────────────────────────────────────────────
def create_access_token(subject: str, extra: dict[str, Any] | None = None) -> str:
    """Create a short-lived JWT access token."""
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.jwt_access_token_expire_minutes)
    payload = {"sub": subject, "exp": expire, "type": "access"}
    if extra:
        payload.update(extra)
    return jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)


def create_refresh_token(subject: str) -> str:
    """Create a longer-lived JWT refresh token."""
    expire = datetime.now(timezone.utc) + timedelta(days=settings.jwt_refresh_token_expire_days)
    payload = {"sub": subject, "exp": expire, "type": "refresh"}
    return jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)


def decode_token(token: str) -> dict[str, Any]:
    """Decode and validate a JWT token. Raises HTTPException on failure."""
    try:
        payload = jwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])
        return payload
    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid or expired token: {exc}",
            headers={"WWW-Authenticate": "Bearer"},
        )


# ── API key helpers ──────────────────────────────────────────────────────────
def hash_api_key(raw_key: str) -> str:
    """Return the SHA-256 hex digest of a raw API key for safe storage."""
    return hashlib.sha256(raw_key.encode()).hexdigest()


# ── FastAPI dependencies ─────────────────────────────────────────────────────
async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
) -> dict[str, Any]:
    """Dependency: extract and validate the JWT from the Authorization header."""
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    payload = decode_token(credentials.credentials)
    if payload.get("type") != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type — access token required",
        )
    return payload


async def get_api_key_user(
    api_key: str | None = Security(api_key_scheme),
) -> str:
    """Dependency: validate the X-API-Key header.

    In a full implementation this would look up the hashed key in the DB.
    For now it returns the raw key as a stub.
    """
    if api_key is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing API key",
        )
    # TODO: look up hash_api_key(api_key) in the database
    return api_key


async def get_authenticated_user(
    jwt_user: dict[str, Any] | None = Depends(get_current_user),
) -> dict[str, Any]:
    """Combined auth dependency — prefers JWT, falls back to API key."""
    return jwt_user
