"""Auth routes — login, refresh, API key management.

POST /auth/login           → JWT token pair
POST /auth/refresh         → refresh access token
POST /auth/api-keys        → create API key
DELETE /auth/api-keys/{id} → revoke API key
"""

from __future__ import annotations

import secrets
import uuid

from fastapi import APIRouter, HTTPException, status

from backend.app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_api_key,
)
from backend.app.schemas.schemas import (
    LoginRequest,
    TokenResponse,
    RefreshRequest,
    APIKeyCreate,
    APIKeyResponse,
)

router = APIRouter()

# Hard-coded demo user for MVP (replace with DB user model later)
DEMO_USER = {"username": "admin", "password": "admin"}


@router.post("/login", response_model=TokenResponse)
async def login(body: LoginRequest):
    """Authenticate and return JWT token pair."""
    if body.username != DEMO_USER["username"] or body.password != DEMO_USER["password"]:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    access = create_access_token(subject=body.username)
    refresh = create_refresh_token(subject=body.username)
    return TokenResponse(access_token=access, refresh_token=refresh)


@router.post("/refresh", response_model=TokenResponse)
async def refresh(body: RefreshRequest):
    """Refresh an access token using a valid refresh token."""
    payload = decode_token(body.refresh_token)
    if payload.get("type") != "refresh":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not a refresh token")
    access = create_access_token(subject=payload["sub"])
    refresh_tok = create_refresh_token(subject=payload["sub"])
    return TokenResponse(access_token=access, refresh_token=refresh_tok)


@router.post("/api-keys", response_model=APIKeyResponse, status_code=status.HTTP_201_CREATED)
async def create_api_key(body: APIKeyCreate):
    """Generate a new API key.

    Stub: generates a key and returns it. In production the hashed key
    would be stored in the database.
    """
    raw_key = secrets.token_urlsafe(32)
    key_id = uuid.uuid4()
    _hashed = hash_api_key(raw_key)  # noqa: F841 — would be stored in DB
    return APIKeyResponse(
        id=key_id,
        name=body.name,
        key=raw_key,
        created_at=__import__("datetime").datetime.now(__import__("datetime").timezone.utc),
    )


@router.delete("/api-keys/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_api_key(key_id: str):
    """Revoke an API key by ID.

    Stub: returns 204 unconditionally.
    TODO: delete the key from the database.
    """
    return None
