"""
PQC-Analyzer - API Authentication & Authorization
===================================================
Implements two complementary auth mechanisms:

  1. JWT Bearer Token — issued by /auth/token, short-lived (configurable TTL)
  2. API Key Header  — static key via X-API-Key header, for service-to-service

Environment variables:
  PQC_JWT_SECRET        — HS256 signing secret (generate with: openssl rand -hex 32)
  PQC_JWT_TTL_MIN       — access token lifetime in minutes (default 60)
  PQC_API_KEYS          — comma-separated list of valid API keys
  PQC_ADMIN_USER        — admin username for /auth/token (default "admin")
  PQC_ADMIN_PASS_HASH   — bcrypt hash of admin password
"""

from __future__ import annotations

import hashlib
import logging
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Depends, Header, HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel

logger = logging.getLogger(__name__)

JWT_SECRET: str = os.getenv(
    "PQC_JWT_SECRET",
    "CHANGE_ME_IN_PRODUCTION_use_openssl_rand_hex_32",  # noqa: S106
)
JWT_ALGORITHM = "HS256"
JWT_TTL_MINUTES: int = int(os.getenv("PQC_JWT_TTL_MIN", "60"))

_raw_api_keys: str = os.getenv("PQC_API_KEYS", "")
VALID_API_KEYS: set[str] = {k.strip() for k in _raw_api_keys.split(",") if k.strip()}

ADMIN_USERNAME: str = os.getenv("PQC_ADMIN_USER", "admin")
_DEFAULT_HASH = "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4oHXyZ8QBK"
ADMIN_PASS_HASH: str = os.getenv("PQC_ADMIN_PASS_HASH", _DEFAULT_HASH)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class CurrentUser(BaseModel):
    username: str
    auth_method: str
    is_admin: bool = False


_pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
_bearer_scheme = HTTPBearer(auto_error=False)


def verify_password(plain: str, hashed: str) -> bool:
    return _pwd_ctx.verify(plain, hashed)


def create_access_token(username: str, extra_claims: Optional[dict] = None) -> str:
    now = datetime.now(tz=timezone.utc)
    payload = {
        "sub": username,
        "iat": now,
        "exp": now + timedelta(minutes=JWT_TTL_MINUTES),
        "jti": secrets.token_hex(8),
    }
    if extra_claims:
        payload.update(extra_claims)
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_access_token(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid or expired token: {exc}",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


def _constant_time_key_check(candidate: str) -> bool:
    for valid_key in VALID_API_KEYS:
        if secrets.compare_digest(
            hashlib.sha256(candidate.encode()).digest(),
            hashlib.sha256(valid_key.encode()).digest(),
        ):
            return True
    return False


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(_bearer_scheme),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
) -> CurrentUser:
    if credentials is not None:
        payload = decode_access_token(credentials.credentials)
        username: str = payload.get("sub", "unknown")
        return CurrentUser(
            username=username,
            auth_method="jwt",
            is_admin=(username == ADMIN_USERNAME),
        )
    if x_api_key is not None:
        if not VALID_API_KEYS:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="No API keys configured on server. Use JWT auth.",
            )
        if _constant_time_key_check(x_api_key):
            return CurrentUser(username="api_key_user", auth_method="api_key", is_admin=False)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
            headers={"WWW-Authenticate": "X-API-Key"},
        )
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required. Provide 'Authorization: Bearer <token>' or 'X-API-Key: <key>'",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def require_admin(user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
    if not user.is_admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin privileges required")
    return user


async def login_for_access_token(form_data: OAuth2PasswordRequestForm) -> TokenResponse:
    if form_data.username != ADMIN_USERNAME or not verify_password(form_data.password, ADMIN_PASS_HASH):
        _pwd_ctx.dummy_verify()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = create_access_token(form_data.username, extra_claims={"role": "admin"})
    logger.info("JWT issued for user '%s'", form_data.username)
    return TokenResponse(access_token=token, expires_in=JWT_TTL_MINUTES * 60)
