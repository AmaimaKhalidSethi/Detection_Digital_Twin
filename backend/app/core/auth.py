"""Authentication primitives for the Detection Digital Twin API.

Secrets are read only on the backend.  Browser sessions use a short-lived JWT
in an HttpOnly cookie; the React app never handles the signed token itself.
"""
from __future__ import annotations

import hmac
import os
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path

from dotenv import load_dotenv
from fastapi import HTTPException, Request
from jose import JWTError, jwt
import bcrypt
from sqlalchemy.orm import Session

from app.models.db import User

load_dotenv(Path(__file__).resolve().parents[2] / ".env")

ALGORITHM = "HS256"
SESSION_COOKIE = "ddt_session"
CSRF_COOKIE = "ddt_csrf"
SESSION_MINUTES = int(os.getenv("JWT_EXPIRATION_MINUTES", "60"))


def auth_required() -> bool:
    """Authentication is on by default; tests can explicitly opt out."""
    return os.getenv("DDT_AUTH_REQUIRED", "true").strip().lower() not in {"0", "false", "no"}


def cookie_secure() -> bool:
    return os.getenv("AUTH_COOKIE_SECURE", "false").strip().lower() in {"1", "true", "yes"}


def jwt_secret() -> str:
    secret = os.getenv("JWT_SECRET")
    if not secret or len(secret) < 32:
        raise RuntimeError("JWT_SECRET must be configured with at least 32 random characters")
    return secret


def hash_password(password: str) -> str:
    encoded = password.encode("utf-8")
    if len(encoded) > 72:
        raise ValueError("Password must not exceed 72 UTF-8 bytes")
    return bcrypt.hashpw(encoded, bcrypt.gensalt(rounds=12)).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except (ValueError, TypeError):
        return False


def create_user(db: Session, *, username: str, password: str, role: str = "analyst", is_active: bool = True) -> User:
    username = username.strip().lower()
    if not username:
        raise ValueError("Username is required")
    if len(password) < 12:
        raise ValueError("Password must be at least 12 characters")
    if role not in {"admin", "analyst"}:
        raise ValueError("Role must be admin or analyst")
    if db.query(User).filter(User.username == username).first():
        raise ValueError("Username already exists")
    user = User(username=username, password_hash=hash_password(password), role=role, is_active=is_active)
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def create_session_token(user: User) -> str:
    now = datetime.now(timezone.utc)
    payload = {"sub": user.id, "role": user.role, "iat": now, "exp": now + timedelta(minutes=SESSION_MINUTES)}
    return jwt.encode(payload, jwt_secret(), algorithm=ALGORITHM)


def new_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def _credential_from_request(request: Request) -> str | None:
    authorization = request.headers.get("Authorization", "")
    if authorization.startswith("Bearer "):
        return authorization.removeprefix("Bearer ").strip()
    return request.cookies.get(SESSION_COOKIE)


def resolve_current_user(request: Request, db: Session) -> User:
    token = _credential_from_request(request)
    if not token:
        raise HTTPException(status_code=401, detail="Authentication required")
    try:
        payload = jwt.decode(token, jwt_secret(), algorithms=[ALGORITHM])
        user_id = payload.get("sub")
    except (JWTError, ValueError, TypeError):
        raise HTTPException(status_code=401, detail="Invalid or expired authentication") from None
    if not isinstance(user_id, str):
        raise HTTPException(status_code=401, detail="Invalid or expired authentication")
    user = db.get(User, user_id)
    if user is None or not user.is_active:
        raise HTTPException(status_code=401, detail="Invalid or expired authentication")
    return user


def verify_csrf(request: Request) -> None:
    """Require a double-submit CSRF token for cookie-authenticated writes."""
    if request.method in {"GET", "HEAD", "OPTIONS"} or request.headers.get("Authorization"):
        return
    cookie_token = request.cookies.get(CSRF_COOKIE)
    header_token = request.headers.get("X-CSRF-Token")
    if not cookie_token or not header_token or not hmac.compare_digest(cookie_token, header_token):
        raise HTTPException(status_code=403, detail="CSRF validation failed")
