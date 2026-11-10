"""Admin login, logout and password change."""
from __future__ import annotations

import time
from collections import defaultdict, deque
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select

from ..db import session_scope
from ..models import AdminUser
from ..security.auth import MIN_PASSWORD_LENGTH, create_token, hash_password, verify_password
from .deps import Admin, audit, current_admin, request_ip

router = APIRouter(prefix="/auth", tags=["auth"])

MAX_FAILED_ATTEMPTS = 5
LOCK_MINUTES = 15
IP_LOGIN_LIMIT = 20
IP_WINDOW_SECONDS = 300.0
_login_attempts: dict[str, deque[float]] = defaultdict(deque)
# One generic message, so attackers can't tell which usernames exist or are locked.
_BAD_LOGIN = HTTPException(status.HTTP_401_UNAUTHORIZED, "Incorrect username or password")


class LoginBody(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class PasswordBody(BaseModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=MIN_PASSWORD_LENGTH, max_length=256)


def _limit_by_ip(ip: str) -> None:
    now = time.monotonic()
    attempts = _login_attempts[ip]
    while attempts and attempts[0] < now - IP_WINDOW_SECONDS:
        attempts.popleft()
    if len(attempts) >= IP_LOGIN_LIMIT:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many login attempts. Try again later.")
    attempts.append(now)


@router.post("/login")
def login(body: LoginBody, request: Request) -> dict:
    ip = request_ip(request)
    _limit_by_ip(ip)
    now = datetime.now(UTC)
    with session_scope() as session:
        user = session.scalar(select(AdminUser).where(AdminUser.username == body.username))
        locked = bool(user and user.locked_until and user.locked_until > now)
        valid = verify_password(user.password_hash if user else None, body.password)
        if user and not locked and valid:
            user.failed_attempts = 0
            user.locked_until = None
            user.last_login_at = now
            token, expires_in = create_token(user.username, user.token_version)
            success = True
        else:
            success = False
            if user and not locked:
                user.failed_attempts += 1
                if user.failed_attempts >= MAX_FAILED_ATTEMPTS:
                    user.locked_until = now + timedelta(minutes=LOCK_MINUTES)
                    user.failed_attempts = 0
    if not success:
        audit(body.username[:64], "login_failed", None, {"locked": locked}, ip)
        raise _BAD_LOGIN
    audit(body.username, "login", None, None, ip)
    return {"access_token": token, "token_type": "bearer", "expires_in": expires_in, "username": body.username}


@router.get("/me")
def me(request: Request, admin: Admin = Depends(current_admin)) -> dict:
    return {"username": admin.username, "ip": request_ip(request)}


@router.post("/logout")
def logout(request: Request, admin: Admin = Depends(current_admin)) -> dict:
    with session_scope() as session:
        user = session.scalar(select(AdminUser).where(AdminUser.username == admin.username))
        if user:
            user.token_version += 1
    audit(admin.username, "logout", None, None, request_ip(request))
    return {"ok": True}


@router.post("/change-password")
def change_password(body: PasswordBody, request: Request, admin: Admin = Depends(current_admin)) -> dict:
    with session_scope() as session:
        user = session.scalar(select(AdminUser).where(AdminUser.username == admin.username))
        if user is None or not verify_password(user.password_hash, body.current_password):
            raise _BAD_LOGIN
        user.password_hash = hash_password(body.new_password)
        user.token_version += 1
    audit(admin.username, "password_changed", admin.username, None, request_ip(request))
    return {"ok": True}
