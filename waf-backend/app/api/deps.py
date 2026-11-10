"""Shared API helpers: admin authentication and audit logging."""
from __future__ import annotations

from dataclasses import dataclass

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select

from ..db import session_scope
from ..models import AdminUser, AuditLog
from ..runtime import get_runtime
from ..security.auth import decode_token
from ..security.client_ip import resolve_client_ip

_bearer = HTTPBearer(auto_error=False)
_UNAUTHORIZED = HTTPException(
    status.HTTP_401_UNAUTHORIZED, "Not authenticated", headers={"WWW-Authenticate": "Bearer"}
)


@dataclass(frozen=True)
class Admin:
    username: str
    token_version: int


def current_admin(credentials: HTTPAuthorizationCredentials | None = Depends(_bearer)) -> Admin:
    if credentials is None:
        raise _UNAUTHORIZED
    try:
        payload = decode_token(credentials.credentials)
    except jwt.PyJWTError:
        raise _UNAUTHORIZED from None
    with session_scope() as session:
        version = session.scalar(select(AdminUser.token_version).where(AdminUser.username == payload["sub"]))
    # Checked on every request, so logging out cancels older tokens immediately.
    if version is None or version != payload["ver"]:
        raise _UNAUTHORIZED
    return Admin(payload["sub"], version)


def request_ip(request: Request) -> str:
    peer = request.client.host if request.client else None
    return resolve_client_ip(peer, request.headers.get("x-forwarded-for"), get_runtime().settings.trust_proxy_hops)


def audit(username: str, action: str, target: str | None, details: dict | None, ip: str | None) -> None:
    with session_scope() as session:
        session.add(AuditLog(username=username, action=action, target=target, details=details, ip=ip))
