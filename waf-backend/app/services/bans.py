"""The ban list: in memory for instant checks, in the database so it survives restarts."""
from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import or_, select

from ..db import session_scope
from ..models import IpBan


class BanStore:
    def __init__(self) -> None:
        # ip -> expiry time, or None for a ban with no end
        self._active: dict[str, datetime | None] = {}

    def is_banned(self, ip: str) -> bool:
        if ip not in self._active:
            return False
        expires = self._active[ip]
        if expires is not None and expires <= datetime.now(UTC):
            del self._active[ip]
            return False
        return True

    def add(self, ip: str, expires_at: datetime | None) -> None:
        self._active[ip] = expires_at

    def remove(self, ip: str) -> None:
        self._active.pop(ip, None)

    def replace_all(self, active: dict[str, datetime | None]) -> None:
        self._active = active

    def count(self) -> int:
        now = datetime.now(UTC)
        return sum(1 for expires in self._active.values() if expires is None or expires > now)


def load_active_bans() -> dict[str, datetime | None]:
    now = datetime.now(UTC)
    with session_scope() as session:
        rows = session.execute(
            select(IpBan.ip, IpBan.expires_at).where(
                IpBan.lifted_at.is_(None), or_(IpBan.expires_at.is_(None), IpBan.expires_at > now)
            )
        ).all()
    return {ip: expires for ip, expires in rows}
