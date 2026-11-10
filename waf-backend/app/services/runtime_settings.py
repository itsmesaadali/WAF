"""Settings admins can change while the WAF runs. Validated here, stored in the database."""
from __future__ import annotations

import ipaddress
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert

from ..db import session_scope
from ..models import Setting

SETTINGS_KEY = "waf"


class RuntimeSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # block stops attacks. monitor records what would have happened and lets it through.
    mode: Literal["block", "monitor"] = "block"
    rate_limit_per_minute: int = Field(default=300, ge=5, le=100_000)
    ban_minutes: int = Field(default=15, ge=1, le=10_080)
    # Blocked requests within 10 minutes before an automatic ban.
    strikes_before_ban: int = Field(default=5, ge=1, le=1000)
    ml_enabled: bool = True
    # Off by default: ML is supporting evidence, not proof of an attack.
    ml_block: bool = False
    ml_threshold_override: float | None = Field(default=None, ge=0.0, le=1.0)
    ip_allowlist: list[str] = Field(default_factory=list, max_length=100)

    @field_validator("ip_allowlist")
    @classmethod
    def _valid_networks(cls, values: list[str]) -> list[str]:
        for value in values:
            ipaddress.ip_network(value, strict=False)
        return values

    def is_allowlisted(self, ip: str) -> bool:
        if not self.ip_allowlist:
            return False
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(address in ipaddress.ip_network(net, strict=False) for net in self.ip_allowlist)


def load_settings() -> RuntimeSettings:
    with session_scope() as session:
        stored = session.scalar(select(Setting.value).where(Setting.key == SETTINGS_KEY))
    return RuntimeSettings.model_validate(stored) if stored else RuntimeSettings()


def save_settings(settings: RuntimeSettings, username: str) -> None:
    value = settings.model_dump()
    statement = insert(Setting).values(key=SETTINGS_KEY, value=value, updated_by=username)
    statement = statement.on_conflict_do_update(
        index_elements=[Setting.key],
        set_={"value": value, "updated_by": username, "updated_at": statement.excluded.updated_at},
    )
    with session_scope() as session:
        session.execute(statement)
