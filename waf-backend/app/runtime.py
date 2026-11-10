"""Shared state for the running WAF process."""
from __future__ import annotations

import time
from dataclasses import dataclass, field

import httpx

from .config import Settings, get_settings
from .ml.model import TrainedModel
from .security.activity import IpActivity
from .services.bans import BanStore
from .services.log_writer import LogWriter
from .services.runtime_settings import RuntimeSettings


@dataclass
class Runtime:
    settings: Settings
    config: RuntimeSettings = field(default_factory=RuntimeSettings)
    writer: LogWriter = field(default_factory=LogWriter)
    bans: BanStore = field(default_factory=BanStore)
    activity: IpActivity = field(default_factory=IpActivity)
    model: TrainedModel | None = None
    model_error: str | None = None
    client: httpx.AsyncClient | None = None
    started_at: float = field(default_factory=time.time)
    db_ok: bool = False
    db_error: str | None = None
    requests_total: int = 0
    inspection_errors: int = 0
    ml_errors: int = 0
    upstream_errors: int = 0


_runtime: Runtime | None = None


def get_runtime() -> Runtime:
    global _runtime
    if _runtime is None:
        _runtime = Runtime(settings=get_settings())
    return _runtime


def reset_runtime(runtime: Runtime | None = None) -> None:
    """Used by tests to start from a clean state."""
    global _runtime
    _runtime = runtime
