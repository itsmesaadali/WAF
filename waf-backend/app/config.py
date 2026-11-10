"""Application settings, read from environment variables or the project .env file."""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_DIR = Path(__file__).resolve().parents[1]
ROOT_DIR = BACKEND_DIR.parent
# Hosting platforms provide real variables, so a missing .env file is fine.
_ENV_FILE = ROOT_DIR / ".env"
MIN_SECRET_LENGTH = 32


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=_ENV_FILE, extra="ignore")

    waf_env: str = "local"
    database_url: str
    database_url_unpooled: str | None = None
    # Optional schema, used to keep automated tests away from real data.
    database_schema: str | None = None

    upstream_url: str = "http://127.0.0.1:3000"
    waf_shared_secret: str
    jwt_secret: str
    model_signing_key: str

    admin_username: str = "admin"
    admin_password: str | None = None

    waf_host: str = "127.0.0.1"
    waf_port: int = 8000
    trust_proxy_hops: int = 0
    fail_mode: str = "closed"
    max_body_bytes: int = 2 * 1024 * 1024
    log_retention_days: int = 30
    simulator_enabled: bool = True

    jwt_lifetime_minutes: int = 120
    model_path: Path = BACKEND_DIR / "models" / "iforest.joblib"

    @field_validator("waf_shared_secret", "jwt_secret", "model_signing_key")
    @classmethod
    def _strong_secret(cls, value: str) -> str:
        if len(value) < MIN_SECRET_LENGTH:
            raise ValueError(f"secrets must be at least {MIN_SECRET_LENGTH} characters; run scripts/setup-env.py")
        return value

    @field_validator("fail_mode")
    @classmethod
    def _valid_fail_mode(cls, value: str) -> str:
        if value not in {"closed", "open"}:
            raise ValueError("FAIL_MODE must be 'closed' or 'open'")
        return value

    @field_validator("upstream_url")
    @classmethod
    def _valid_upstream(cls, value: str) -> str:
        parts = urlsplit(value)
        if parts.scheme not in {"http", "https"} or not parts.netloc:
            raise ValueError("UPSTREAM_URL must be a full http(s) URL")
        return value.rstrip("/")

    @property
    def sqlalchemy_url(self) -> str:
        return to_sqlalchemy_url(self.database_url)


def to_sqlalchemy_url(url: str) -> str:
    """Convert a Neon URL to SQLAlchemy's psycopg form, keeping only libpq options."""
    parts = urlsplit(url)
    query = [(k, v) for k, v in parse_qsl(parts.query) if k != "schema"]
    return urlunsplit(("postgresql+psycopg", parts.netloc, parts.path, urlencode(query), ""))


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
