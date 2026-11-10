"""SQLAlchemy view of the tables created by the Prisma migrations.

Tables are never created from here. tests/integration/test_schema_match.py checks
that these definitions still match the migrated database.
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import BigInteger, Boolean, DateTime, Double, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class AdminUser(Base):
    __tablename__ = "admin_users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True)
    password_hash: Mapped[str] = mapped_column(Text)
    failed_attempts: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    token_version: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class RequestLog(Base):
    __tablename__ = "request_logs"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    client_ip: Mapped[str] = mapped_column(String(64))
    method: Mapped[str] = mapped_column(String(16))
    path: Mapped[str] = mapped_column(Text)
    query: Mapped[str | None] = mapped_column(Text)
    user_agent: Mapped[str | None] = mapped_column(Text)
    status_code: Mapped[int] = mapped_column(Integer)
    action: Mapped[str] = mapped_column(String(16))
    reason: Mapped[str | None] = mapped_column(Text)
    waf_ms: Mapped[float] = mapped_column(Double)
    upstream_ms: Mapped[float | None] = mapped_column(Double)
    anomaly_score: Mapped[float | None] = mapped_column(Double)
    is_anomaly: Mapped[bool] = mapped_column(Boolean, default=False)
    features: Mapped[dict | None] = mapped_column(JSONB)
    mode: Mapped[str] = mapped_column(String(16))
    simulated: Mapped[bool] = mapped_column(Boolean, default=False)
    upstream: Mapped[str | None] = mapped_column(Text)


class Incident(Base):
    __tablename__ = "incidents"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    client_ip: Mapped[str] = mapped_column(String(64))
    method: Mapped[str] = mapped_column(String(16))
    path: Mapped[str] = mapped_column(Text)
    attack_type: Mapped[str] = mapped_column(String(32))
    severity: Mapped[str] = mapped_column(String(16))
    rule_id: Mapped[str | None] = mapped_column(String(64))
    rule_name: Mapped[str | None] = mapped_column(Text)
    location: Mapped[str | None] = mapped_column(Text)
    evidence: Mapped[str | None] = mapped_column(Text)
    action_taken: Mapped[str] = mapped_column(String(16))
    anomaly_score: Mapped[float | None] = mapped_column(Double)
    mode: Mapped[str] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(16), default="open")
    simulated: Mapped[bool] = mapped_column(Boolean, default=False)


class IpBan(Base):
    __tablename__ = "ip_bans"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ip: Mapped[str] = mapped_column(String(64))
    reason: Mapped[str] = mapped_column(Text)
    source: Mapped[str] = mapped_column(String(16))
    created_by: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    lifted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    lifted_by: Mapped[str | None] = mapped_column(String(64))
    simulated: Mapped[bool] = mapped_column(Boolean, default=False)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    username: Mapped[str] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(64))
    target: Mapped[str | None] = mapped_column(Text)
    details: Mapped[dict | None] = mapped_column(JSONB)
    ip: Mapped[str | None] = mapped_column(String(64))


class Setting(Base):
    __tablename__ = "settings"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[object] = mapped_column(JSONB)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_by: Mapped[str | None] = mapped_column(String(64))


class MlModelRun(Base):
    __tablename__ = "ml_model_runs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    source: Mapped[str] = mapped_column(String(16))
    samples: Mapped[int] = mapped_column(Integer)
    contamination: Mapped[float] = mapped_column(Double)
    threshold: Mapped[float] = mapped_column(Double)
    holdout_flag_rate: Mapped[float] = mapped_column(Double)
    feature_names: Mapped[list] = mapped_column(JSONB)
    trained_by: Mapped[str | None] = mapped_column(String(64))
    active: Mapped[bool] = mapped_column(Boolean, default=False)
