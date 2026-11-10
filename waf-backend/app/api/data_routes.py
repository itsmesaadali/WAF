"""Protected read and management APIs used by the dashboard."""
from __future__ import annotations

import asyncio
import csv
import io
import time
from datetime import UTC, datetime, timedelta
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import Response
from pydantic import BaseModel, Field, ValidationError, field_validator
from sqlalchemy import desc, func, or_, select, text

from ..config import get_settings
from ..db import session_scope
from ..models import AuditLog, Incident, IpBan, MlModelRun, RequestLog
from ..ml import train as train_lib
from ..ml import model as model_lib
from ..ml.features import FEATURE_NAMES
from ..runtime import get_runtime
from ..security.client_ip import canonical_ip
from ..services.runtime_settings import RuntimeSettings, save_settings
from .deps import Admin, audit, current_admin, request_ip

router = APIRouter(dependencies=[Depends(current_admin)])

WINDOWS = {"1h": (timedelta(hours=1), 60), "24h": (timedelta(hours=24), 1800), "7d": (timedelta(days=7), 14400)}
Window = Literal["1h", "24h", "7d"]


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _request_json(row: RequestLog) -> dict:
    return {
        "id": str(row.id),
        "created_at": _iso(row.created_at),
        "client_ip": row.client_ip,
        "method": row.method,
        "path": row.path,
        "query": row.query,
        "user_agent": row.user_agent,
        "status_code": row.status_code,
        "action": row.action,
        "reason": row.reason,
        "waf_ms": row.waf_ms,
        "upstream_ms": row.upstream_ms,
        "anomaly_score": row.anomaly_score,
        "is_anomaly": row.is_anomaly,
        "mode": row.mode,
        "simulated": row.simulated,
    }


def _incident_json(row: Incident) -> dict:
    return {
        "id": str(row.id),
        "created_at": _iso(row.created_at),
        "client_ip": row.client_ip,
        "method": row.method,
        "path": row.path,
        "attack_type": row.attack_type,
        "severity": row.severity,
        "rule_id": row.rule_id,
        "rule_name": row.rule_name,
        "location": row.location,
        "evidence": row.evidence,
        "action_taken": row.action_taken,
        "anomaly_score": row.anomaly_score,
        "mode": row.mode,
        "status": row.status,
        "simulated": row.simulated,
    }


def _ban_json(row: IpBan) -> dict:
    now = datetime.now(UTC)
    active = row.lifted_at is None and (row.expires_at is None or row.expires_at > now)
    return {
        "id": row.id,
        "ip": row.ip,
        "reason": row.reason,
        "source": row.source,
        "created_by": row.created_by,
        "created_at": _iso(row.created_at),
        "expires_at": _iso(row.expires_at),
        "lifted_at": _iso(row.lifted_at),
        "lifted_by": row.lifted_by,
        "simulated": row.simulated,
        "active": active,
    }


@router.get("/stats/overview")
def overview(window: Window = "1h") -> dict:
    span, bucket_seconds = WINDOWS[window]
    since = datetime.now(UTC) - span
    with session_scope() as session:
        summary = session.execute(
            select(
                func.count().label("total"),
                func.count().filter(RequestLog.action == "allowed").label("allowed"),
                func.count().filter(RequestLog.action == "flagged").label("flagged"),
                func.count().filter(RequestLog.action == "blocked").label("blocked"),
                func.count().filter(RequestLog.action == "rate_limited").label("rate_limited"),
                func.count().filter(RequestLog.action == "banned").label("banned"),
                func.count().filter(RequestLog.action == "error").label("errors"),
                func.count().filter(RequestLog.is_anomaly.is_(True)).label("anomalies"),
                func.count(func.distinct(RequestLog.client_ip)).label("unique_ips"),
                func.percentile_cont(0.5).within_group(RequestLog.waf_ms).label("waf_p50"),
                func.percentile_cont(0.95).within_group(RequestLog.waf_ms).label("waf_p95"),
            ).where(RequestLog.created_at >= since)
        ).one()

        bucket = func.to_timestamp(
            func.floor(func.extract("epoch", RequestLog.created_at) / bucket_seconds) * bucket_seconds
        ).label("bucket")
        series = session.execute(
            select(
                bucket,
                func.count().filter(RequestLog.action.in_(("allowed", "flagged"))).label("allowed"),
                func.count().filter(RequestLog.action.in_(("blocked", "rate_limited", "banned"))).label("blocked"),
                func.count().filter(RequestLog.is_anomaly.is_(True)).label("anomalies"),
            )
            .where(RequestLog.created_at >= since)
            .group_by(bucket)
            .order_by(bucket)
        ).all()

        by_type = session.execute(
            select(Incident.attack_type, func.count())
            .where(Incident.created_at >= since)
            .group_by(Incident.attack_type)
            .order_by(desc(func.count()))
        ).all()
        by_severity = session.execute(
            select(Incident.severity, func.count()).where(Incident.created_at >= since).group_by(Incident.severity)
        ).all()
        top_ips = session.execute(
            select(Incident.client_ip, func.count().label("count"))
            .where(Incident.created_at >= since)
            .group_by(Incident.client_ip)
            .order_by(desc("count"))
            .limit(5)
        ).all()
        recent = session.scalars(select(Incident).order_by(Incident.created_at.desc()).limit(8)).all()
        incident_total = sum(count for _, count in by_type)
        recent_json = [_incident_json(r) for r in recent]

    return {
        "window": window,
        "bucket_seconds": bucket_seconds,
        "totals": {
            "requests": summary.total,
            "allowed": summary.allowed,
            "flagged": summary.flagged,
            "blocked": summary.blocked,
            "rate_limited": summary.rate_limited,
            "banned": summary.banned,
            "errors": summary.errors,
            "anomalies": summary.anomalies,
            "unique_ips": summary.unique_ips,
            "incidents": incident_total,
        },
        "latency": {"waf_p50_ms": summary.waf_p50, "waf_p95_ms": summary.waf_p95},
        "series": [
            {"t": _iso(row.bucket), "allowed": row.allowed, "blocked": row.blocked, "anomalies": row.anomalies}
            for row in series
        ],
        "incidents_by_type": [{"type": t, "count": c} for t, c in by_type],
        "incidents_by_severity": [{"severity": s, "count": c} for s, c in by_severity],
        "top_ips": [{"ip": ip, "count": count} for ip, count in top_ips],
        "recent_incidents": recent_json,
        "active_bans": get_runtime().bans.count(),
        "mode": get_runtime().config.mode,
    }


@router.get("/traffic")
def traffic(
    limit: int = Query(50, ge=1, le=200),
    before_id: int | None = Query(None, ge=1),
    action: str | None = Query(None, max_length=16),
    ip: str | None = Query(None, max_length=64),
    search: str | None = Query(None, max_length=200),
    hide_simulated: bool = False,
) -> dict:
    query = select(RequestLog).order_by(RequestLog.id.desc()).limit(limit + 1)
    if before_id:
        query = query.where(RequestLog.id < before_id)
    if action:
        query = query.where(RequestLog.action == action)
    if ip:
        query = query.where(RequestLog.client_ip == ip)
    if search:
        query = query.where(RequestLog.path.ilike(f"%{_escape_like(search)}%", escape="\\"))
    if hide_simulated:
        query = query.where(RequestLog.simulated.is_(False))
    with session_scope() as session:
        rows = session.scalars(query).all()
        items = [_request_json(r) for r in rows[:limit]]
    return {"items": items, "next_before_id": items[-1]["id"] if len(rows) > limit else None}


def _escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _incident_filters(query, attack_type, severity, incident_status, ip, search, hide_simulated):  # noqa: ANN001, ANN202
    if attack_type:
        query = query.where(Incident.attack_type == attack_type)
    if severity:
        query = query.where(Incident.severity == severity)
    if incident_status:
        query = query.where(Incident.status == incident_status)
    if ip:
        query = query.where(Incident.client_ip == ip)
    if search:
        pattern = f"%{_escape_like(search)}%"
        query = query.where(or_(Incident.path.ilike(pattern, escape="\\"), Incident.rule_name.ilike(pattern, escape="\\")))
    if hide_simulated:
        query = query.where(Incident.simulated.is_(False))
    return query


@router.get("/incidents")
def incidents(
    limit: int = Query(50, ge=1, le=200),
    before_id: int | None = Query(None, ge=1),
    attack_type: str | None = Query(None, max_length=32),
    severity: str | None = Query(None, max_length=16),
    status_filter: str | None = Query(None, alias="status", max_length=16),
    ip: str | None = Query(None, max_length=64),
    search: str | None = Query(None, max_length=200),
    hide_simulated: bool = False,
) -> dict:
    query = select(Incident).order_by(Incident.id.desc()).limit(limit + 1)
    if before_id:
        query = query.where(Incident.id < before_id)
    query = _incident_filters(query, attack_type, severity, status_filter, ip, search, hide_simulated)
    with session_scope() as session:
        rows = session.scalars(query).all()
        items = [_incident_json(r) for r in rows[:limit]]
    return {"items": items, "next_before_id": items[-1]["id"] if len(rows) > limit else None}


def _csv_safe(value: object) -> str:
    """Stop spreadsheets from running attacker text as a formula (CSV injection)."""
    text_value = "" if value is None else str(value)
    return "'" + text_value if text_value[:1] in {"=", "+", "-", "@", "\t", "\r"} else text_value


@router.get("/incidents/export.csv")
def export_incidents(
    request: Request,
    attack_type: str | None = Query(None, max_length=32),
    severity: str | None = Query(None, max_length=16),
    status_filter: str | None = Query(None, alias="status", max_length=16),
    ip: str | None = Query(None, max_length=64),
    hide_simulated: bool = False,
    admin: Admin = Depends(current_admin),
) -> Response:
    query = select(Incident).order_by(Incident.id.desc()).limit(50_000)
    query = _incident_filters(query, attack_type, severity, status_filter, ip, None, hide_simulated)
    columns = ("id", "created_at", "client_ip", "method", "path", "attack_type", "severity", "rule_id", "rule_name",
               "location", "evidence", "action_taken", "anomaly_score", "mode", "status", "simulated")
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(columns)
    with session_scope() as session:
        rows = session.scalars(query).all()
        for row in rows:
            writer.writerow([_csv_safe(getattr(row, c)) for c in columns])
        count = len(rows)
    audit(admin.username, "incidents_exported", None, {"rows": count}, request_ip(request))
    return Response(
        output.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={"content-disposition": 'attachment; filename="waf-incidents.csv"'},
    )


class IncidentUpdate(BaseModel):
    status: Literal["open", "reviewed", "false_positive"]


@router.patch("/incidents/{incident_id}")
def update_incident(
    incident_id: int, body: IncidentUpdate, request: Request, admin: Admin = Depends(current_admin)
) -> dict:
    with session_scope() as session:
        row = session.get(Incident, incident_id)
        if row is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Incident not found")
        row.status = body.status
        result = _incident_json(row)
    audit(admin.username, "incident_updated", str(incident_id), {"status": body.status}, request_ip(request))
    return result


class BanCreate(BaseModel):
    ip: str = Field(max_length=64)
    reason: str = Field(min_length=3, max_length=500)
    # None means the ban stays until an admin lifts it.
    minutes: int | None = Field(default=None, ge=1, le=525_600)

    @field_validator("ip")
    @classmethod
    def _valid_ip(cls, value: str) -> str:
        ip = canonical_ip(value)
        if ip is None:
            raise ValueError("not a valid IP address")
        return ip


@router.get("/bans")
def list_bans(active_only: bool = True, limit: int = Query(100, ge=1, le=500)) -> dict:
    now = datetime.now(UTC)
    query = select(IpBan).order_by(IpBan.created_at.desc()).limit(limit)
    if active_only:
        query = query.where(IpBan.lifted_at.is_(None), or_(IpBan.expires_at.is_(None), IpBan.expires_at > now))
    with session_scope() as session:
        items = [_ban_json(r) for r in session.scalars(query).all()]
    return {"items": items}


@router.post("/bans", status_code=status.HTTP_201_CREATED)
def create_ban(body: BanCreate, request: Request, admin: Admin = Depends(current_admin)) -> dict:
    expires = datetime.now(UTC) + timedelta(minutes=body.minutes) if body.minutes else None
    with session_scope() as session:
        row = IpBan(ip=body.ip, reason=body.reason, source="manual", created_by=admin.username, expires_at=expires)
        session.add(row)
        session.flush()
        session.refresh(row)
        result = _ban_json(row)
    get_runtime().bans.add(body.ip, expires)
    audit(admin.username, "ip_banned", body.ip, {"minutes": body.minutes, "reason": body.reason}, request_ip(request))
    return result


@router.delete("/bans/{ban_id}")
def lift_ban(ban_id: int, request: Request, admin: Admin = Depends(current_admin)) -> dict:
    now = datetime.now(UTC)
    with session_scope() as session:
        row = session.get(IpBan, ban_id)
        if row is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Ban not found")
        ip = row.ip
        # All active rows for this IP are lifted, otherwise an older ban would still apply.
        rows = session.scalars(
            select(IpBan).where(IpBan.ip == ip, IpBan.lifted_at.is_(None))
        ).all()
        for active in rows:
            active.lifted_at = now
            active.lifted_by = admin.username
    runtime = get_runtime()
    runtime.bans.remove(ip)
    runtime.activity.clear_strikes(ip)
    audit(admin.username, "ip_unbanned", ip, None, request_ip(request))
    return {"ok": True, "ip": ip}


@router.get("/ml/status")
def ml_status() -> dict:
    runtime = get_runtime()
    with session_scope() as session:
        runs = session.scalars(select(MlModelRun).order_by(MlModelRun.created_at.desc()).limit(10)).all()
        history = [
            {
                "id": r.id,
                "created_at": _iso(r.created_at),
                "source": r.source,
                "samples": r.samples,
                "threshold": r.threshold,
                "holdout_flag_rate": r.holdout_flag_rate,
                "trained_by": r.trained_by,
                "active": r.active,
            }
            for r in runs
        ]
        distribution = session.execute(
            select(
                func.width_bucket(RequestLog.anomaly_score, 0.3, 0.8, 20).label("bucket"),
                func.count().label("count"),
            )
            .where(RequestLog.anomaly_score.is_not(None), RequestLog.created_at >= datetime.now(UTC) - timedelta(hours=24))
            .group_by("bucket")
            .order_by("bucket")
        ).all()
    model = runtime.model
    return {
        "loaded": model is not None,
        "error": runtime.model_error,
        "enabled": runtime.config.ml_enabled,
        "block_on_anomaly": runtime.config.ml_block,
        "threshold": model.threshold if model else None,
        "threshold_override": runtime.config.ml_threshold_override,
        "feature_names": list(FEATURE_NAMES),
        "history": history,
        "score_distribution": [
            {"from": round(0.3 + (row.bucket - 1) * 0.025, 3), "to": round(0.3 + row.bucket * 0.025, 3), "count": row.count}
            for row in distribution
        ],
    }


@router.get("/ml/anomalies")
def ml_anomalies(limit: int = Query(50, ge=1, le=200), before_id: int | None = Query(None, ge=1)) -> dict:
    query = select(RequestLog).where(RequestLog.is_anomaly.is_(True)).order_by(RequestLog.id.desc()).limit(limit + 1)
    if before_id:
        query = query.where(RequestLog.id < before_id)
    with session_scope() as session:
        rows = session.scalars(query).all()
        items = [_request_json(r) for r in rows[:limit]]
    return {"items": items, "next_before_id": items[-1]["id"] if len(rows) > limit else None}


class RetrainBody(BaseModel):
    source: Literal["generated", "observed"] = "generated"


@router.post("/ml/retrain")
def retrain(body: RetrainBody, request: Request, admin: Admin = Depends(current_admin)) -> dict:
    settings = get_settings()
    try:
        result = train_lib.train_and_save(body.source, trained_by=admin.username)
    except ValueError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from None
    runtime = get_runtime()
    runtime.model = model_lib.load(settings.model_path, settings.model_signing_key)
    runtime.model_error = None
    details = {"source": body.source, "samples": result.samples, "holdout_flag_rate": result.holdout_flag_rate}
    audit(admin.username, "ml_retrained", None, details, request_ip(request))
    return {"threshold": result.model.threshold, **details, "observed_samples": result.observed_samples}


@router.get("/settings")
def get_waf_settings() -> dict:
    runtime = get_runtime()
    return {
        "config": runtime.config.model_dump(),
        "environment": {
            "waf_env": runtime.settings.waf_env,
            "upstream_url": runtime.settings.upstream_url,
            "fail_mode": runtime.settings.fail_mode,
            "trust_proxy_hops": runtime.settings.trust_proxy_hops,
            "max_body_bytes": runtime.settings.max_body_bytes,
            "log_retention_days": runtime.settings.log_retention_days,
            "simulator_enabled": runtime.settings.simulator_enabled,
        },
    }


@router.patch("/settings")
def update_settings(changes: dict, request: Request, admin: Admin = Depends(current_admin)) -> dict:
    runtime = get_runtime()
    before = runtime.config.model_dump()
    try:
        updated = RuntimeSettings.model_validate({**before, **changes})
    except ValidationError as exc:
        problems = "; ".join(f"{'.'.join(map(str, e['loc']))}: {e['msg']}" for e in exc.errors(include_input=False))
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, problems) from None
    save_settings(updated, admin.username)
    runtime.config = updated
    after = updated.model_dump()
    diff = {k: {"from": before[k], "to": after[k]} for k in after if before[k] != after[k]}
    audit(admin.username, "settings_changed", None, diff, request_ip(request))
    return after


@router.get("/audit")
def audit_log(limit: int = Query(50, ge=1, le=200), before_id: int | None = Query(None, ge=1)) -> dict:
    query = select(AuditLog).order_by(AuditLog.id.desc()).limit(limit + 1)
    if before_id:
        query = query.where(AuditLog.id < before_id)
    with session_scope() as session:
        rows = session.scalars(query).all()
        items = [
            {
                "id": str(r.id),
                "created_at": _iso(r.created_at),
                "username": r.username,
                "action": r.action,
                "target": r.target,
                "details": r.details,
                "ip": r.ip,
            }
            for r in rows[:limit]
        ]
    return {"items": items, "next_before_id": items[-1]["id"] if len(rows) > limit else None}


@router.get("/health")
async def health_detail() -> dict:
    runtime = get_runtime()

    def check_database() -> tuple[bool, float | None, str | None]:
        started = time.perf_counter()
        try:
            with session_scope() as session:
                session.execute(text("SELECT 1"))
            return True, (time.perf_counter() - started) * 1000, None
        except Exception as exc:  # noqa: BLE001
            return False, None, exc.__class__.__name__

    db_ok, db_ms, db_error = await asyncio.to_thread(check_database)

    upstream_ok = False
    upstream_ms = None
    upstream_status = None
    upstream_error = None
    if runtime.client is not None:
        started = time.perf_counter()
        try:
            response = await runtime.client.get(
                runtime.settings.upstream_url + "/", headers={"x-waf-secret": runtime.settings.waf_shared_secret}, timeout=10
            )
            upstream_status = response.status_code
            upstream_ok = response.status_code < 500
            upstream_ms = (time.perf_counter() - started) * 1000
        except Exception as exc:  # noqa: BLE001
            upstream_error = exc.__class__.__name__

    writer = runtime.writer
    healthy = db_ok and upstream_ok and runtime.model is not None
    return {
        "status": "healthy" if healthy else "degraded",
        "uptime_seconds": round(time.time() - runtime.started_at),
        "environment": runtime.settings.waf_env,
        "mode": runtime.config.mode,
        "requests_since_start": runtime.requests_total,
        "database": {"ok": db_ok, "latency_ms": db_ms, "error": db_error},
        "upstream": {
            "ok": upstream_ok,
            "url": runtime.settings.upstream_url,
            "status": upstream_status,
            "latency_ms": upstream_ms,
            "error": upstream_error,
        },
        "ml": {"loaded": runtime.model is not None, "enabled": runtime.config.ml_enabled, "error": runtime.model_error, "failures": runtime.ml_errors},
        "log_writer": {
            "pending": writer.pending,
            "written": writer.stats.written,
            "dropped": writer.stats.dropped,
            "failures": writer.stats.failures,
            "last_error": writer.stats.last_error,
        },
        "inspection_errors": runtime.inspection_errors,
        "upstream_errors": runtime.upstream_errors,
        "active_bans": runtime.bans.count(),
    }
