"""Hybrid WAF entry point: admin API under /__waf, and the reverse proxy for everything else."""
from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta

import httpx
from fastapi import APIRouter, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy import delete, select, text
from sqlalchemy.exc import OperationalError
from starlette.exceptions import HTTPException as StarletteHTTPException

from .api import auth_routes, data_routes, playground_routes, simulator_routes
from .db import session_scope
from .ml import model as model_lib
from .ml.model import ModelIntegrityError
from .ml.train import train_and_save
from .models import AdminUser, Incident, RequestLog
from .proxy.router import router as proxy_router
from .runtime import Runtime, get_runtime
from .security.auth import MIN_PASSWORD_LENGTH, hash_password
from .services.bans import load_active_bans
from .services.runtime_settings import load_settings

logger = logging.getLogger("waf")
API_PREFIX = "/__waf"
REFRESH_SECONDS = 30
RETENTION_INTERVAL_SECONDS = 6 * 60 * 60


def _bootstrap_admin(rt: Runtime) -> None:
    """Create the first admin from environment variables, only when no admin exists."""
    settings = rt.settings
    with session_scope() as session:
        if session.scalar(select(AdminUser.id).limit(1)) is not None:
            return
        password = settings.admin_password
        if not password or len(password) < MIN_PASSWORD_LENGTH:
            logger.warning("No admin exists and ADMIN_PASSWORD is missing or too short; login is unavailable.")
            return
        session.add(AdminUser(username=settings.admin_username, password_hash=hash_password(password)))
    logger.info("Created the first admin account.")


def _refresh_state(rt: Runtime) -> None:
    """Reload settings and bans. Failure keeps the last good values, so traffic isn't affected."""
    try:
        with session_scope() as session:
            session.execute(text("SELECT 1"))
        rt.config = load_settings()
        rt.bans.replace_all(load_active_bans())
        rt.db_ok, rt.db_error = True, None
    except Exception as exc:  # noqa: BLE001
        rt.db_ok, rt.db_error = False, exc.__class__.__name__
        logger.warning("Database unavailable: %s", exc.__class__.__name__)


def _purge_old_logs(rt: Runtime) -> None:
    """Delete logs past the retention period (data minimization)."""
    cutoff = datetime.now(UTC) - timedelta(days=rt.settings.log_retention_days)
    with session_scope() as session:
        session.execute(delete(RequestLog).where(RequestLog.created_at < cutoff))
        session.execute(delete(Incident).where(Incident.created_at < cutoff))


def _load_model(rt: Runtime) -> None:
    settings = rt.settings
    try:
        if not settings.model_path.exists():
            logger.info("No trained model found, training one now.")
            train_and_save(trained_by="startup")
        rt.model = model_lib.load(settings.model_path, settings.model_signing_key)
        rt.model_error = None
    except ModelIntegrityError as exc:
        # A tampered model isn't used. Signatures keep protecting the site.
        rt.model, rt.model_error = None, str(exc)
        logger.error("Model refused: %s", exc)
    except Exception as exc:  # noqa: BLE001
        rt.model, rt.model_error = None, exc.__class__.__name__
        logger.exception("Model could not be loaded")


async def _maintenance(rt: Runtime) -> None:
    elapsed = 0
    while True:
        await asyncio.sleep(REFRESH_SECONDS)
        elapsed += REFRESH_SECONDS
        await asyncio.to_thread(_refresh_state, rt)
        if elapsed >= RETENTION_INTERVAL_SECONDS:
            elapsed = 0
            try:
                await asyncio.to_thread(_purge_old_logs, rt)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Log cleanup failed: %s", exc.__class__.__name__)


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    rt = get_runtime()
    rt.client = httpx.AsyncClient(
        follow_redirects=False,
        timeout=httpx.Timeout(30.0, connect=10.0),
        limits=httpx.Limits(max_connections=200, max_keepalive_connections=50),
    )
    rt.writer.start()
    await asyncio.to_thread(_refresh_state, rt)
    if rt.db_ok:
        try:
            await asyncio.to_thread(_bootstrap_admin, rt)
            await asyncio.to_thread(_purge_old_logs, rt)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Startup database task failed: %s", exc.__class__.__name__)
    await asyncio.to_thread(_load_model, rt)
    task = asyncio.create_task(_maintenance(rt))
    try:
        yield
    finally:
        task.cancel()
        rt.writer.stop()
        await rt.client.aclose()


def create_app() -> FastAPI:
    # Interactive API docs stay off, so the admin API isn't advertised publicly.
    app = FastAPI(title="Hybrid WAF", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)

    @app.get(f"{API_PREFIX}/ping", include_in_schema=False)
    async def ping() -> dict:
        """Public liveness check for hosting platforms. Reveals nothing about the system."""
        return {"status": "ok"}

    api = APIRouter(prefix=f"{API_PREFIX}/api")
    api.include_router(auth_routes.router)
    api.include_router(data_routes.router)
    api.include_router(simulator_routes.router)
    api.include_router(playground_routes.router)
    app.include_router(api)

    @app.api_route(f"{API_PREFIX}/{{rest:path}}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"], include_in_schema=False)
    async def unknown_admin_route(rest: str) -> None:  # noqa: ARG001
        # The WAF's own namespace is never forwarded to the website.
        raise HTTPException(404, "Not found")

    @app.exception_handler(RequestValidationError)
    async def _validation_error(_request: Request, exc: RequestValidationError) -> JSONResponse:
        # Submitted values aren't echoed back, because they could contain passwords.
        problems = [{"field": ".".join(map(str, e["loc"][1:])), "message": e["msg"]} for e in exc.errors()]
        return JSONResponse({"detail": "Invalid request", "problems": problems}, status_code=422)

    @app.exception_handler(OperationalError)
    async def _database_down(_request: Request, _exc: OperationalError) -> JSONResponse:
        # Connection details stay in server logs, and never reach the client.
        return JSONResponse({"detail": "The database is temporarily unavailable"}, status_code=503)

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(_request: Request, exc: StarletteHTTPException) -> JSONResponse:
        return JSONResponse({"detail": exc.detail}, status_code=exc.status_code, headers=exc.headers)

    # Must stay last: it matches every remaining path.
    app.include_router(proxy_router)
    return app


app = create_app()


def run() -> None:
    import uvicorn

    settings = get_runtime().settings
    # proxy_headers stays off: the WAF resolves client IPs itself using TRUST_PROXY_HOPS.
    uvicorn.run(app, host=settings.waf_host, port=settings.waf_port, proxy_headers=False, server_header=False)


if __name__ == "__main__":
    run()
