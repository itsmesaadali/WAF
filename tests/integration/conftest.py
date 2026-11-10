"""Starts the real website and WAF as separate processes, using a separate database schema.

Nothing is mocked: requests travel over real HTTP, and rows are written to real PostgreSQL.
TRUST_PROXY_HOPS=1 lets each test act as a different visitor by setting X-Forwarded-For.
"""
from __future__ import annotations

import itertools
import os
import secrets
import shutil
import subprocess
import sys
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx
import psycopg
import pytest
from dotenv import dotenv_values

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = "waf_test"
SITE_PORT = 3100
WAF_PORT = 8100
SITE_URL = f"http://127.0.0.1:{SITE_PORT}"
WAF_URL = f"http://127.0.0.1:{WAF_PORT}"
API = "/__waf/api"
TABLES = ("admin_users", "request_logs", "incidents", "ip_bans", "audit_logs", "settings", "ml_model_runs")
ADMIN_USER = "testadmin"
ADMIN_PASSWORD = secrets.token_urlsafe(24)
SHARED_SECRET = secrets.token_urlsafe(32)
_ip_counter = itertools.count(1)


def _with_schema(url: str) -> str:
    parts = urlsplit(url)
    # Prisma's engine doesn't need channel_binding, which it can reject on some versions.
    query = [(k, v) for k, v in parse_qsl(parts.query) if k != "channel_binding"]
    query.append(("schema", SCHEMA))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), ""))


def _direct_url() -> str:
    env = dotenv_values(ROOT / ".env")
    url = env.get("DATABASE_URL_UNPOOLED") or env.get("DATABASE_URL")
    if not url or "USER:PASSWORD" in url:
        pytest.skip("No database is configured in .env")
    return url


def wait_until_up(url: str, process: subprocess.Popen, timeout: float = 90) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"process for {url} exited with code {process.returncode}")
        try:
            httpx.get(url, timeout=2)
            return
        except httpx.HTTPError:
            time.sleep(0.25)
    raise TimeoutError(f"{url} didn't start in time")


@pytest.fixture(scope="session")
def database_url() -> str:
    url = _direct_url()
    pnpm = shutil.which("pnpm")
    assert pnpm, "pnpm is required to run Prisma migrations"
    env = {**os.environ, "DATABASE_URL_UNPOOLED": _with_schema(url)}
    done = subprocess.run([pnpm, "exec", "prisma", "migrate", "deploy"], cwd=ROOT, env=env, capture_output=True, text=True)
    assert done.returncode == 0, f"migration failed:\n{done.stdout[-1500:]}\n{done.stderr[-1500:]}"
    with psycopg.connect(url, autocommit=True) as connection:
        tables = ", ".join(f'"{SCHEMA}"."{t}"' for t in TABLES)
        connection.execute(f"TRUNCATE {tables} RESTART IDENTITY CASCADE")
    return url


@pytest.fixture()
def db(database_url: str) -> Iterator[psycopg.Connection]:
    with psycopg.connect(database_url, autocommit=True) as connection:
        connection.execute(f'SET search_path TO "{SCHEMA}"')
        yield connection


@pytest.fixture(scope="session")
def site() -> Iterator[str]:
    env = {**os.environ, "WAF_SHARED_SECRET": SHARED_SECRET, "SITE_HOST": "127.0.0.1", "SITE_PORT": str(SITE_PORT), "PORT": str(SITE_PORT)}
    process = subprocess.Popen(["node", "src/server.js"], cwd=ROOT / "protected-site", env=env, stdout=subprocess.DEVNULL)
    try:
        wait_until_up(SITE_URL, process)
        yield SITE_URL
    finally:
        process.terminate()
        process.wait(10)


@pytest.fixture(scope="session")
def waf_factory(database_url: str, tmp_path_factory: pytest.TempPathFactory) -> Iterator[Callable[..., subprocess.Popen]]:
    """Start extra WAF processes, for example one with an unreachable website."""
    started: list[subprocess.Popen] = []
    model_path = tmp_path_factory.mktemp("model") / "iforest.joblib"
    jwt_secret = secrets.token_urlsafe(32)
    signing_key = secrets.token_urlsafe(32)

    def start(port: int, upstream: str = SITE_URL, **extra: str) -> subprocess.Popen:
        env = {
            **os.environ,
            "PYTHONPATH": str(ROOT / "waf-backend"),
            "WAF_ENV": "test",
            "DATABASE_URL": database_url,
            "DATABASE_SCHEMA": SCHEMA,
            "UPSTREAM_URL": upstream,
            "WAF_SHARED_SECRET": SHARED_SECRET,
            "JWT_SECRET": jwt_secret,
            "MODEL_SIGNING_KEY": signing_key,
            "MODEL_PATH": str(model_path),
            "ADMIN_USERNAME": ADMIN_USER,
            "ADMIN_PASSWORD": ADMIN_PASSWORD,
            "WAF_HOST": "127.0.0.1",
            "WAF_PORT": str(port),
            "TRUST_PROXY_HOPS": "1",
            "FAIL_MODE": "closed",
            "MAX_BODY_BYTES": "65536",
            **extra,
        }
        process = subprocess.Popen([sys.executable, "-m", "app.main"], cwd=ROOT / "waf-backend", env=env, stdout=subprocess.DEVNULL)
        started.append(process)
        wait_until_up(f"http://127.0.0.1:{port}/__waf/ping", process)
        return process

    yield start
    for process in started:
        process.terminate()
    for process in started:
        process.wait(15)


@pytest.fixture(scope="session")
def waf(site: str, waf_factory: Callable[..., subprocess.Popen]) -> str:  # noqa: ARG001
    waf_factory(WAF_PORT)
    return WAF_URL


@pytest.fixture()
def client(waf: str) -> Iterator[httpx.Client]:
    with httpx.Client(base_url=waf, timeout=45) as http:
        yield http


@pytest.fixture()
def admin_headers(waf: str) -> dict[str, str]:
    # A new login per test, because the logout test cancels earlier tokens. Each uses its
    # own IP, so test logins don't trigger the login rate limit.
    response = httpx.post(
        f"{waf}{API}/auth/login",
        json={"username": ADMIN_USER, "password": ADMIN_PASSWORD},
        headers={"x-forwarded-for": f"192.0.2.{next(_ip_counter) % 250 + 1}"},
        timeout=45,
    )
    assert response.status_code == 200, response.text
    return {"authorization": f"Bearer {response.json()['access_token']}"}


@pytest.fixture()
def visitor() -> dict[str, str]:
    """Headers for a new visitor, each with its own IP so tests don't interfere."""
    return {"x-forwarded-for": f"198.51.{next(_ip_counter) // 250}.{next(_ip_counter) % 250 + 1}", "user-agent": "pytest-visitor", "accept": "*/*"}


def wait_for(check: Callable[[], object], timeout: float = 40.0, interval: float = 0.25) -> object:
    """Logs are written in the background, so results appear shortly after a request."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = check()
        if value:
            return value
        time.sleep(interval)
    return check()
