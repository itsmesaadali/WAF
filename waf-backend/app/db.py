"""Database connection. Calls are synchronous and run on worker threads, never the proxy loop."""
from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from functools import lru_cache

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from .config import get_settings


@lru_cache
def get_engine() -> Engine:
    settings = get_settings()
    engine = create_engine(
        settings.sqlalchemy_url,
        pool_size=5,
        max_overflow=5,
        pool_pre_ping=True,
        pool_recycle=240,  # Neon closes idle connections when the compute sleeps.
        # The Neon pooler runs PgBouncer, so server-side prepared statements stay off.
        connect_args={"prepare_threshold": None, "connect_timeout": 15},
    )
    if settings.database_schema:
        schema = settings.database_schema
        if not schema.isidentifier():
            raise ValueError("DATABASE_SCHEMA must be a simple name")

        @event.listens_for(engine, "connect")
        def _set_search_path(dbapi_connection, _record):  # noqa: ANN001
            autocommit = dbapi_connection.autocommit
            dbapi_connection.autocommit = True
            with dbapi_connection.cursor() as cursor:
                cursor.execute(f'SET search_path TO "{schema}"')
            dbapi_connection.autocommit = autocommit

    return engine


@lru_cache
def _session_factory() -> sessionmaker[Session]:
    return sessionmaker(bind=get_engine(), expire_on_commit=False)


@contextmanager
def session_scope() -> Iterator[Session]:
    session = _session_factory()()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
