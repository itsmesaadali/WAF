"""Prisma owns the tables. This fails when the Python models stop matching them."""
from __future__ import annotations

import psycopg
import pytest

from app.models import Base

from .conftest import SCHEMA

TYPE_GROUPS = {
    "INTEGER": "integer",
    "BIGINTEGER": "bigint",
    "TEXT": "text",
    "BOOLEAN": "boolean",
    "DOUBLE": "double precision",
    "JSONB": "jsonb",
    "TIMESTAMP": "timestamp with time zone",
    "DATETIME": "timestamp with time zone",
    "VARCHAR": "character varying",
}


def _sql_type(column) -> str:  # noqa: ANN001
    name = column.type.__class__.__name__.upper()
    return TYPE_GROUPS["VARCHAR" if name == "STRING" else name]


@pytest.mark.parametrize("table", list(Base.metadata.tables.values()), ids=lambda t: t.name)
def test_python_model_matches_prisma_table(database_url: str, table) -> None:  # noqa: ANN001
    with psycopg.connect(database_url) as connection:
        rows = connection.execute(
            "SELECT column_name, data_type FROM information_schema.columns WHERE table_schema=%s AND table_name=%s",
            (SCHEMA, table.name),
        ).fetchall()
    actual = dict(rows)
    expected = {column.name: _sql_type(column) for column in table.columns}
    assert actual == expected
