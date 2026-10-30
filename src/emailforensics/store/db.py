from __future__ import annotations

from importlib import resources

import psycopg
from psycopg import sql


def connect(dsn: str) -> psycopg.Connection:
    return psycopg.connect(dsn, autocommit=True)


def create_database(admin_dsn: str, name: str) -> None:
    with connect(admin_dsn) as conn:
        exists = conn.execute("SELECT 1 FROM pg_database WHERE datname = %s", (name,)).fetchone()
        if exists:
            raise FileExistsError(f"database {name!r} already exists; refusing to reuse it")
        conn.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))


def drop_database(admin_dsn: str, name: str) -> None:
    with connect(admin_dsn) as conn:
        conn.execute(sql.SQL("DROP DATABASE IF EXISTS {}").format(sql.Identifier(name)))


def _migrations() -> list[tuple[str, str]]:
    folder = resources.files("emailforensics.store").joinpath("migrations")
    files = sorted((f for f in folder.iterdir() if f.name.endswith(".sql")), key=lambda f: f.name)
    return [(f.name.removesuffix(".sql"), f.read_text(encoding="utf-8")) for f in files]


def migrate(conn: psycopg.Connection) -> list[str]:
    conn.execute(
        "CREATE TABLE IF NOT EXISTS schema_migration ("
        " version text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())"
    )
    done = {r[0] for r in conn.execute("SELECT version FROM schema_migration")}
    applied = []
    for version, text in _migrations():
        if version in done:
            continue
        with conn.transaction():
            conn.execute(text)
            conn.execute("INSERT INTO schema_migration (version) VALUES (%s)", (version,))
        applied.append(version)
    return applied
