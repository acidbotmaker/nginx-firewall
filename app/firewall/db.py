import sqlite3
from contextlib import contextmanager
from pathlib import Path

from .config import settings

SCHEMA = """
CREATE TABLE IF NOT EXISTS admin (
    id            INTEGER PRIMARY KEY CHECK (id = 1),
    password_hash TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ip_entries (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    value      TEXT NOT NULL UNIQUE,
    label      TEXT,
    enabled    INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS api_tokens (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT NOT NULL,
    token_hash   TEXT NOT NULL UNIQUE,
    created_at   TEXT NOT NULL,
    last_used_at TEXT
);
"""


def _ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def connect() -> sqlite3.Connection:
    _ensure_parent(settings.db_path)
    conn = sqlite3.connect(settings.db_path, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


@contextmanager
def cursor():
    conn = connect()
    try:
        cur = conn.cursor()
        yield cur
    finally:
        conn.close()


def init_db() -> None:
    with cursor() as cur:
        cur.executescript(SCHEMA)
