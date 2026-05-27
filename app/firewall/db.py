import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from .config import settings

SCHEMA = """
CREATE TABLE IF NOT EXISTS admin (
    id            INTEGER PRIMARY KEY CHECK (id = 1),
    password_hash TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS services (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL UNIQUE,
    upstream_host TEXT NOT NULL,
    protocol      TEXT NOT NULL CHECK (protocol IN ('tcp', 'udp')),
    external_port INTEGER NOT NULL,
    target_port   INTEGER NOT NULL,
    enabled       INTEGER NOT NULL DEFAULT 1,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    UNIQUE (protocol, external_port)
);

CREATE TABLE IF NOT EXISTS ip_entries (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    service_id INTEGER NOT NULL REFERENCES services(id) ON DELETE CASCADE,
    value      TEXT NOT NULL,
    label      TEXT,
    enabled    INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (service_id, value)
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
    _migrate_legacy_ip_entries()


def _migrate_legacy_ip_entries() -> None:
    """Upgrade a pre-multi-service DB.

    The old `ip_entries` had a globally-unique `value` and no `service_id`.
    Per-service allowlists need `UNIQUE(service_id, value)`, so rebuild the
    table. Any existing rows are parked under a disabled "legacy-default"
    service the admin can edit and enable from the UI — disabled so it emits
    no nginx server block (and can't break a reload) until reviewed.
    """
    with cursor() as cur:
        cols = [r["name"] for r in cur.execute("PRAGMA table_info(ip_entries)")]
        if not cols or "service_id" in cols:
            return  # fresh install (already new schema) or nothing to migrate

        rows = cur.execute(
            "SELECT id, value, label, enabled, created_at, updated_at FROM ip_entries"
        ).fetchall()

        cur.execute("PRAGMA foreign_keys = OFF")
        default_service_id = _create_legacy_service(cur) if rows else None
        cur.executescript(
            """
            DROP TABLE ip_entries;
            CREATE TABLE ip_entries (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                service_id INTEGER NOT NULL REFERENCES services(id) ON DELETE CASCADE,
                value      TEXT NOT NULL,
                label      TEXT,
                enabled    INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE (service_id, value)
            );
            """
        )
        for r in rows:
            cur.execute(
                "INSERT INTO ip_entries "
                "(id, service_id, value, label, enabled, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    r["id"],
                    default_service_id,
                    r["value"],
                    r["label"],
                    r["enabled"],
                    r["created_at"],
                    r["updated_at"],
                ),
            )
        cur.execute("PRAGMA foreign_keys = ON")


def _create_legacy_service(cur) -> int:
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    host = os.environ.get("UPSTREAM_HOST", "127.0.0.1")
    external = int(os.environ.get("EXTERNAL_TCP", os.environ.get("TARGET_TCP", "0")) or 0)
    target = int(os.environ.get("TARGET_TCP", os.environ.get("EXTERNAL_TCP", "0")) or 0)
    cur.execute(
        "INSERT INTO services "
        "(name, upstream_host, protocol, external_port, target_port, enabled, "
        " created_at, updated_at) "
        "VALUES (?, ?, 'tcp', ?, ?, 0, ?, ?)",
        ("legacy-default", host, external, target, now, now),
    )
    return cur.lastrowid
