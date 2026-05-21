from datetime import datetime, timezone
from typing import Optional

from .auth import generate_token, hash_token
from .db import cursor


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def list_tokens() -> list[dict]:
    with cursor() as cur:
        rows = cur.execute(
            "SELECT id, name, created_at, last_used_at FROM api_tokens ORDER BY id"
        ).fetchall()
        return [dict(r) for r in rows]


def create_token(name: str) -> tuple[str, dict]:
    token = generate_token()
    th = hash_token(token)
    now = _now()
    with cursor() as cur:
        cur.execute(
            "INSERT INTO api_tokens (name, token_hash, created_at) VALUES (?, ?, ?)",
            (name, th, now),
        )
        tid = cur.lastrowid
        row = cur.execute(
            "SELECT id, name, created_at, last_used_at FROM api_tokens WHERE id = ?",
            (tid,),
        ).fetchone()
    return token, dict(row)


def delete_token(token_id: int) -> bool:
    with cursor() as cur:
        cur.execute("DELETE FROM api_tokens WHERE id = ?", (token_id,))
        return cur.rowcount > 0


def get_token(token_id: int) -> Optional[dict]:
    with cursor() as cur:
        row = cur.execute(
            "SELECT id, name, created_at, last_used_at FROM api_tokens WHERE id = ?",
            (token_id,),
        ).fetchone()
        return dict(row) if row else None
