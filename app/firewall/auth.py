import hashlib
import secrets
from datetime import datetime, timezone
from typing import Optional

import bcrypt
from fastapi import Depends, HTTPException, Request, status

from .db import cursor


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
    except ValueError:
        return False


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def generate_token() -> str:
    return secrets.token_urlsafe(32)


def get_admin_hash() -> Optional[str]:
    with cursor() as cur:
        row = cur.execute("SELECT password_hash FROM admin WHERE id = 1").fetchone()
        return row["password_hash"] if row else None


def set_admin_password(password: str) -> None:
    h = hash_password(password)
    now = _now()
    with cursor() as cur:
        cur.execute(
            """
            INSERT INTO admin (id, password_hash, updated_at) VALUES (1, ?, ?)
            ON CONFLICT(id) DO UPDATE SET password_hash = excluded.password_hash,
                                          updated_at = excluded.updated_at
            """,
            (h, now),
        )


def ensure_admin_password() -> Optional[str]:
    """Create an admin row with a random password if none exists.

    Returns the plaintext password if one was just generated, else None.
    """
    if get_admin_hash() is not None:
        return None
    pw = secrets.token_urlsafe(16)
    set_admin_password(pw)
    return pw


def verify_admin_login(password: str) -> bool:
    h = get_admin_hash()
    return bool(h) and verify_password(password, h)


def _bearer_token(request: Request) -> Optional[str]:
    auth = request.headers.get("authorization") or request.headers.get("Authorization")
    if not auth:
        return None
    parts = auth.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    return parts[1].strip() or None


def _verify_token(token: str) -> bool:
    th = hash_token(token)
    with cursor() as cur:
        row = cur.execute(
            "SELECT id FROM api_tokens WHERE token_hash = ?", (th,)
        ).fetchone()
        if not row:
            return False
        cur.execute(
            "UPDATE api_tokens SET last_used_at = ? WHERE id = ?", (_now(), row["id"])
        )
        return True


def require_auth(request: Request) -> str:
    """Allow either an authenticated session or a valid bearer token."""
    if request.session.get("admin"):
        return "session"
    tok = _bearer_token(request)
    if tok and _verify_token(tok):
        return "token"
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required",
        headers={"WWW-Authenticate": "Bearer"},
    )


def require_session(request: Request) -> None:
    """Stricter dependency: UI-only actions (e.g. login/logout pages)."""
    if not request.session.get("admin"):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)


AuthDep = Depends(require_auth)
SessionDep = Depends(require_session)
