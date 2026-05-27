from datetime import datetime, timezone
from typing import Optional

from .db import cursor

PROTOCOLS = ("tcp", "udp")


class ServiceValidationError(ValueError):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _validate(name: str, upstream_host: str, protocol: str,
              external_port: int, target_port: int) -> None:
    if not name or not name.strip():
        raise ServiceValidationError("name is required")
    if not upstream_host or not upstream_host.strip():
        raise ServiceValidationError("upstream_host is required")
    if protocol not in PROTOCOLS:
        raise ServiceValidationError("protocol must be 'tcp' or 'udp'")
    for label, port in (("external_port", external_port), ("target_port", target_port)):
        if not (1 <= port <= 65535):
            raise ServiceValidationError(f"{label} must be between 1 and 65535")


def list_services() -> list[dict]:
    with cursor() as cur:
        rows = cur.execute(
            "SELECT * FROM services ORDER BY id"
        ).fetchall()
        return [_row_to_dict(r) for r in rows]


def list_enabled_services() -> list[dict]:
    with cursor() as cur:
        rows = cur.execute(
            "SELECT * FROM services WHERE enabled = 1 ORDER BY id"
        ).fetchall()
        return [_row_to_dict(r) for r in rows]


def get_service(service_id: int) -> Optional[dict]:
    with cursor() as cur:
        row = cur.execute(
            "SELECT * FROM services WHERE id = ?", (service_id,)
        ).fetchone()
        return _row_to_dict(row) if row else None


def create_service(name: str, upstream_host: str, protocol: str,
                   external_port: int, target_port: int, enabled: bool) -> dict:
    name = name.strip()
    upstream_host = upstream_host.strip()
    _validate(name, upstream_host, protocol, external_port, target_port)
    now = _now()
    with cursor() as cur:
        try:
            cur.execute(
                "INSERT INTO services "
                "(name, upstream_host, protocol, external_port, target_port, "
                " enabled, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (name, upstream_host, protocol, external_port, target_port,
                 int(enabled), now, now),
            )
        except Exception as e:
            raise _conflict(e, name, protocol, external_port)
        service_id = cur.lastrowid
    return get_service(service_id)  # type: ignore[return-value]


def update_service(service_id: int, **fields) -> Optional[dict]:
    existing = get_service(service_id)
    if not existing:
        return None
    merged = {**existing, **{k: v for k, v in fields.items() if v is not None}}
    name = str(merged["name"]).strip()
    upstream_host = str(merged["upstream_host"]).strip()
    _validate(name, upstream_host, merged["protocol"],
              int(merged["external_port"]), int(merged["target_port"]))
    with cursor() as cur:
        try:
            cur.execute(
                "UPDATE services SET name = ?, upstream_host = ?, protocol = ?, "
                "external_port = ?, target_port = ?, enabled = ?, updated_at = ? "
                "WHERE id = ?",
                (name, upstream_host, merged["protocol"], int(merged["external_port"]),
                 int(merged["target_port"]), int(bool(merged["enabled"])), _now(),
                 service_id),
            )
        except Exception as e:
            raise _conflict(e, name, merged["protocol"], int(merged["external_port"]))
    return get_service(service_id)


def delete_service(service_id: int) -> bool:
    with cursor() as cur:
        cur.execute("DELETE FROM services WHERE id = ?", (service_id,))
        return cur.rowcount > 0


def _conflict(e: Exception, name: str, protocol: str, external_port: int):
    msg = str(e)
    if "UNIQUE" not in msg:
        return e
    if "services.name" in msg:
        return ServiceValidationError(f"a service named '{name}' already exists")
    return ServiceValidationError(
        f"{protocol}/{external_port} is already used by another service"
    )


def _row_to_dict(row) -> dict:
    return {
        "id": row["id"],
        "name": row["name"],
        "upstream_host": row["upstream_host"],
        "protocol": row["protocol"],
        "external_port": row["external_port"],
        "target_port": row["target_port"],
        "enabled": bool(row["enabled"]),
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }
