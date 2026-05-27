import ipaddress
from datetime import datetime, timezone
from typing import Optional

from .db import cursor


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class IPValidationError(ValueError):
    pass


def normalize(value: str) -> str:
    """Validate + normalize an IP or CIDR.

    Bare IPs are kept as `1.2.3.4`. CIDR ranges are normalized to network form
    (`10.0.0.5/24` -> `10.0.0.0/24`).
    """
    if not value or not value.strip():
        raise IPValidationError("value is required")
    raw = value.strip()
    try:
        if "/" in raw:
            net = ipaddress.ip_network(raw, strict=False)
            return str(net)
        return str(ipaddress.ip_address(raw))
    except ValueError as e:
        raise IPValidationError(str(e)) from e


_SELECT = (
    "SELECT e.id, e.service_id, e.value, e.label, e.enabled, "
    "e.created_at, e.updated_at, s.name AS service_name "
    "FROM ip_entries e JOIN services s ON s.id = e.service_id"
)


def list_entries(service_id: Optional[int] = None) -> list[dict]:
    with cursor() as cur:
        if service_id is None:
            rows = cur.execute(_SELECT + " ORDER BY e.service_id, e.id").fetchall()
        else:
            rows = cur.execute(
                _SELECT + " WHERE e.service_id = ? ORDER BY e.id", (service_id,)
            ).fetchall()
        return [_row_to_dict(r) for r in rows]


def list_enabled_values(service_id: int) -> list[str]:
    with cursor() as cur:
        rows = cur.execute(
            "SELECT value FROM ip_entries WHERE service_id = ? AND enabled = 1 "
            "ORDER BY id",
            (service_id,),
        ).fetchall()
        return [r["value"] for r in rows]


def get_entry(entry_id: int) -> Optional[dict]:
    with cursor() as cur:
        row = cur.execute(_SELECT + " WHERE e.id = ?", (entry_id,)).fetchone()
        return _row_to_dict(row) if row else None


def create_entry(service_id: int, value: str, label: Optional[str],
                 enabled: bool) -> dict:
    normalized = normalize(value)
    now = _now()
    with cursor() as cur:
        svc = cur.execute(
            "SELECT id FROM services WHERE id = ?", (service_id,)
        ).fetchone()
        if not svc:
            raise IPValidationError("service not found")
        try:
            cur.execute(
                "INSERT INTO ip_entries "
                "(service_id, value, label, enabled, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (service_id, normalized, label, int(enabled), now, now),
            )
        except Exception as e:
            if "UNIQUE" in str(e):
                raise IPValidationError(
                    f"{normalized} already exists for this service"
                ) from e
            raise
        entry_id = cur.lastrowid
    return get_entry(entry_id)  # type: ignore[return-value]


def update_entry(
    entry_id: int, label: Optional[str], enabled: Optional[bool]
) -> Optional[dict]:
    existing = get_entry(entry_id)
    if not existing:
        return None
    new_label = existing["label"] if label is None else label
    new_enabled = existing["enabled"] if enabled is None else enabled
    with cursor() as cur:
        cur.execute(
            "UPDATE ip_entries SET label = ?, enabled = ?, updated_at = ? WHERE id = ?",
            (new_label, int(new_enabled), _now(), entry_id),
        )
    return get_entry(entry_id)


def delete_entry(entry_id: int) -> bool:
    with cursor() as cur:
        cur.execute("DELETE FROM ip_entries WHERE id = ?", (entry_id,))
        return cur.rowcount > 0


def _row_to_dict(row) -> dict:
    return {
        "id": row["id"],
        "service_id": row["service_id"],
        "service_name": row["service_name"],
        "value": row["value"],
        "label": row["label"],
        "enabled": bool(row["enabled"]),
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }
