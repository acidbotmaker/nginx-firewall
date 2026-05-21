import logging

from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import JSONResponse

from ..auth import AuthDep, verify_admin_login
from ..ips import (
    IPValidationError,
    create_entry,
    delete_entry,
    get_entry,
    list_entries,
    update_entry,
)
from ..models import (
    IPEntryCreate,
    IPEntryOut,
    IPEntryUpdate,
    LoginRequest,
    TokenCreate,
    TokenCreatedOut,
    TokenOut,
)
from ..nginx import regenerate_allowlist
from ..tokens import create_token, delete_token, list_tokens

log = logging.getLogger("firewall.api")
router = APIRouter(prefix="/api")


@router.post("/auth/login")
def login(payload: LoginRequest, request: Request):
    if not verify_admin_login(payload.password):
        raise HTTPException(status_code=401, detail="Invalid password")
    request.session["admin"] = True
    return {"ok": True}


@router.post("/auth/logout")
def logout(request: Request):
    request.session.clear()
    return {"ok": True}


@router.get("/me")
def me(request: Request, _: str = AuthDep):
    return {"authenticated": True, "via": _}


@router.get("/ips", response_model=list[IPEntryOut])
def ips_list(_: str = AuthDep):
    return list_entries()


@router.post("/ips", response_model=IPEntryOut, status_code=status.HTTP_201_CREATED)
def ips_create(payload: IPEntryCreate, _: str = AuthDep):
    try:
        entry = create_entry(payload.value, payload.label, payload.enabled)
    except IPValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    regenerate_allowlist()
    return entry


@router.put("/ips/{entry_id}", response_model=IPEntryOut)
def ips_update(entry_id: int, payload: IPEntryUpdate, _: str = AuthDep):
    entry = update_entry(entry_id, payload.label, payload.enabled)
    if not entry:
        raise HTTPException(status_code=404, detail="Not found")
    regenerate_allowlist()
    return entry


@router.delete("/ips/{entry_id}")
def ips_delete(entry_id: int, _: str = AuthDep):
    if not delete_entry(entry_id):
        raise HTTPException(status_code=404, detail="Not found")
    regenerate_allowlist()
    return {"ok": True}


@router.get("/tokens", response_model=list[TokenOut])
def tokens_list(_: str = AuthDep):
    return list_tokens()


@router.post("/tokens", response_model=TokenCreatedOut, status_code=status.HTTP_201_CREATED)
def tokens_create(payload: TokenCreate, _: str = AuthDep):
    token, row = create_token(payload.name)
    return {**row, "token": token}


@router.delete("/tokens/{token_id}")
def tokens_delete(token_id: int, _: str = AuthDep):
    if not delete_token(token_id):
        raise HTTPException(status_code=404, detail="Not found")
    return {"ok": True}


@router.post("/reload")
def force_reload(_: str = AuthDep):
    content = regenerate_allowlist()
    return JSONResponse({"ok": True, "bytes": len(content)})
