import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import JSONResponse

from ..auth import AuthDep, verify_admin_login
from ..ips import (
    IPValidationError,
    create_entry,
    delete_entry,
    list_entries,
    update_entry,
)
from ..models import (
    IPEntryCreate,
    IPEntryOut,
    IPEntryUpdate,
    LoginRequest,
    ServiceCreate,
    ServiceOut,
    ServiceUpdate,
    TokenCreate,
    TokenCreatedOut,
    TokenOut,
)
from ..nginx import regenerate
from ..services import (
    ServiceValidationError,
    create_service,
    delete_service,
    list_services,
    update_service,
)
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


# --- Services -------------------------------------------------------------

@router.get("/services", response_model=list[ServiceOut])
def services_list(_: str = AuthDep):
    return list_services()


@router.post("/services", response_model=ServiceOut, status_code=status.HTTP_201_CREATED)
def services_create(payload: ServiceCreate, _: str = AuthDep):
    try:
        svc = create_service(
            payload.name, payload.upstream_host, payload.protocol,
            payload.external_port, payload.target_port, payload.enabled,
        )
    except ServiceValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    regenerate()
    return svc


@router.put("/services/{service_id}", response_model=ServiceOut)
def services_update(service_id: int, payload: ServiceUpdate, _: str = AuthDep):
    try:
        svc = update_service(service_id, **payload.model_dump(exclude_unset=True))
    except ServiceValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    if not svc:
        raise HTTPException(status_code=404, detail="Not found")
    regenerate()
    return svc


@router.delete("/services/{service_id}")
def services_delete(service_id: int, _: str = AuthDep):
    if not delete_service(service_id):
        raise HTTPException(status_code=404, detail="Not found")
    regenerate()
    return {"ok": True}


# --- IP allowlist (per service) -------------------------------------------

@router.get("/ips", response_model=list[IPEntryOut])
def ips_list(service_id: Optional[int] = None, _: str = AuthDep):
    return list_entries(service_id)


@router.post("/ips", response_model=IPEntryOut, status_code=status.HTTP_201_CREATED)
def ips_create(payload: IPEntryCreate, _: str = AuthDep):
    try:
        entry = create_entry(
            payload.service_id, payload.value, payload.label, payload.enabled
        )
    except IPValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    regenerate()
    return entry


@router.put("/ips/{entry_id}", response_model=IPEntryOut)
def ips_update(entry_id: int, payload: IPEntryUpdate, _: str = AuthDep):
    entry = update_entry(entry_id, payload.label, payload.enabled)
    if not entry:
        raise HTTPException(status_code=404, detail="Not found")
    regenerate()
    return entry


@router.delete("/ips/{entry_id}")
def ips_delete(entry_id: int, _: str = AuthDep):
    if not delete_entry(entry_id):
        raise HTTPException(status_code=404, detail="Not found")
    regenerate()
    return {"ok": True}


# --- Tokens ---------------------------------------------------------------

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
    content = regenerate()
    return JSONResponse({"ok": True, "bytes": len(content)})
