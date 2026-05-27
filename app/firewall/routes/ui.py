from pathlib import Path

from fastapi import APIRouter, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from ..auth import verify_admin_login

router = APIRouter()

BASE_DIR = Path(__file__).resolve().parent.parent.parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


def _is_logged_in(request: Request) -> bool:
    return bool(request.session.get("admin"))


@router.get("/", response_class=HTMLResponse)
def index(request: Request):
    if not _is_logged_in(request):
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse(
        "services.html", {"request": request, "active": "services"}
    )


@router.get("/ips", response_class=HTMLResponse)
def ips_page(request: Request):
    if not _is_logged_in(request):
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse("ips.html", {"request": request, "active": "ips"})


@router.get("/tokens", response_class=HTMLResponse)
def tokens_page(request: Request):
    if not _is_logged_in(request):
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse(
        "tokens.html", {"request": request, "active": "tokens"}
    )


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request, error: str | None = None):
    if _is_logged_in(request):
        return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse(
        "login.html", {"request": request, "error": error}
    )


@router.post("/login")
def login_submit(request: Request, password: str = Form(...)):
    if not verify_admin_login(password):
        return RedirectResponse(
            url="/login?error=invalid", status_code=status.HTTP_303_SEE_OTHER
        )
    request.session["admin"] = True
    return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/healthz")
def healthz():
    return {"ok": True}
