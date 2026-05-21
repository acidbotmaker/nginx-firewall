import logging
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from .auth import ensure_admin_password
from .config import settings
from .db import init_db
from .nginx import regenerate_allowlist
from .routes import api as api_routes
from .routes import ui as ui_routes

log = logging.getLogger("firewall")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

BASE_DIR = Path(__file__).resolve().parent.parent

app = FastAPI(title="nginx-firewall", docs_url=None, redoc_url=None)

if not settings.secret_key:
    raise RuntimeError("SECRET_KEY env var is required")

app.add_middleware(
    SessionMiddleware,
    secret_key=settings.secret_key,
    session_cookie="firewall_session",
    max_age=settings.session_max_age,
    same_site="lax",
    https_only=False,
)

app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")

app.include_router(api_routes.router)
app.include_router(ui_routes.router)


@app.on_event("startup")
def on_startup() -> None:
    init_db()
    new_pw = ensure_admin_password()
    if new_pw:
        log.warning("=" * 60)
        log.warning("Generated initial admin password: %s", new_pw)
        log.warning("Save it now. Reset later via the CLI if needed.")
        log.warning("=" * 60)
    try:
        regenerate_allowlist()
        log.info("Rebuilt nginx allowlist on startup")
    except Exception as e:
        log.warning("Could not write allowlist on startup: %s", e)
