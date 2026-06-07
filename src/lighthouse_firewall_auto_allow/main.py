from __future__ import annotations

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from lighthouse_firewall_auto_allow.config import get_settings
from lighthouse_firewall_auto_allow.database import create_db_and_tables
from lighthouse_firewall_auto_allow.routes_api import router as api_router
from lighthouse_firewall_auto_allow.routes_auth import configure_oauth
from lighthouse_firewall_auto_allow.routes_auth import router as auth_router
from lighthouse_firewall_auto_allow.routes_web import router as web_router


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(title="Lighthouse Firewall Auto Allow")
    app.add_middleware(
        SessionMiddleware,
        secret_key=settings.app_secret_key,
        same_site="lax",
        https_only=settings.public_base_url.startswith("https://"),
    )
    app.mount(
        "/static",
        StaticFiles(packages=[("lighthouse_firewall_auto_allow", "static")]),
        name="static",
    )
    configure_oauth(app, settings)
    app.include_router(auth_router)
    app.include_router(api_router)
    app.include_router(web_router)

    @app.on_event("startup")
    def startup() -> None:
        create_db_and_tables()

    return app


app = create_app()
