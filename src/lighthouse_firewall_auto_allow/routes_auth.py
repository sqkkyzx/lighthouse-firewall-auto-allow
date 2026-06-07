from __future__ import annotations

from authlib.integrations.starlette_client import OAuth
from fastapi import APIRouter, Depends
from starlette.requests import Request
from starlette.responses import RedirectResponse

from lighthouse_firewall_auto_allow.config import Settings, get_settings

router = APIRouter()


def configure_oauth(app, settings: Settings) -> None:
    oauth = OAuth()
    if settings.oidc_enabled:
        oauth.register(
            name="oidc",
            client_id=settings.oidc_client_id,
            client_secret=settings.oidc_client_secret,
            server_metadata_url=settings.oidc_discovery_url,
            client_kwargs={"scope": "openid profile email"},
        )
    app.state.oauth = oauth


@router.get("/login")
async def login(request: Request, settings: Settings = Depends(get_settings)):
    if not settings.oidc_enabled:
        request.session["user"] = {"email": "dev-admin", "name": "dev-admin"}
        return RedirectResponse("/", status_code=303)
    redirect_uri = f"{settings.public_base_url.rstrip('/')}/auth/callback"
    return await request.app.state.oauth.oidc.authorize_redirect(request, redirect_uri)


@router.get("/auth/callback")
async def auth_callback(request: Request, settings: Settings = Depends(get_settings)):
    if not settings.oidc_enabled:
        return RedirectResponse("/", status_code=303)

    token = await request.app.state.oauth.oidc.authorize_access_token(request)
    userinfo = token.get("userinfo")
    if userinfo is None:
        userinfo = await request.app.state.oauth.oidc.userinfo(token=token)
    request.session["user"] = dict(userinfo)
    return RedirectResponse("/", status_code=303)


@router.post("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=303)
