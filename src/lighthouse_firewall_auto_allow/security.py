from __future__ import annotations

import hmac
import re
import secrets
from hashlib import sha256

from fastapi import HTTPException
from starlette.requests import Request
from starlette.responses import RedirectResponse

from lighthouse_firewall_auto_allow.config import Settings

CLIENT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{1,39}$")


def validate_client_id(client_id: str) -> str:
    if CLIENT_ID_RE.fullmatch(client_id) is None:
        raise ValueError("client_id must be 2-40 chars: letters, numbers, underscore or dash")
    if len(f"[AUTO] {client_id}") > 64:
        raise ValueError("client_id is too long for Tencent Cloud firewall description")
    return client_id


def generate_token() -> str:
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    return sha256(token.encode("utf-8")).hexdigest()


def verify_token(token: str, token_hash: str) -> bool:
    return hmac.compare_digest(hash_token(token), token_hash)


def require_admin(request: Request, settings: Settings) -> str | RedirectResponse:
    if not settings.oidc_enabled:
        return "dev-admin"

    user = request.session.get("user")
    if not isinstance(user, dict):
        return RedirectResponse("/login", status_code=303)

    email = str(user.get("email", "")).lower()
    if not email:
        raise HTTPException(status_code=403, detail="OIDC user has no email")
    if settings.admin_email_set and email not in settings.admin_email_set:
        raise HTTPException(status_code=403, detail="User is not an admin")
    return email


def bearer_token(authorization: str | None) -> str:
    if authorization is None or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    token = authorization.removeprefix("Bearer ").strip()
    if not token:
        raise HTTPException(status_code=401, detail="Missing bearer token")
    return token
