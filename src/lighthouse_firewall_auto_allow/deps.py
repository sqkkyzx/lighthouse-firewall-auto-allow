from __future__ import annotations

from fastapi import Depends
from starlette.requests import Request
from starlette.responses import RedirectResponse

from lighthouse_firewall_auto_allow.config import Settings, get_settings
from lighthouse_firewall_auto_allow.security import require_admin


def admin_actor_or_redirect(
    request: Request,
    settings: Settings = Depends(get_settings),
) -> str | RedirectResponse:
    return require_admin(request, settings)
