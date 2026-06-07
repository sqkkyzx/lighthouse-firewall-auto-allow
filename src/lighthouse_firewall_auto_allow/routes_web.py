from __future__ import annotations

from fastapi import APIRouter, Depends, Form, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response

from lighthouse_firewall_auto_allow.agent_scripts import (
    generate_agent_script,
    install_command_for_client,
    script_url_for_client,
    uninstall_command_for_client,
)
from lighthouse_firewall_auto_allow.config import Settings, get_settings
from lighthouse_firewall_auto_allow.database import get_db
from lighthouse_firewall_auto_allow.deps import admin_actor_or_redirect
from lighthouse_firewall_auto_allow.models import AuditLog, Client, Target
from lighthouse_firewall_auto_allow.reconcile import (
    reconcile_client_firewall,
    remove_client_firewall_rules,
)
from lighthouse_firewall_auto_allow.rules import (
    normalize_ip_mode,
    normalize_port,
    normalize_protocol,
)
from lighthouse_firewall_auto_allow.security import (
    generate_token,
    hash_token,
    validate_client_id,
    verify_token,
)
from lighthouse_firewall_auto_allow.templating import templates
from lighthouse_firewall_auto_allow.tencent import TencentLighthouseFirewallGateway

router = APIRouter()


@router.get("/", response_class=HTMLResponse)
def index(
    request: Request,
    db: Session = Depends(get_db),
    actor: str | RedirectResponse = Depends(admin_actor_or_redirect),
):
    if isinstance(actor, RedirectResponse):
        return actor
    show_deleted = request.query_params.get("show_deleted") == "1"
    all_clients = db.scalars(select(Client).order_by(Client.id)).all()
    visible_clients = (
        all_clients
        if show_deleted
        else [c for c in all_clients if c.status != "deleted"]
    )
    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "actor": actor,
            "clients": visible_clients,
            "all_clients": all_clients,
            "show_deleted": show_deleted,
            "targets": db.scalars(select(Target).order_by(Target.region, Target.instance_id)).all(),
        },
    )


@router.get("/targets", response_class=HTMLResponse)
def targets(
    request: Request,
    db: Session = Depends(get_db),
    actor: str | RedirectResponse = Depends(admin_actor_or_redirect),
):
    if isinstance(actor, RedirectResponse):
        return actor
    return templates.TemplateResponse(
        request,
        "targets.html",
        {"actor": actor, "targets": db.scalars(select(Target).order_by(Target.id)).all()},
    )


@router.post("/targets")
def create_target(
    region: str = Form(...),
    instance_id: str = Form(...),
    alias: str = Form(""),
    db: Session = Depends(get_db),
    actor: str | RedirectResponse = Depends(admin_actor_or_redirect),
):
    if isinstance(actor, RedirectResponse):
        return actor
    target = Target(
        region=region.strip(),
        instance_id=instance_id.strip(),
        alias=alias.strip() or instance_id.strip(),
    )
    db.add(target)
    _audit(
        db,
        actor=actor,
        action="create_target",
        subject=target.instance_id,
        detail=target.region,
    )
    db.commit()
    return RedirectResponse("/targets", status_code=303)


@router.post("/targets/{target_id}/toggle")
def toggle_target(
    target_id: int,
    db: Session = Depends(get_db),
    actor: str | RedirectResponse = Depends(admin_actor_or_redirect),
):
    if isinstance(actor, RedirectResponse):
        return actor
    target = db.get(Target, target_id)
    if target is None:
        raise HTTPException(status_code=404)
    target.enabled = not target.enabled
    _audit(
        db,
        actor=actor,
        action="toggle_target",
        subject=target.instance_id,
        detail=str(target.enabled),
    )
    db.commit()
    return RedirectResponse("/targets", status_code=303)


@router.get("/clients/new", response_class=HTMLResponse)
def new_client(
    request: Request,
    db: Session = Depends(get_db),
    actor: str | RedirectResponse = Depends(admin_actor_or_redirect),
):
    if isinstance(actor, RedirectResponse):
        return actor
    return templates.TemplateResponse(
        request,
        "client_form.html",
        {"actor": actor, "targets": db.scalars(select(Target).order_by(Target.id)).all()},
    )


@router.post("/clients")
async def create_client(
    request: Request,
    client_id: str = Form(...),
    platform: str = Form(...),
    frequency_minutes: int = Form(...),
    ip_mode: str = Form(...),
    allow_ipv6_prefix: str | None = Form(None),
    protocol: str = Form(...),
    port: str = Form(...),
    generate_install: str | None = Form(None),
    db: Session = Depends(get_db),
    actor: str | RedirectResponse = Depends(admin_actor_or_redirect),
):
    if isinstance(actor, RedirectResponse):
        return actor

    form = await request.form()
    target_ids = [int(item) for item in form.getlist("target_ids")]
    try:
        normalized_id = validate_client_id(client_id.strip())
        normalized_protocol = normalize_protocol(protocol)
        normalized_port = normalize_port(normalized_protocol, port)
        normalized_ip_mode = normalize_ip_mode(ip_mode)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e)) from e

    if db.get(Client, normalized_id) is not None:
        raise HTTPException(status_code=409, detail="client_id already exists")

    token = generate_token()
    client = Client(
        id=normalized_id,
        token_hash=hash_token(token),
        platform=platform,
        frequency_minutes=max(frequency_minutes, 1),
        ip_mode=normalized_ip_mode,
        allow_ipv6_prefix=allow_ipv6_prefix == "1",
        protocol=normalized_protocol,
        port=normalized_port,
    )
    if target_ids:
        client.targets = db.scalars(select(Target).where(Target.id.in_(target_ids))).all()
    db.add(client)
    _audit(db, actor=actor, action="create_client", subject=client.id, detail="")
    db.commit()
    return RedirectResponse(f"/clients/{client.id}?new_token={token}", status_code=303)


@router.get("/clients/{client_id}", response_class=HTMLResponse)
def client_detail(
    client_id: str,
    request: Request,
    new_token: str | None = None,
    db: Session = Depends(get_db),
    actor: str | RedirectResponse = Depends(admin_actor_or_redirect),
):
    if isinstance(actor, RedirectResponse):
        return actor
    client = db.get(Client, client_id)
    if client is None:
        raise HTTPException(status_code=404)
    return templates.TemplateResponse(
        request,
        "client_detail.html",
        {
            "actor": actor,
            "client": client,
            "targets": db.scalars(select(Target).order_by(Target.id)).all(),
            "new_token": new_token,
            "install_command": _install_command(client, new_token, get_settings()),
            "uninstall_command": uninstall_command_for_client(client),
            "script_url": _script_url(client, new_token, get_settings()),
        },
    )


@router.post("/clients/{client_id}/status/{status}")
def set_client_status(
    client_id: str,
    status: str,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    actor: str | RedirectResponse = Depends(admin_actor_or_redirect),
):
    if isinstance(actor, RedirectResponse):
        return actor
    if status not in {"active", "disabled", "blocked", "deleted"}:
        raise HTTPException(status_code=422)
    client = db.get(Client, client_id)
    if client is None:
        raise HTTPException(status_code=404)
    client.status = status
    _audit(db, actor=actor, action="set_status", subject=client.id, detail=status)
    db.commit()
    db.refresh(client)

    if status == "blocked" and client.targets:
        _reconcile_from_web(db, settings=settings, client=client, action="DROP")
    if status == "active" and client.targets:
        _reconcile_from_web(db, settings=settings, client=client, action="ACCEPT")
    if status == "deleted" and client.targets:
        _delete_from_web(db, settings=settings, client=client)

    return RedirectResponse(f"/clients/{client.id}", status_code=303)


@router.post("/clients/{client_id}/config")
async def update_client_config(
    request: Request,
    client_id: str,
    platform: str = Form(...),
    frequency_minutes: int = Form(...),
    ip_mode: str = Form(...),
    allow_ipv6_prefix: str | None = Form(None),
    protocol: str = Form(...),
    port: str = Form(...),
    generate_install: str | None = Form(None),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    actor: str | RedirectResponse = Depends(admin_actor_or_redirect),
):
    if isinstance(actor, RedirectResponse):
        return actor
    client = db.get(Client, client_id)
    if client is None:
        raise HTTPException(status_code=404)
    if client.status == "deleted":
        raise HTTPException(status_code=409, detail="deleted client cannot be updated")

    form = await request.form()
    target_ids = [int(item) for item in form.getlist("target_ids")]
    try:
        normalized_protocol = normalize_protocol(protocol)
        normalized_port = normalize_port(normalized_protocol, port)
        normalized_ip_mode = normalize_ip_mode(ip_mode)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e)) from e

    token = generate_token() if generate_install == "1" else None
    if token is not None:
        client.token_hash = hash_token(token)
    client.platform = platform
    client.frequency_minutes = max(frequency_minutes, 1)
    client.ip_mode = normalized_ip_mode
    client.allow_ipv6_prefix = allow_ipv6_prefix == "1"
    client.protocol = normalized_protocol
    client.port = normalized_port
    client.targets = db.scalars(select(Target).where(Target.id.in_(target_ids))).all()
    _audit(db, actor=actor, action="update_client_config", subject=client.id, detail="")
    db.commit()
    db.refresh(client)

    if client.status == "active" and client.targets:
        _reconcile_from_web(db, settings=settings, client=client, action="ACCEPT")
    if client.status == "blocked" and client.targets:
        _reconcile_from_web(db, settings=settings, client=client, action="DROP")

    location = f"/clients/{client.id}"
    if token is not None:
        location = f"{location}?new_token={token}"
    return RedirectResponse(location, status_code=303)


@router.post("/clients/{client_id}/rotate-token")
def rotate_client_token(
    client_id: str,
    db: Session = Depends(get_db),
    actor: str | RedirectResponse = Depends(admin_actor_or_redirect),
):
    if isinstance(actor, RedirectResponse):
        return actor
    client = db.get(Client, client_id)
    if client is None:
        raise HTTPException(status_code=404)
    token = generate_token()
    client.token_hash = hash_token(token)
    _audit(db, actor=actor, action="rotate_token", subject=client.id, detail="")
    db.commit()
    return RedirectResponse(f"/clients/{client.id}?new_token={token}", status_code=303)


@router.post("/clients/{client_id}/purge")
def purge_client(
    client_id: str,
    db: Session = Depends(get_db),
    actor: str | RedirectResponse = Depends(admin_actor_or_redirect),
):
    if isinstance(actor, RedirectResponse):
        return actor
    client = db.get(Client, client_id)
    if client is None:
        raise HTTPException(status_code=404)
    if client.status != "deleted":
        raise HTTPException(status_code=409, detail="client must be deleted before purge")

    client.targets.clear()
    _audit(db, actor=actor, action="purge_client", subject=client.id, detail="")
    db.delete(client)
    db.commit()
    return RedirectResponse("/?show_deleted=1", status_code=303)


@router.get("/clients/{client_id}/install")
def download_install_script(
    client_id: str,
    token: str,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    client = db.get(Client, client_id)
    if client is None:
        raise HTTPException(status_code=404)
    if client.status == "deleted":
        raise HTTPException(status_code=410, detail={"status": "deleted", "action": "uninstall"})
    if not verify_token(token, client.token_hash):
        raise HTTPException(status_code=401, detail="Invalid install token")
    script = generate_agent_script(client, token=token, public_base_url=settings.public_base_url)
    return Response(
        script.body,
        media_type=script.content_type,
        headers={"Content-Disposition": f'attachment; filename="{script.filename}"'},
    )


def _audit(db: Session, *, actor: str, action: str, subject: str, detail: str) -> None:
    db.add(AuditLog(actor=actor, action=action, subject=subject, detail=detail))


def _reconcile_from_web(db: Session, *, settings: Settings, client: Client, action: str) -> None:
    try:
        reconcile_client_firewall(
            db,
            client=client,
            gateway=TencentLighthouseFirewallGateway(settings),
            action=action,
        )
        db.commit()
    except ValueError:
        db.rollback()


def _delete_from_web(db: Session, *, settings: Settings, client: Client) -> None:
    try:
        remove_client_firewall_rules(
            db,
            client=client,
            gateway=TencentLighthouseFirewallGateway(settings),
        )
        db.commit()
    except ValueError:
        db.rollback()


def _install_command(client: Client, token: str | None, settings: Settings) -> str | None:
    if token is None:
        return None
    return install_command_for_client(
        client,
        token=token,
        public_base_url=settings.public_base_url,
        script_base_url=settings.script_base_url,
    )


def _script_url(client: Client, token: str | None, settings: Settings) -> str | None:
    if token is None:
        return None
    return script_url_for_client(
        client,
        token=token,
        public_base_url=settings.public_base_url,
        script_base_url=settings.script_base_url,
    )
