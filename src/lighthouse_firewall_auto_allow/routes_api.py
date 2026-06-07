from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Header, HTTPException
from sqlalchemy.orm import Session

from lighthouse_firewall_auto_allow.config import Settings, get_settings
from lighthouse_firewall_auto_allow.database import get_db
from lighthouse_firewall_auto_allow.models import Client, Report
from lighthouse_firewall_auto_allow.reconcile import reconcile_client_firewall
from lighthouse_firewall_auto_allow.rules import normalize_report_ip
from lighthouse_firewall_auto_allow.schemas import ReportRequest, ReportResponse
from lighthouse_firewall_auto_allow.security import bearer_token, verify_token
from lighthouse_firewall_auto_allow.tencent import TencentLighthouseFirewallGateway

router = APIRouter(prefix="/api/v1")


@router.post("/report/{client_id}", response_model=ReportResponse)
def report_client(
    client_id: str,
    payload: ReportRequest,
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> ReportResponse:
    client = db.get(Client, client_id)
    if client is None:
        raise HTTPException(status_code=404, detail="Unknown client")
    if client.status == "deleted":
        raise HTTPException(status_code=410, detail={"status": "deleted", "action": "uninstall"})
    if not verify_token(bearer_token(authorization), client.token_hash):
        raise HTTPException(status_code=401, detail="Invalid token")

    try:
        ipv4 = normalize_report_ip(payload.ipv4, 4)
        ipv6 = normalize_report_ip(payload.ipv6, 6)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e)) from e

    if client.ip_mode == "ipv4" and ipv4 is None:
        raise HTTPException(status_code=422, detail="IPv4 is required for this client")
    if client.ip_mode == "ipv6" and ipv6 is None:
        raise HTTPException(status_code=422, detail="IPv6 is required for this client")
    if client.ip_mode == "all" and ipv4 is None and ipv6 is None:
        raise HTTPException(status_code=422, detail="At least one IP address is required")

    ip_changed = client.last_ipv4 != ipv4 or client.last_ipv6 != ipv6
    client.hostname = payload.hostname
    client.last_ipv4 = ipv4
    client.last_ipv6 = ipv6
    client.last_report_at = datetime.now(UTC)
    db.add(
        Report(
            client_id=client.id,
            hostname=payload.hostname,
            ipv4=ipv4,
            ipv6=ipv6,
            agent_version=payload.agent_version,
        )
    )
    db.commit()
    db.refresh(client)

    if client.status == "disabled":
        return ReportResponse(status="accepted")
    if not ip_changed and client.status == "active":
        return ReportResponse(status="unchanged")

    if client.targets:
        try:
            reconcile_client_firewall(
                db,
                client=client,
                gateway=TencentLighthouseFirewallGateway(settings),
                action="DROP" if client.status == "blocked" else "ACCEPT",
            )
            db.commit()
        except ValueError as e:
            db.rollback()
            raise HTTPException(status_code=503, detail=str(e)) from e
        except Exception as e:
            db.rollback()
            raise HTTPException(status_code=502, detail=str(e)) from e

    return ReportResponse(status="updated")
