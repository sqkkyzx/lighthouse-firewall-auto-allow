from __future__ import annotations

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session

from lighthouse_firewall_auto_allow.models import (
    AuditLog,
    Base,
    Client,
    ClientTarget,
    FirewallEvent,
    Report,
    Target,
)
from lighthouse_firewall_auto_allow.routes_web import purge_client


def test_purge_deleted_client_removes_client_owned_records_and_bindings() -> None:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)

    with Session(engine) as db:
        client = Client(
            id="office",
            status="deleted",
            token_hash="hash",
            platform="windows",
            frequency_minutes=300,
            ip_mode="ipv6",
            protocol="TCP",
            port="22",
        )
        target = Target(region="ap-guangzhou", instance_id="lhins-test", alias="test")
        client.targets.append(target)
        client.reports.append(Report(hostname="desktop", ipv4=None, ipv6="240e::1"))
        client.firewall_events.append(
            FirewallEvent(target=target, action="delete", status="ok", message="deleted")
        )
        db.add(client)
        db.commit()

        response = purge_client("office", db=db, actor="admin")

        assert response.status_code == 303
        assert response.headers["location"] == "/?show_deleted=1"
        assert db.get(Client, "office") is None
        assert db.scalar(select(func.count()).select_from(ClientTarget)) == 0
        assert db.scalar(select(func.count()).select_from(Report)) == 0
        assert db.scalar(select(func.count()).select_from(FirewallEvent)) == 0
        assert db.scalar(select(func.count()).select_from(Target)) == 1
        assert db.scalar(select(func.count()).select_from(AuditLog)) == 1
