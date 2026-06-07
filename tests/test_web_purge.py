from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session
from starlette.datastructures import FormData

from lighthouse_firewall_auto_allow.config import Settings
from lighthouse_firewall_auto_allow.models import (
    AuditLog,
    Base,
    Client,
    ClientTarget,
    FirewallEvent,
    Report,
    Target,
)
from lighthouse_firewall_auto_allow.routes_web import (
    download_install_script,
    purge_client,
    update_client_config,
)
from lighthouse_firewall_auto_allow.security import hash_token, verify_token


class FakeRequest:
    def __init__(self, form: FormData) -> None:
        self._form = form

    async def form(self) -> FormData:
        return self._form


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


def test_install_script_download_uses_client_token_without_admin_session() -> None:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)

    with Session(engine) as db:
        db.add(
            Client(
                id="office",
                status="active",
                token_hash=hash_token("secret"),
                platform="ubuntu",
                frequency_minutes=300,
                ip_mode="ipv4",
                protocol="TCP",
                port="22",
            )
        )
        db.commit()

        response = download_install_script(
            "office",
            token="secret",
            db=db,
            settings=Settings(public_base_url="https://center.example"),
        )

        assert response.status_code == 200
        assert b"https://ip4.blsy.team" in response.body


async def test_update_client_config_changes_settings_targets_and_rotates_token() -> None:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)

    with Session(engine) as db:
        client = Client(
            id="office",
            status="disabled",
            token_hash=hash_token("old-token"),
            platform="ubuntu",
            frequency_minutes=300,
            ip_mode="ipv4",
            protocol="TCP",
            port="22",
        )
        target = Target(region="ap-guangzhou", instance_id="lhins-test", alias="test")
        db.add_all([client, target])
        db.commit()

        response = await update_client_config(
            FakeRequest(FormData([("target_ids", str(target.id))])),
            "office",
            platform="windows",
            frequency_minutes=60,
            ip_mode="all",
            allow_ipv6_prefix="1",
            protocol="UDP",
            port="53",
            generate_install="1",
            db=db,
            settings=Settings(public_base_url="https://center.example"),
            actor="admin",
        )

        db.refresh(client)
        location = response.headers["location"]
        token = parse_qs(urlsplit(location).query)["new_token"][0]
        assert response.status_code == 303
        assert location.startswith("/clients/office?new_token=")
        assert client.platform == "windows"
        assert client.frequency_minutes == 60
        assert client.ip_mode == "all"
        assert client.allow_ipv6_prefix is True
        assert client.protocol == "UDP"
        assert client.port == "53"
        assert client.targets == [target]
        assert verify_token(token, client.token_hash)
        assert not verify_token("old-token", client.token_hash)


async def test_update_client_config_can_preserve_existing_token() -> None:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)

    with Session(engine) as db:
        client = Client(
            id="office",
            status="disabled",
            token_hash=hash_token("old-token"),
            platform="ubuntu",
            frequency_minutes=300,
            ip_mode="ipv4",
            protocol="TCP",
            port="22",
        )
        db.add(client)
        db.commit()

        response = await update_client_config(
            FakeRequest(FormData()),
            "office",
            platform="ubuntu",
            frequency_minutes=300,
            ip_mode="ipv4",
            allow_ipv6_prefix=None,
            protocol="TCP",
            port="22",
            generate_install=None,
            db=db,
            settings=Settings(public_base_url="https://center.example"),
            actor="admin",
        )

        db.refresh(client)
        assert response.status_code == 303
        assert response.headers["location"] == "/clients/office"
        assert verify_token("old-token", client.token_hash)
