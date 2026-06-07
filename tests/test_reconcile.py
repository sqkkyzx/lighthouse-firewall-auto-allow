from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from lighthouse_firewall_auto_allow.models import Base, Client, Target
from lighthouse_firewall_auto_allow.reconcile import (
    reconcile_client_firewall,
    remove_client_firewall_rules,
)
from lighthouse_firewall_auto_allow.rules import FirewallRule
from lighthouse_firewall_auto_allow.tencent import FirewallGateway, FirewallSnapshot


class FakeGateway(FirewallGateway):
    def __init__(self, rules: list[FirewallRule] | None = None) -> None:
        self.rules = list(rules or [])
        self.deleted: list[FirewallRule] = []
        self.created: list[FirewallRule] = []
        self.version = 1

    def describe_rules(self, *, region: str, instance_id: str) -> FirewallSnapshot:
        return FirewallSnapshot(rules=list(self.rules), version=self.version)

    def delete_rules(
        self,
        *,
        region: str,
        instance_id: str,
        rules: list[FirewallRule],
        version: int | None,
    ) -> None:
        self.deleted.extend(rules)
        delete_keys = {rule.key() for rule in rules}
        self.rules = [rule for rule in self.rules if rule.key() not in delete_keys]
        self.version += 1

    def create_rules(
        self,
        *,
        region: str,
        instance_id: str,
        rules: list[FirewallRule],
        version: int | None,
    ) -> None:
        self.created.extend(rules)
        self.rules.extend(rules)
        self.version += 1


def test_reconcile_deletes_stale_managed_rule_and_creates_desired_rule() -> None:
    with _session() as db:
        client, target = _client_with_target()
        db.add_all([client, target])
        client.targets.append(target)
        db.commit()

        stale = FirewallRule(
            protocol="TCP",
            port="22",
            action="ACCEPT",
            cidr_block="5.6.7.8/32",
            description="[AUTO] office",
        )
        gateway = FakeGateway([stale])

        reconcile_client_firewall(db, client=client, gateway=gateway)

        assert gateway.deleted == [stale]
        assert gateway.created[0].cidr_block == "1.2.3.4/32"


def test_reconcile_noops_when_rules_match() -> None:
    with _session() as db:
        client, target = _client_with_target()
        db.add_all([client, target])
        client.targets.append(target)
        db.commit()

        existing = FirewallRule(
            protocol="TCP",
            port="22",
            action="ACCEPT",
            cidr_block="1.2.3.4/32",
            description="[AUTO] office",
        )
        gateway = FakeGateway([existing])

        reconcile_client_firewall(db, client=client, gateway=gateway)

        assert gateway.deleted == []
        assert gateway.created == []


def test_reconcile_skips_create_when_same_tencent_rule_exists_for_another_id() -> None:
    with _session() as db:
        client, target = _client_with_target()
        db.add_all([client, target])
        client.targets.append(target)
        db.commit()

        existing_for_other_client = FirewallRule(
            protocol="TCP",
            port="22",
            action="ACCEPT",
            cidr_block="1.2.3.4/32",
            description="[AUTO] laptop",
        )
        gateway = FakeGateway([existing_for_other_client])

        reconcile_client_firewall(db, client=client, gateway=gateway)

        assert gateway.deleted == []
        assert gateway.created == []


def test_reconcile_skips_create_when_same_network_slot_has_different_action() -> None:
    with _session() as db:
        client, target = _client_with_target()
        db.add_all([client, target])
        client.targets.append(target)
        db.commit()

        existing_accept = FirewallRule(
            protocol="TCP",
            port="22",
            action="ACCEPT",
            cidr_block="1.2.3.4/32",
            description="[AUTO] laptop",
        )
        gateway = FakeGateway([existing_accept])

        reconcile_client_firewall(db, client=client, gateway=gateway, action="DROP")

        assert gateway.deleted == []
        assert gateway.created == []


def test_remove_client_firewall_rules_deletes_only_managed_rules() -> None:
    with _session() as db:
        client, target = _client_with_target()
        db.add_all([client, target])
        client.targets.append(target)
        db.commit()

        managed = FirewallRule(
            protocol="TCP",
            port="22",
            action="ACCEPT",
            cidr_block="1.2.3.4/32",
            description="[AUTO] office",
        )
        unrelated = FirewallRule(
            protocol="TCP",
            port="80",
            action="ACCEPT",
            cidr_block="0.0.0.0/0",
            description="manual",
        )
        gateway = FakeGateway([managed, unrelated])

        remove_client_firewall_rules(db, client=client, gateway=gateway)

        assert gateway.deleted == [managed]
        assert gateway.rules == [unrelated]


def _session() -> Session:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def _client_with_target() -> tuple[Client, Target]:
    client = Client(
        id="office",
        token_hash="hash",
        platform="ubuntu",
        frequency_minutes=5,
        ip_mode="ipv4",
        protocol="TCP",
        port="22",
        last_ipv4="1.2.3.4",
    )
    target = Target(region="ap-guangzhou", instance_id="lhins-test", alias="test")
    return client, target
