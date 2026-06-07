from __future__ import annotations

from sqlalchemy.orm import Session

from lighthouse_firewall_auto_allow.models import Client, FirewallEvent, Target
from lighthouse_firewall_auto_allow.rules import desired_rules_for_client, rule_description
from lighthouse_firewall_auto_allow.tencent import FirewallGateway

VERSION_MISMATCH_MARKERS = {
    "UnsupportedOperation.FirewallVersionMismatch",
    "FirewallVersionMismatch",
}


def reconcile_client_firewall(
    db: Session,
    *,
    client: Client,
    gateway: FirewallGateway,
    action: str = "ACCEPT",
) -> None:
    for target in client.targets:
        if not target.enabled:
            continue
        _reconcile_target(db, client=client, target=target, gateway=gateway, action=action)


def remove_client_firewall_rules(db: Session, *, client: Client, gateway: FirewallGateway) -> None:
    for target in client.targets:
        _delete_managed_rules(db, client=client, target=target, gateway=gateway)


def _reconcile_target(
    db: Session,
    *,
    client: Client,
    target: Target,
    gateway: FirewallGateway,
    action: str,
) -> None:
    desired = desired_rules_for_client(client, action=action)
    if not desired:
        _record_event(db, client, target, "skip", "ok", "No IP available for selected mode")
        return

    for attempt in range(2):
        try:
            snapshot = gateway.describe_rules(region=target.region, instance_id=target.instance_id)
            managed = [
                rule for rule in snapshot.rules if rule.description == rule_description(client.id)
            ]
            if {rule.key() for rule in managed} == {rule.key() for rule in desired}:
                _record_event(db, client, target, "noop", "ok", "Managed rules already match")
                return

            if managed:
                gateway.delete_rules(
                    region=target.region,
                    instance_id=target.instance_id,
                    rules=managed,
                    version=snapshot.version,
                )
                snapshot = gateway.describe_rules(
                    region=target.region,
                    instance_id=target.instance_id,
                )

            existing_identity_keys = {rule.tencent_identity_key() for rule in snapshot.rules}
            existing_network_slots = {rule.network_slot_key() for rule in snapshot.rules}
            conflicted = [
                rule
                for rule in desired
                if rule.network_slot_key() in existing_network_slots
                and rule.tencent_identity_key() not in existing_identity_keys
            ]
            to_create = [
                rule
                for rule in desired
                if rule.tencent_identity_key() not in existing_identity_keys
                and rule.network_slot_key()
                not in {conflicted_rule.network_slot_key() for conflicted_rule in conflicted}
            ]

            if conflicted:
                _record_event(
                    db,
                    client,
                    target,
                    "conflict",
                    "warning",
                    "A rule with the same protocol, port and IP already exists with another action",
                )

            if not to_create:
                _record_event(
                    db,
                    client,
                    target,
                    "covered",
                    "ok",
                    "Desired rules are already covered by existing Tencent Cloud rules",
                )
                return

            gateway.create_rules(
                region=target.region,
                instance_id=target.instance_id,
                rules=to_create,
                version=snapshot.version,
            )
            _record_event(db, client, target, "reconcile", "ok", "Managed rules updated")
            return
        except Exception as e:
            if attempt == 0 and _is_version_mismatch(e):
                continue
            _record_event(db, client, target, "reconcile", "error", str(e))
            raise


def _delete_managed_rules(
    db: Session,
    *,
    client: Client,
    target: Target,
    gateway: FirewallGateway,
) -> None:
    for attempt in range(2):
        try:
            snapshot = gateway.describe_rules(region=target.region, instance_id=target.instance_id)
            managed = [
                rule for rule in snapshot.rules if rule.description == rule_description(client.id)
            ]
            if not managed:
                _record_event(db, client, target, "delete", "ok", "No managed rules to delete")
                return
            gateway.delete_rules(
                region=target.region,
                instance_id=target.instance_id,
                rules=managed,
                version=snapshot.version,
            )
            _record_event(db, client, target, "delete", "ok", "Managed rules deleted")
            return
        except Exception as e:
            if attempt == 0 and _is_version_mismatch(e):
                continue
            _record_event(db, client, target, "delete", "error", str(e))
            raise


def _record_event(
    db: Session,
    client: Client,
    target: Target,
    action: str,
    status: str,
    message: str,
) -> None:
    db.add(
        FirewallEvent(
            client_id=client.id,
            target_id=target.id,
            action=action,
            status=status,
            message=message,
        )
    )
    db.flush()


def _is_version_mismatch(error: Exception) -> bool:
    text = str(error)
    return any(marker in text for marker in VERSION_MISMATCH_MARKERS)
