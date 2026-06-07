from __future__ import annotations

import pytest

from lighthouse_firewall_auto_allow.models import Client
from lighthouse_firewall_auto_allow.rules import (
    desired_rules_for_client,
    normalize_port,
    normalize_report_ip,
    rule_description,
)
from lighthouse_firewall_auto_allow.security import validate_client_id


def test_rule_description_uses_auto_prefix() -> None:
    assert rule_description("home-pc") == "[AUTO] home-pc"


def test_validate_client_id_rejects_unsafe_text() -> None:
    with pytest.raises(ValueError):
        validate_client_id("../bad")


def test_normalize_port_supports_lists_ranges_and_all() -> None:
    assert normalize_port("TCP", "22,80,8000-9000") == "22,80,8000-9000"
    assert normalize_port("TCP", "ALL") == "ALL"
    assert normalize_port("UDP", "ALL") == "ALL"
    assert normalize_port("ALL", "ALL") == "ALL"


def test_normalize_port_rejects_bad_range() -> None:
    with pytest.raises(ValueError):
        normalize_port("TCP", "9000-8000")


def test_normalize_report_ip_checks_version() -> None:
    assert normalize_report_ip("1.2.3.4", 4) == "1.2.3.4"
    with pytest.raises(ValueError):
        normalize_report_ip("1.2.3.4", 6)


def test_desired_rules_generate_separate_ipv4_and_ipv6_rules() -> None:
    client = Client(
        id="office",
        token_hash="hash",
        platform="ubuntu",
        frequency_minutes=5,
        ip_mode="all",
        protocol="TCP",
        port="22",
        last_ipv4="1.2.3.4",
        last_ipv6="2402:4e00::1",
    )

    rules = desired_rules_for_client(client)

    assert [rule.to_payload() for rule in rules] == [
        {
            "Protocol": "TCP",
            "Port": "22",
            "Action": "ACCEPT",
            "FirewallRuleDescription": "[AUTO] office",
            "CidrBlock": "1.2.3.4/32",
        },
        {
            "Protocol": "TCP",
            "Port": "22",
            "Action": "ACCEPT",
            "FirewallRuleDescription": "[AUTO] office",
            "Ipv6CidrBlock": "2402:4e00::1/128",
        },
    ]


def test_desired_rules_can_allow_ipv6_prefix() -> None:
    client = Client(
        id="office",
        token_hash="hash",
        platform="ubuntu",
        frequency_minutes=5,
        ip_mode="ipv6",
        allow_ipv6_prefix=True,
        protocol="TCP",
        port="22",
        last_ipv6="240e:37d:1b01:1f00:74c1:8b99:d8f9:b6b1",
    )

    rules = desired_rules_for_client(client)

    assert [rule.to_payload() for rule in rules] == [
        {
            "Protocol": "TCP",
            "Port": "22",
            "Action": "ACCEPT",
            "FirewallRuleDescription": "[AUTO] office",
            "Ipv6CidrBlock": "240e:37d:1b01:1f00::/64",
        },
    ]
