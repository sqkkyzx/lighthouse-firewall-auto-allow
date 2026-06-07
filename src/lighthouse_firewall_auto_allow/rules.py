from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

from lighthouse_firewall_auto_allow.models import Client

ALLOWED_PROTOCOLS = {"TCP", "UDP", "ALL"}
ALLOWED_IP_MODES = {"ipv4", "ipv6", "all"}
PORT_RE = re.compile(r"^(ALL|\d{1,5}(-\d{1,5})?)(,(ALL|\d{1,5}(-\d{1,5})?))*$")

PRESET_PORTS: dict[str, tuple[str, str]] = {
    "ssh": ("TCP", "22"),
    "http": ("TCP", "80"),
    "https": ("TCP", "443"),
    "rdp": ("TCP", "3389"),
    "all": ("ALL", "ALL"),
}


@dataclass(frozen=True)
class FirewallRule:
    protocol: str
    port: str
    action: str
    description: str
    cidr_block: str | None = None
    ipv6_cidr_block: str | None = None

    def to_payload(self) -> dict[str, str]:
        payload = {
            "Protocol": self.protocol,
            "Port": self.port,
            "Action": self.action,
            "FirewallRuleDescription": self.description,
        }
        if self.cidr_block is not None:
            payload["CidrBlock"] = self.cidr_block
        if self.ipv6_cidr_block is not None:
            payload["Ipv6CidrBlock"] = self.ipv6_cidr_block
        return payload

    def key(self) -> tuple[str, str, str, str | None, str | None, str]:
        return (
            self.protocol,
            self.port,
            self.action,
            self.cidr_block,
            self.ipv6_cidr_block,
            self.description,
        )

    def tencent_identity_key(self) -> tuple[str, str, str, str | None, str | None]:
        return (
            self.protocol,
            self.port,
            self.action,
            self.cidr_block,
            self.ipv6_cidr_block,
        )

    def network_slot_key(self) -> tuple[str, str, str | None, str | None]:
        return (
            self.protocol,
            self.port,
            self.cidr_block,
            self.ipv6_cidr_block,
        )


def rule_description(client_id: str) -> str:
    return f"[AUTO] {client_id}"


def normalize_protocol(protocol: str) -> str:
    normalized = protocol.upper()
    if normalized not in ALLOWED_PROTOCOLS:
        raise ValueError("protocol must be TCP, UDP or ALL")
    return normalized


def normalize_ip_mode(ip_mode: str) -> str:
    normalized = ip_mode.lower()
    if normalized not in ALLOWED_IP_MODES:
        raise ValueError("ip_mode must be ipv4, ipv6 or all")
    return normalized


def normalize_port(protocol: str, port: str) -> str:
    value = port.strip().upper()
    if len(value) > 64:
        raise ValueError("port is too long")
    if PORT_RE.fullmatch(value) is None:
        raise ValueError("port must be ALL, single ports, comma-separated ports or ranges")
    if protocol not in {"TCP", "UDP"} and value != "ALL":
        raise ValueError("non TCP/UDP protocol must use port ALL")

    for part in value.split(","):
        if part == "ALL":
            continue
        if "-" in part:
            left, right = part.split("-", 1)
            _validate_port_number(left)
            _validate_port_number(right)
            if int(left) >= int(right):
                raise ValueError("port range start must be smaller than range end")
        else:
            _validate_port_number(part)
    return value


def normalize_report_ip(value: str | None, version: int) -> str | None:
    if value is None or value.strip() == "":
        return None
    parsed = ipaddress.ip_address(value.strip())
    if parsed.version != version:
        raise ValueError(f"expected IPv{version} address")
    return str(parsed)


def desired_rules_for_client(client: Client, *, action: str = "ACCEPT") -> list[FirewallRule]:
    rules: list[FirewallRule] = []
    description = rule_description(client.id)
    if client.ip_mode in {"ipv4", "all"} and client.last_ipv4 is not None:
        rules.append(
            FirewallRule(
                protocol=client.protocol,
                port=client.port,
                action=action,
                cidr_block=f"{client.last_ipv4}/32",
                description=description,
            )
        )
    if client.ip_mode in {"ipv6", "all"} and client.last_ipv6 is not None:
        prefix_length = 64 if client.allow_ipv6_prefix else 128
        rules.append(
            FirewallRule(
                protocol=client.protocol,
                port=client.port,
                action=action,
                ipv6_cidr_block=_ipv6_cidr(client.last_ipv6, prefix_length),
                description=description,
            )
        )
    return rules


def firewall_rule_from_unknown(value: object) -> FirewallRule:
    if isinstance(value, dict):
        return FirewallRule(
            protocol=str(value.get("Protocol", "")),
            port=str(value.get("Port", "")),
            action=str(value.get("Action", "")),
            cidr_block=_optional_str(value.get("CidrBlock")),
            ipv6_cidr_block=_optional_str(value.get("Ipv6CidrBlock")),
            description=str(value.get("FirewallRuleDescription", "")),
        )

    return FirewallRule(
        protocol=str(getattr(value, "Protocol", "")),
        port=str(getattr(value, "Port", "")),
        action=str(getattr(value, "Action", "")),
        cidr_block=_optional_str(getattr(value, "CidrBlock", None)),
        ipv6_cidr_block=_optional_str(getattr(value, "Ipv6CidrBlock", None)),
        description=str(getattr(value, "FirewallRuleDescription", "")),
    )


def _optional_str(value: object) -> str | None:
    if value is None:
        return None
    text = str(value)
    if text == "":
        return None
    return text


def _validate_port_number(value: str) -> None:
    number = int(value)
    if number < 1 or number > 65535:
        raise ValueError("port number must be 1-65535")


def _ipv6_cidr(value: str, prefix_length: int) -> str:
    network = ipaddress.ip_network(f"{value}/{prefix_length}", strict=False)
    return str(network)
