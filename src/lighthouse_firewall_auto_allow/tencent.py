from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass

from lighthouse_firewall_auto_allow.config import Settings
from lighthouse_firewall_auto_allow.rules import FirewallRule, firewall_rule_from_unknown

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class FirewallSnapshot:
    rules: list[FirewallRule]
    version: int | None


class FirewallGateway(ABC):
    @abstractmethod
    def describe_rules(self, *, region: str, instance_id: str) -> FirewallSnapshot:
        raise NotImplementedError

    @abstractmethod
    def delete_rules(
        self,
        *,
        region: str,
        instance_id: str,
        rules: list[FirewallRule],
        version: int | None,
    ) -> None:
        raise NotImplementedError

    @abstractmethod
    def create_rules(
        self,
        *,
        region: str,
        instance_id: str,
        rules: list[FirewallRule],
        version: int | None,
    ) -> None:
        raise NotImplementedError


class TencentLighthouseFirewallGateway(FirewallGateway):
    def __init__(self, settings: Settings) -> None:
        if not settings.tencentcloud_secret_id or not settings.tencentcloud_secret_key:
            raise ValueError("Tencent Cloud credentials are not configured")
        self._secret_id = settings.tencentcloud_secret_id
        self._secret_key = settings.tencentcloud_secret_key

    def describe_rules(self, *, region: str, instance_id: str) -> FirewallSnapshot:
        client, models = self._sdk_client(region)
        request = models.DescribeFirewallRulesRequest()
        request.InstanceId = instance_id
        request.Limit = 100
        response = client.DescribeFirewallRules(request)
        return FirewallSnapshot(
            rules=[firewall_rule_from_unknown(item) for item in response.FirewallRuleSet],
            version=response.FirewallVersion,
        )

    def delete_rules(
        self,
        *,
        region: str,
        instance_id: str,
        rules: list[FirewallRule],
        version: int | None,
    ) -> None:
        if not rules:
            return
        client, models = self._sdk_client(region)
        request = models.DeleteFirewallRulesRequest()
        request.InstanceId = instance_id
        request.FirewallRules = [self._sdk_rule(models, rule) for rule in rules]
        if version is not None:
            request.FirewallVersion = version
        client.DeleteFirewallRules(request)

    def create_rules(
        self,
        *,
        region: str,
        instance_id: str,
        rules: list[FirewallRule],
        version: int | None,
    ) -> None:
        if not rules:
            return
        client, models = self._sdk_client(region)
        request = models.CreateFirewallRulesRequest()
        request.InstanceId = instance_id
        request.FirewallRules = [self._sdk_rule(models, rule) for rule in rules]
        if version is not None:
            request.FirewallVersion = version
        client.CreateFirewallRules(request)

    def _sdk_client(self, region: str):
        from tencentcloud.common import credential
        from tencentcloud.common.profile.client_profile import ClientProfile
        from tencentcloud.common.profile.http_profile import HttpProfile
        from tencentcloud.lighthouse.v20200324 import lighthouse_client, models

        http_profile = HttpProfile()
        http_profile.endpoint = "lighthouse.tencentcloudapi.com"
        client_profile = ClientProfile()
        client_profile.httpProfile = http_profile
        cred = credential.Credential(self._secret_id, self._secret_key)
        return lighthouse_client.LighthouseClient(cred, region, client_profile), models

    @staticmethod
    def _sdk_rule(models, rule: FirewallRule):
        sdk_rule = models.FirewallRule()
        sdk_rule.Protocol = rule.protocol
        sdk_rule.Port = rule.port
        sdk_rule.Action = rule.action
        sdk_rule.FirewallRuleDescription = rule.description
        if rule.cidr_block is not None:
            sdk_rule.CidrBlock = rule.cidr_block
        if rule.ipv6_cidr_block is not None:
            sdk_rule.Ipv6CidrBlock = rule.ipv6_cidr_block
        return sdk_rule
