from __future__ import annotations

from lighthouse_firewall_auto_allow.agent_scripts import (
    generate_agent_script,
    install_command_for_client,
    script_url_for_client,
    uninstall_command_for_client,
)
from lighthouse_firewall_auto_allow.models import Client


def test_linux_script_contains_report_url_ip_endpoints_and_uninstall() -> None:
    client = Client(
        id="office",
        token_hash="hash",
        platform="ubuntu",
        frequency_minutes=5,
        ip_mode="all",
        protocol="TCP",
        port="22",
    )

    script = generate_agent_script(client, token="secret", public_base_url="https://center.example")

    assert script.filename == "install-linux.sh"
    assert "TOKEN=\"\"" in script.body
    assert "SERVER_URL=\"\"" in script.body
    assert "https://ip4.blsy.team" in script.body
    assert "https://ip6.blsy.team" in script.body
    assert "uninstall" in script.body
    assert "secret" not in script.body
    assert "https://center.example/api/v1/report/office" not in script.body


def test_windows_script_uses_scheduled_task() -> None:
    client = Client(
        id="office",
        token_hash="hash",
        platform="windows",
        frequency_minutes=5,
        ip_mode="ipv4",
        protocol="TCP",
        port="3389",
    )

    script = generate_agent_script(client, token="secret", public_base_url="https://center.example")

    assert script.filename == "install-windows.ps1"
    assert "Register-ScheduledTask" in script.body
    assert "Invoke-RestMethod" in script.body
    assert "function Uninstall-Agent" in script.body
    assert "Server returned 410; uninstalling" in script.body
    assert "Registered startup loop task" in script.body
    assert "secret" not in script.body
    assert "https://center.example" not in script.body


def test_windows_install_command_passes_client_values_as_arguments() -> None:
    client = Client(
        id="office",
        token_hash="hash",
        platform="windows",
        frequency_minutes=5,
        ip_mode="ipv4",
        protocol="TCP",
        port="3389",
    )

    command = install_command_for_client(
        client,
        token="secret",
        public_base_url="https://center.example",
        script_base_url="https://cdn.example/scripts",
    )

    assert command.startswith('curl -fSL "https://cdn.example/scripts/install-windows.ps1" | ')
    assert "powershell -ExecutionPolicy Bypass -Command" in command
    assert "iex ([Console]::In.ReadToEnd()); Install-Agent" in command
    assert "Install-Agent -ClientId 'office' -Token 'secret'" in command
    assert "EncodedCommand" not in command
    assert "$p" not in command


def test_script_url_uses_fixed_platform_filename() -> None:
    client = Client(
        id="office",
        token_hash="hash",
        platform="ubuntu",
        frequency_minutes=5,
        ip_mode="ipv4",
        protocol="TCP",
        port="22",
    )

    assert (
        script_url_for_client(
            client,
            token="secret",
            public_base_url="https://center.example",
            script_base_url="https://cdn.example/scripts",
        )
        == "https://cdn.example/scripts/install-linux.sh"
    )
    assert uninstall_command_for_client(client) == (
        "sudo bash /opt/lighthouse-firewall-auto-allow/install-office.sh uninstall"
    )
