from __future__ import annotations

import shlex
from dataclasses import dataclass
from pathlib import Path

from lighthouse_firewall_auto_allow.models import Client


@dataclass(frozen=True)
class AgentScript:
    filename: str
    content_type: str
    body: str


def generate_agent_script(client: Client, *, token: str, public_base_url: str) -> AgentScript:
    script_path = _static_script_path(client)
    return AgentScript(
        filename=_script_filename(client),
        content_type=_content_type(client),
        body=script_path.read_text(encoding="utf-8"),
    )


def script_url_for_client(
    client: Client,
    *,
    token: str,
    public_base_url: str,
    script_base_url: str,
) -> str:
    filename = _script_filename(client)
    if script_base_url.strip():
        return f"{script_base_url.rstrip('/')}/{filename}"
    return f"{public_base_url.rstrip('/')}/clients/{client.id}/install?token={token}"


def install_command_for_client(
    client: Client,
    *,
    token: str,
    public_base_url: str,
    script_base_url: str,
) -> str:
    script_url = script_url_for_client(
        client,
        token=token,
        public_base_url=public_base_url,
        script_base_url=script_base_url,
    )
    server_url = public_base_url.rstrip("/")
    if client.platform == "windows":
        return (
            f"curl -fSL {_double_quote(script_url)} | "
            "powershell -ExecutionPolicy Bypass -Command "
            "\"iex ([Console]::In.ReadToEnd()); "
            f"Install-Agent -ClientId {_ps_single_quote(client.id)} -Token {_ps_single_quote(token)} "
            f"-ServerUrl {_ps_single_quote(server_url)} "
            f"-FrequencySeconds {max(client.frequency_minutes, 1)} "
            f"-IpMode {_ps_single_quote(client.ip_mode)}\""
        )

    args = " ".join(
        [
            f"--client-id {shlex.quote(client.id)}",
            f"--token {shlex.quote(token)}",
            f"--server-url {shlex.quote(server_url)}",
            f"--frequency-seconds {max(client.frequency_minutes, 1)}",
            f"--ip-mode {shlex.quote(client.ip_mode)}",
        ]
    )
    if client.platform == "macos":
        return f"curl -fsSL {shlex.quote(script_url)} | bash -s -- {args}"
    return f"curl -fsSL {shlex.quote(script_url)} | sudo bash -s -- {args}"


def uninstall_command_for_client(client: Client) -> str:
    if client.platform == "windows":
        return (
            "powershell -ExecutionPolicy Bypass -Command "
            f"\"& '$env:ProgramData\\lighthouse-firewall-auto-allow\\report-{client.id}.ps1' "
            "uninstall\""
        )
    if client.platform == "macos":
        return (
            "bash "
            f"\"$HOME/Library/Application Support/lighthouse-firewall-auto-allow/"
            f"install-{client.id}.sh\" uninstall"
        )
    return f"sudo bash /opt/lighthouse-firewall-auto-allow/install-{client.id}.sh uninstall"


def _static_script_path(client: Client) -> Path:
    return Path(__file__).parent / "static" / "scripts" / _script_filename(client)


def _script_filename(client: Client) -> str:
    if client.platform == "windows":
        return "install-windows.ps1"
    if client.platform == "macos":
        return "install-macos.sh"
    return "install-linux.sh"


def _content_type(client: Client) -> str:
    if client.platform == "windows":
        return "text/plain; charset=utf-8"
    return "text/x-shellscript; charset=utf-8"


def _ps_single_quote(value: str) -> str:
    escaped = value.replace("'", "''")
    return f"'{escaped}'"


def _double_quote(value: str) -> str:
    escaped = value.replace('"', '\\"')
    return f'"{escaped}"'
