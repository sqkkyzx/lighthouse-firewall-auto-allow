#!/usr/bin/env bash
set -euo pipefail

CLIENT_ID=""
TOKEN=""
SERVER_URL=""
FREQUENCY_SECONDS="300"
IP_MODE="ipv4"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --client-id) CLIENT_ID="$2"; shift 2 ;;
    --token) TOKEN="$2"; shift 2 ;;
    --server-url) SERVER_URL="$2"; shift 2 ;;
    --frequency-seconds) FREQUENCY_SECONDS="$2"; shift 2 ;;
    --ip-mode) IP_MODE="$2"; shift 2 ;;
    uninstall) ACTION="uninstall"; shift ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done

INSTALL_DIR="/opt/lighthouse-firewall-auto-allow"
RUNNER="$INSTALL_DIR/report-$CLIENT_ID.sh"
INSTALLER="$INSTALL_DIR/install-$CLIENT_ID.sh"
SERVICE="lighthouse-firewall-auto-allow-$CLIENT_ID"
ACTION="${ACTION:-install}"

log() {
  printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"
}

if [[ "$ACTION" == "uninstall" ]]; then
  log "Uninstalling $CLIENT_ID"
  systemctl disable --now "$SERVICE.timer" >/dev/null 2>&1 || true
  rm -f "/etc/systemd/system/$SERVICE.service" "/etc/systemd/system/$SERVICE.timer"
  systemctl daemon-reload >/dev/null 2>&1 || true
  crontab -l 2>/dev/null | grep -v "$RUNNER" | crontab - 2>/dev/null || true
  rm -f "$RUNNER" "$INSTALLER"
  rmdir "$INSTALL_DIR" >/dev/null 2>&1 || true
  log "Uninstalled $CLIENT_ID"
  exit 0
fi

if [[ -z "$CLIENT_ID" || -z "$TOKEN" || -z "$SERVER_URL" ]]; then
  echo "--client-id, --token and --server-url are required" >&2
  exit 2
fi

log "Installing $CLIENT_ID"
mkdir -p "$INSTALL_DIR"
cat > "$INSTALLER" <<INSTALLER
#!/usr/bin/env bash
set -euo pipefail

CLIENT_ID="$CLIENT_ID"
INSTALL_DIR="$INSTALL_DIR"
RUNNER="$RUNNER"
SERVICE="$SERVICE"

log() {
  printf '[%s] %s\n' "\$(date '+%Y-%m-%d %H:%M:%S')" "\$*"
}

if [[ "\${1:-}" != "uninstall" ]]; then
  echo "Usage: \$0 uninstall" >&2
  exit 2
fi

log "Uninstalling \$CLIENT_ID"
systemctl disable --now "\$SERVICE.timer" >/dev/null 2>&1 || true
rm -f "/etc/systemd/system/\$SERVICE.service" "/etc/systemd/system/\$SERVICE.timer"
systemctl daemon-reload >/dev/null 2>&1 || true
crontab -l 2>/dev/null | grep -v "\$RUNNER" | crontab - 2>/dev/null || true
rm -f "\$RUNNER" "\$0"
rmdir "\$INSTALL_DIR" >/dev/null 2>&1 || true
log "Uninstalled \$CLIENT_ID"
INSTALLER
chmod +x "$INSTALLER"

cat > "$RUNNER" <<RUNNER
#!/usr/bin/env bash
set -euo pipefail
CLIENT_ID="$CLIENT_ID"
TOKEN="$TOKEN"
REPORT_URL="${SERVER_URL%/}/api/v1/report/$CLIENT_ID"
IP_MODE="$IP_MODE"
INSTALLER="$INSTALLER"

ipv4=""
ipv6=""
if [[ "\$IP_MODE" == "ipv4" || "\$IP_MODE" == "all" ]]; then
  ipv4="\$(curl -fsS --max-time 10 https://ip4.blsy.team || true)"
fi
if [[ "\$IP_MODE" == "ipv6" || "\$IP_MODE" == "all" ]]; then
  ipv6="\$(curl -fsS --max-time 10 https://ip6.blsy.team || true)"
fi

payload="\$(printf '{"hostname":"%s","ipv4":%s,"ipv6":%s,"agent_version":"0.1.0"}' \\
  "\$(hostname)" \\
  "\$(if [[ -n "\$ipv4" ]]; then printf '"%s"' "\$ipv4"; else printf null; fi)" \\
  "\$(if [[ -n "\$ipv6" ]]; then printf '"%s"' "\$ipv6"; else printf null; fi)")"

code="\$(curl -sS -o /tmp/lighthouse-firewall-auto-allow-$CLIENT_ID.json -w "%{http_code}" -X POST "\$REPORT_URL" \\
  -H "Authorization: Bearer \$TOKEN" \\
  -H "Content-Type: application/json" \\
  --data "\$payload" || true)"

if [[ "\$code" == "410" ]]; then
  bash "\$INSTALLER" uninstall
fi
RUNNER
chmod +x "$RUNNER"

if command -v systemctl >/dev/null 2>&1; then
  cat > "/etc/systemd/system/$SERVICE.service" <<SERVICE
[Unit]
Description=Lighthouse firewall auto allow report for $CLIENT_ID

[Service]
Type=oneshot
ExecStart=$RUNNER
SERVICE
  cat > "/etc/systemd/system/$SERVICE.timer" <<TIMER
[Unit]
Description=Run Lighthouse firewall auto allow report for $CLIENT_ID

[Timer]
OnBootSec=30s
OnUnitActiveSec=${FREQUENCY_SECONDS}s
Unit=$SERVICE.service

[Install]
WantedBy=timers.target
TIMER
  systemctl daemon-reload
  systemctl enable --now "$SERVICE.timer"
  log "Installed systemd timer $SERVICE.timer"
else
  line="* * * * * $RUNNER"
  (crontab -l 2>/dev/null | grep -v "$RUNNER"; echo "$line") | crontab -
  log "Installed crontab entry; cron fallback runs at minute granularity"
fi

log "Running first report"
"$RUNNER"
