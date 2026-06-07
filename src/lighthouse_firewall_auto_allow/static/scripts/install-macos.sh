#!/usr/bin/env bash
set -euo pipefail

CLIENT_ID=""
TOKEN=""
SERVER_URL=""
FREQUENCY_SECONDS="300"
IP_MODE="ipv4"
ACTION="install"

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

BASE_DIR="$HOME/Library/Application Support/lighthouse-firewall-auto-allow"
RUNNER="$BASE_DIR/report-$CLIENT_ID.sh"
INSTALLER="$BASE_DIR/install-$CLIENT_ID.sh"
PLIST="$HOME/Library/LaunchAgents/team.blsy.lighthouse-firewall-auto-allow.$CLIENT_ID.plist"
LABEL="team.blsy.lighthouse-firewall-auto-allow.$CLIENT_ID"

log() {
  printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"
}

if [[ "$ACTION" == "uninstall" ]]; then
  log "Uninstalling $CLIENT_ID"
  launchctl unload "$PLIST" >/dev/null 2>&1 || true
  rm -f "$PLIST" "$RUNNER" "$INSTALLER"
  rmdir "$BASE_DIR" >/dev/null 2>&1 || true
  log "Uninstalled $CLIENT_ID"
  exit 0
fi

if [[ -z "$CLIENT_ID" || -z "$TOKEN" || -z "$SERVER_URL" ]]; then
  echo "--client-id, --token and --server-url are required" >&2
  exit 2
fi

log "Installing $CLIENT_ID"
mkdir -p "$BASE_DIR"
cat > "$INSTALLER" <<INSTALLER
#!/usr/bin/env bash
set -euo pipefail

CLIENT_ID="$CLIENT_ID"
BASE_DIR="$BASE_DIR"
RUNNER="$RUNNER"
PLIST="$PLIST"

log() {
  printf '[%s] %s\n' "\$(date '+%Y-%m-%d %H:%M:%S')" "\$*"
}

if [[ "\${1:-}" != "uninstall" ]]; then
  echo "Usage: \$0 uninstall" >&2
  exit 2
fi

log "Uninstalling \$CLIENT_ID"
launchctl unload "\$PLIST" >/dev/null 2>&1 || true
rm -f "\$PLIST" "\$RUNNER" "\$0"
rmdir "\$BASE_DIR" >/dev/null 2>&1 || true
log "Uninstalled \$CLIENT_ID"
INSTALLER
chmod +x "$INSTALLER"

cat > "$RUNNER" <<RUNNER
#!/usr/bin/env bash
set -euo pipefail
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
payload="\$(printf '{"hostname":"%s","ipv4":%s,"ipv6":%s,"agent_version":"0.1.0"}' "\$(hostname)" "\$(if [[ -n "\$ipv4" ]]; then printf '"%s"' "\$ipv4"; else printf null; fi)" "\$(if [[ -n "\$ipv6" ]]; then printf '"%s"' "\$ipv6"; else printf null; fi)")"
code="\$(curl -sS -o /tmp/lighthouse-firewall-auto-allow-$CLIENT_ID.json -w "%{http_code}" -X POST "\$REPORT_URL" -H "Authorization: Bearer \$TOKEN" -H "Content-Type: application/json" --data "\$payload" || true)"
if [[ "\$code" == "410" ]]; then
  "\$INSTALLER" uninstall
fi
RUNNER
chmod +x "$RUNNER"

cat > "$PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key><array><string>$RUNNER</string></array>
  <key>RunAtLoad</key><true/>
  <key>StartInterval</key><integer>$FREQUENCY_SECONDS</integer>
</dict>
</plist>
PLIST

launchctl unload "$PLIST" >/dev/null 2>&1 || true
launchctl load "$PLIST"
log "Installed launchd agent $LABEL"
log "Running first report"
"$RUNNER"
