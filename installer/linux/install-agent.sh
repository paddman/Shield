#!/usr/bin/env bash
# NT Shield Linux Agent installer
# Usage:
#   sudo ./install-agent.sh --host 10.0.0.5 --port 7443
#   sudo ./install-agent.sh --url https://10.0.0.5:7443
#   sudo ./install-agent.sh   # interactive
set -euo pipefail

INSTALL_ROOT="/opt/ntshield/agent"
SERVICE_NAME="ntshield-agent"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
LOG_DIR="/var/log/ntshield"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

CENTRAL_HOST=""
CENTRAL_PORT="7443"
CENTRAL_URL=""
SCHEME="https"
ALLOW_UNTRUSTED="true"
NO_START="0"

red()  { printf '\033[31m%s\033[0m\n' "$*"; }
green(){ printf '\033[32m%s\033[0m\n' "$*"; }
cyan() { printf '\033[36m%s\033[0m\n' "$*"; }

usage() {
  cat <<EOF
NT Shield Linux Agent Installer

Options:
  --host HOST          Central server IP or hostname
  --port PORT          HTTPS port (default 7443)
  --url URL            Full Central URL (overrides host/port)
  --enrollment-token T Central EnrollmentToken (from secrets.json)
  --api-key KEY        Optional existing agent ApiKey
  --http               Use http:// instead of https://
  --no-untrusted       Do not accept self-signed certificates
  --no-start           Install but do not start systemd service
  -h, --help           Show this help

Examples:
  sudo ./install-agent.sh --host 192.168.56.210 --port 7443
  sudo ./install-agent.sh --url https://10.0.0.5:7443 --enrollment-token <token>
EOF
}

ENROLLMENT_TOKEN=""
API_KEY=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host) CENTRAL_HOST="${2:-}"; shift 2 ;;
    --port) CENTRAL_PORT="${2:-}"; shift 2 ;;
    --url)  CENTRAL_URL="${2:-}"; shift 2 ;;
    --enrollment-token) ENROLLMENT_TOKEN="${2:-}"; shift 2 ;;
    --api-key) API_KEY="${2:-}"; shift 2 ;;
    --http) SCHEME="http"; shift ;;
    --no-untrusted) ALLOW_UNTRUSTED="false"; shift ;;
    --no-start) NO_START="1"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) red "Unknown option: $1"; usage; exit 1 ;;
  esac
done

if [[ "$(id -u)" -ne 0 ]]; then
  red "Please run as root: sudo $0 ..."
  exit 1
fi

# Locate package files (run from extracted tarball root or installer/linux with ../publish)
BIN_SRC=""
for d in \
  "$SCRIPT_DIR" \
  "$SCRIPT_DIR/.." \
  "$SCRIPT_DIR/../../artifacts/linux-agent" \
  "$SCRIPT_DIR/publish" \
  "$(pwd)"
do
  if [[ -f "$d/NTShield.Agent.Linux" || -f "$d/NTShield.Agent.Linux.dll" ]]; then
    BIN_SRC="$d"
    break
  fi
done

if [[ -z "$BIN_SRC" ]]; then
  red "Cannot find NTShield.Agent.Linux binaries next to this script."
  red "Extract the full linux-agent package first."
  exit 1
fi

# Interactive URL if missing
if [[ -z "$CENTRAL_URL" && -z "$CENTRAL_HOST" ]]; then
  cyan "=== NT Shield Linux Agent ==="
  echo "Agent will send heartbeats to Central (not to Dashboard)."
  read -r -p "Central Server IP / Host: " CENTRAL_HOST
  read -r -p "Port [7443]: " CENTRAL_PORT
  CENTRAL_PORT="${CENTRAL_PORT:-7443}"
fi

if [[ -z "$CENTRAL_URL" ]]; then
  if [[ -z "$CENTRAL_HOST" ]]; then
    red "Central host is required."
    exit 1
  fi
  # host field may already be full URL
  if [[ "$CENTRAL_HOST" == http://* || "$CENTRAL_HOST" == https://* ]]; then
    CENTRAL_URL="${CENTRAL_HOST%/}"
  else
    CENTRAL_URL="${SCHEME}://${CENTRAL_HOST}:${CENTRAL_PORT}"
  fi
fi
CENTRAL_URL="${CENTRAL_URL%/}"

cyan "Install dir : $INSTALL_ROOT"
cyan "Central URL : $CENTRAL_URL"
cyan "Package from: $BIN_SRC"

# Stop old service
if systemctl list-unit-files | grep -q "^${SERVICE_NAME}.service"; then
  systemctl stop "$SERVICE_NAME" 2>/dev/null || true
fi

mkdir -p "$INSTALL_ROOT" "$LOG_DIR"
# Copy all package files except install scripts overwriting carefully
shopt -s dotglob nullglob
for f in "$BIN_SRC"/*; do
  base="$(basename "$f")"
  case "$base" in
    install-agent.sh|uninstall-agent.sh|set-central-url.sh|README*.md) continue ;;
  esac
  if [[ -d "$f" ]]; then
    cp -a "$f" "$INSTALL_ROOT/"
  else
    cp -a "$f" "$INSTALL_ROOT/"
  fi
done
shopt -u dotglob nullglob

# Prefer native executable
EXE="$INSTALL_ROOT/NTShield.Agent.Linux"
if [[ -f "$EXE" ]]; then
  chmod +x "$EXE"
elif [[ -f "$INSTALL_ROOT/NTShield.Agent.Linux.dll" ]]; then
  # Framework-dependent fallback
  if ! command -v dotnet >/dev/null 2>&1; then
    red "Only managed DLL present and 'dotnet' not installed. Use self-contained package."
    exit 1
  fi
  # Wrapper
  cat > "$EXE" <<'WRAP'
#!/usr/bin/env bash
cd "$(dirname "$0")"
exec dotnet NTShield.Agent.Linux.dll "$@"
WRAP
  chmod +x "$EXE"
else
  red "Binary missing after copy."
  exit 1
fi

# appsettings.json
APPSETTINGS="$INSTALL_ROOT/appsettings.json"
if [[ ! -f "$APPSETTINGS" ]]; then
  cat > "$APPSETTINGS" <<EOF
{
  "Agent": {
    "AgentId": "",
    "ComputerName": ""
  },
  "Server": {
    "Url": "$CENTRAL_URL",
    "EnrollmentToken": "$ENROLLMENT_TOKEN",
    "ApiKey": "$API_KEY",
    "AllowUntrustedServerCertificate": $ALLOW_UNTRUSTED,
    "HeartbeatIntervalSeconds": 60
  }
}
EOF
else
  # Update Server.Url with python3 or sed fallback
  if command -v python3 >/dev/null 2>&1; then
    python3 - <<PY
import json
p = r"""$APPSETTINGS"""
with open(p) as f:
    j = json.load(f)
j.setdefault("Server", {})
j["Server"]["Url"] = r"""$CENTRAL_URL"""
j["Server"]["AllowUntrustedServerCertificate"] = ($ALLOW_UNTRUSTED == "true")
j["Server"]["HeartbeatIntervalSeconds"] = j["Server"].get("HeartbeatIntervalSeconds", 60)
et = r"""$ENROLLMENT_TOKEN"""
ak = r"""$API_KEY"""
if et:
    j["Server"]["EnrollmentToken"] = et
if ak:
    j["Server"]["ApiKey"] = ak
j.setdefault("Agent", {})
with open(p, "w") as f:
    json.dump(j, f, indent=2)
    f.write("\n")
print("OK appsettings:", j["Server"]["Url"])
PY
  else
    # crude replace
    sed -i "s|\"Url\": *\"[^\"]*\"|\"Url\": \"$CENTRAL_URL\"|g" "$APPSETTINGS" || true
  fi
fi

# systemd unit
UNIT_SRC="$INSTALL_ROOT/ntshield-agent.service"
if [[ -f "$UNIT_SRC" ]]; then
  cp "$UNIT_SRC" "$SERVICE_FILE"
else
  cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=NT Shield Linux Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
ExecStart=$INSTALL_ROOT/NTShield.Agent.Linux
WorkingDirectory=$INSTALL_ROOT
Restart=on-failure
RestartSec=5
Environment=DOTNET_ENVIRONMENT=Production

[Install]
WantedBy=multi-user.target
EOF
fi

# Ensure ExecStart path
sed -i "s|ExecStart=.*|ExecStart=$INSTALL_ROOT/NTShield.Agent.Linux|" "$SERVICE_FILE" || true
sed -i "s|WorkingDirectory=.*|WorkingDirectory=$INSTALL_ROOT|" "$SERVICE_FILE" || true

# Helper scripts into install dir
for s in install-agent.sh uninstall-agent.sh set-central-url.sh; do
  if [[ -f "$SCRIPT_DIR/$s" ]]; then
    cp "$SCRIPT_DIR/$s" "$INSTALL_ROOT/"
    chmod +x "$INSTALL_ROOT/$s"
  fi
done

systemctl daemon-reload
systemctl enable "$SERVICE_NAME"

if [[ "$NO_START" != "1" ]]; then
  systemctl restart "$SERVICE_NAME"
  sleep 2
  systemctl --no-pager --full status "$SERVICE_NAME" || true
fi

green "========================================"
green " NT Shield Linux Agent installed"
green "========================================"
echo " Version files : $INSTALL_ROOT"
echo " Service       : $SERVICE_NAME"
echo " Central URL   : $CENTRAL_URL"
echo " Logs          : $LOG_DIR  (or $INSTALL_ROOT/logs)"
echo ""
echo " Commands:"
echo "   systemctl status $SERVICE_NAME"
echo "   journalctl -u $SERVICE_NAME -f"
echo "   $INSTALL_ROOT/set-central-url.sh --host <IP> --port 7443"
echo ""
echo " Dashboard Endpoints should show this host (platform=linux) within ~1 minute."
echo " Health test:"
echo "   curl -k $CENTRAL_URL/api/v1/health"
