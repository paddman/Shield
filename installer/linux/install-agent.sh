#!/usr/bin/env bash
# NT Shield Linux Agent installer
# Usage:
#   sudo ./install-agent.sh --host 10.0.0.5 --port 7443 \
#     --ca-cert ./central-ca.crt --enrollment-token '<token>'
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
ALLOW_UNTRUSTED="false"
ALLOW_HTTP="false"
CA_CERT=""
CA_DEST=""
NO_START="0"
ENROLLMENT_TOKEN=""
API_KEY=""

red()  { printf '\033[31m%s\033[0m\n' "$*"; }
green(){ printf '\033[32m%s\033[0m\n' "$*"; }
cyan() { printf '\033[36m%s\033[0m\n' "$*"; }
yellow(){ printf '\033[33m%s\033[0m\n' "$*"; }

usage() {
  cat <<EOF
NT Shield Linux Agent Installer

Options:
  --host HOST          Central server IP or hostname
  --port PORT          HTTPS port (default 7443)
  --url URL            Full Central URL (overrides host/port)
  --enrollment-token T Central EnrollmentToken from protected secrets.json
  --api-key KEY        Existing per-agent API key
  --ca-cert PATH       CA/server certificate used to validate Central TLS
  --allow-untrusted    Disable TLS certificate validation (isolated lab only)
  --http               Use plaintext HTTP (isolated migration lab only)
  --no-untrusted       Compatibility alias; certificate validation remains enabled
  --no-start           Install but do not start systemd service
  -h, --help           Show this help

Examples:
  sudo ./install-agent.sh --host 10.0.0.5 --port 7443 \
    --ca-cert ./central-ca.crt --enrollment-token '<token>'

  # Publicly trusted Central certificate
  sudo ./install-agent.sh --url https://shield.example.go.th:7443 \
    --enrollment-token '<token>'
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host) CENTRAL_HOST="${2:-}"; shift 2 ;;
    --port) CENTRAL_PORT="${2:-}"; shift 2 ;;
    --url) CENTRAL_URL="${2:-}"; shift 2 ;;
    --enrollment-token) ENROLLMENT_TOKEN="${2:-}"; shift 2 ;;
    --api-key) API_KEY="${2:-}"; shift 2 ;;
    --ca-cert) CA_CERT="${2:-}"; shift 2 ;;
    --allow-untrusted) ALLOW_UNTRUSTED="true"; shift ;;
    --no-untrusted) ALLOW_UNTRUSTED="false"; shift ;;
    --http) SCHEME="http"; ALLOW_HTTP="true"; shift ;;
    --no-start) NO_START="1"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) red "Unknown option: $1"; usage; exit 1 ;;
  esac
done

if [[ "$(id -u)" -ne 0 ]]; then
  red "Please run as root: sudo $0 ..."
  exit 1
fi

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
  red "Extract the complete linux-agent package first."
  exit 1
fi

if [[ -z "$CENTRAL_URL" && -z "$CENTRAL_HOST" ]]; then
  cyan "=== NT Shield Linux Agent ==="
  echo "Agent sends telemetry to Central only."
  read -r -p "Central Server IP / Host: " CENTRAL_HOST
  read -r -p "Port [7443]: " CENTRAL_PORT
  CENTRAL_PORT="${CENTRAL_PORT:-7443}"
  read -r -p "CA certificate path [blank = OS trust store]: " CA_CERT
  read -r -p "Disable TLS certificate validation? ISOLATED LAB ONLY (y/N): " unsafe
  if [[ "${unsafe:-}" =~ ^[Yy]([Ee][Ss])?$ ]]; then
    ALLOW_UNTRUSTED="true"
  fi
fi

if [[ -z "$CENTRAL_URL" ]]; then
  if [[ -z "$CENTRAL_HOST" ]]; then
    red "Central host is required."
    exit 1
  fi
  if [[ "$CENTRAL_HOST" == http://* || "$CENTRAL_HOST" == https://* ]]; then
    CENTRAL_URL="${CENTRAL_HOST%/}"
  else
    CENTRAL_URL="${SCHEME}://${CENTRAL_HOST}:${CENTRAL_PORT}"
  fi
fi
CENTRAL_URL="${CENTRAL_URL%/}"

if [[ "$CENTRAL_URL" == http://* && "$ALLOW_HTTP" != "true" ]]; then
  red "Plain HTTP is disabled. Use HTTPS."
  exit 1
fi
if [[ "$CENTRAL_URL" != https://* && "$CENTRAL_URL" != http://* ]]; then
  red "Central URL must be absolute: $CENTRAL_URL"
  exit 1
fi
if [[ "$CENTRAL_URL" == http://* ]]; then
  yellow "WARNING: plaintext HTTP exposes telemetry, enrollment and policy in transit."
fi
if [[ "$ALLOW_UNTRUSTED" == "true" ]]; then
  yellow "WARNING: TLS certificate validation is DISABLED by explicit request."
fi

if [[ -n "$CA_CERT" && ! -f "$CA_CERT" ]]; then
  red "CA certificate not found: $CA_CERT"
  exit 1
fi

cyan "Install dir : $INSTALL_ROOT"
cyan "Central URL : $CENTRAL_URL"
cyan "Package from: $BIN_SRC"

if systemctl list-unit-files | grep -q "^${SERVICE_NAME}.service"; then
  systemctl stop "$SERVICE_NAME" 2>/dev/null || true
fi

mkdir -p "$INSTALL_ROOT" "$LOG_DIR" /var/lib/ntshield
chmod 0750 "$INSTALL_ROOT" "$LOG_DIR" /var/lib/ntshield

shopt -s dotglob nullglob
for f in "$BIN_SRC"/*; do
  base="$(basename "$f")"
  case "$base" in
    install-agent.sh|uninstall-agent.sh|set-central-url.sh|README*.md) continue ;;
  esac
  cp -a "$f" "$INSTALL_ROOT/"
done
shopt -u dotglob nullglob

EXE="$INSTALL_ROOT/NTShield.Agent.Linux"
if [[ -f "$EXE" ]]; then
  chmod 0750 "$EXE"
elif [[ -f "$INSTALL_ROOT/NTShield.Agent.Linux.dll" ]]; then
  if ! command -v dotnet >/dev/null 2>&1; then
    red "Only managed DLL present and dotnet is not installed. Use the self-contained package."
    exit 1
  fi
  cat > "$EXE" <<'WRAP'
#!/usr/bin/env bash
cd "$(dirname "$0")"
exec dotnet NTShield.Agent.Linux.dll "$@"
WRAP
  chmod 0750 "$EXE"
else
  red "Agent binary missing after copy."
  exit 1
fi

if [[ -n "$CA_CERT" ]]; then
  CA_DEST="$INSTALL_ROOT/central-ca.crt"
  cp -f "$CA_CERT" "$CA_DEST"
  chmod 0644 "$CA_DEST"
  green "Trusted Central CA copied to $CA_DEST"
fi

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
    "CaCertificatePath": "$CA_DEST",
    "AllowUntrustedServerCertificate": $ALLOW_UNTRUSTED,
    "HeartbeatIntervalSeconds": 60
  },
  "Linux": {
    "AutoRemediate": false
  }
}
EOF
else
  if command -v python3 >/dev/null 2>&1; then
    NTS_APPSETTINGS="$APPSETTINGS" \
    NTS_CENTRAL_URL="$CENTRAL_URL" \
    NTS_ALLOW_UNTRUSTED="$ALLOW_UNTRUSTED" \
    NTS_CA_DEST="$CA_DEST" \
    NTS_ENROLLMENT_TOKEN="$ENROLLMENT_TOKEN" \
    NTS_API_KEY="$API_KEY" \
    python3 - <<'PY'
import json
import os

path = os.environ["NTS_APPSETTINGS"]
with open(path, encoding="utf-8-sig") as handle:
    config = json.load(handle)
server = config.setdefault("Server", {})
server["Url"] = os.environ["NTS_CENTRAL_URL"]
server["AllowUntrustedServerCertificate"] = os.environ["NTS_ALLOW_UNTRUSTED"].lower() == "true"
server["CaCertificatePath"] = os.environ["NTS_CA_DEST"]
server.setdefault("HeartbeatIntervalSeconds", 60)
if os.environ["NTS_ENROLLMENT_TOKEN"]:
    server["EnrollmentToken"] = os.environ["NTS_ENROLLMENT_TOKEN"]
if os.environ["NTS_API_KEY"]:
    server["ApiKey"] = os.environ["NTS_API_KEY"]
config.setdefault("Agent", {})
config.setdefault("Linux", {}).setdefault("AutoRemediate", False)
with open(path, "w", encoding="utf-8") as handle:
    json.dump(config, handle, indent=2)
    handle.write("\n")
print("OK appsettings:", server["Url"])
PY
  else
    red "python3 is required to update an existing appsettings.json safely."
    exit 1
  fi
fi
chmod 0600 "$APPSETTINGS"

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
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=read-only
ReadWritePaths=$INSTALL_ROOT /var/log/ntshield /var/lib/ntshield

[Install]
WantedBy=multi-user.target
EOF
fi

sed -i "s|ExecStart=.*|ExecStart=$INSTALL_ROOT/NTShield.Agent.Linux|" "$SERVICE_FILE" || true
sed -i "s|WorkingDirectory=.*|WorkingDirectory=$INSTALL_ROOT|" "$SERVICE_FILE" || true
chmod 0644 "$SERVICE_FILE"

for script in install-agent.sh uninstall-agent.sh set-central-url.sh; do
  if [[ -f "$SCRIPT_DIR/$script" ]]; then
    cp "$SCRIPT_DIR/$script" "$INSTALL_ROOT/"
    chmod 0750 "$INSTALL_ROOT/$script"
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
echo " Install        : $INSTALL_ROOT"
echo " Service        : $SERVICE_NAME"
echo " Central URL    : $CENTRAL_URL"
echo " TLS custom CA  : ${CA_DEST:-system trust store}"
echo " Credentials    : $APPSETTINGS (mode 0600)"
echo " Logs           : $LOG_DIR"
echo ""
echo " Commands:"
echo "   systemctl status $SERVICE_NAME"
echo "   journalctl -u $SERVICE_NAME -f"
echo ""
echo " Health test:"
if [[ "$CENTRAL_URL" == http://* ]]; then
  echo "   curl $CENTRAL_URL/api/v1/health"
elif [[ "$ALLOW_UNTRUSTED" == "true" ]]; then
  echo "   curl -k $CENTRAL_URL/api/v1/health   # lab-only insecure validation"
elif [[ -n "$CA_DEST" ]]; then
  echo "   curl --cacert $CA_DEST $CENTRAL_URL/api/v1/health"
else
  echo "   curl $CENTRAL_URL/api/v1/health"
fi
