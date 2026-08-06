#!/usr/bin/env bash
# Reconfigure Central URL for installed Linux agent
#   sudo ./set-central-url.sh --host 10.0.0.5 --port 7443
set -euo pipefail

INSTALL_ROOT="/opt/ntshield/agent"
APPSETTINGS="$INSTALL_ROOT/appsettings.json"
SERVICE_NAME="ntshield-agent"
CENTRAL_HOST=""
CENTRAL_PORT="7443"
CENTRAL_URL=""
SCHEME="https"

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
    *) echo "Unknown: $1"; exit 1 ;;
  esac
done

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Please run as root"
  exit 1
fi

if [[ ! -f "$APPSETTINGS" ]]; then
  echo "Agent not installed at $INSTALL_ROOT"
  exit 1
fi

if [[ -z "$CENTRAL_URL" ]]; then
  if [[ -z "$CENTRAL_HOST" ]]; then
    read -r -p "Central IP / Host: " CENTRAL_HOST
    read -r -p "Port [7443]: " CENTRAL_PORT
    CENTRAL_PORT="${CENTRAL_PORT:-7443}"
  fi
  if [[ "$CENTRAL_HOST" == http://* || "$CENTRAL_HOST" == https://* ]]; then
    CENTRAL_URL="${CENTRAL_HOST%/}"
  else
    CENTRAL_URL="${SCHEME}://${CENTRAL_HOST}:${CENTRAL_PORT}"
  fi
fi
CENTRAL_URL="${CENTRAL_URL%/}"

if command -v python3 >/dev/null 2>&1; then
  python3 - <<PY
import json
p = r"""$APPSETTINGS"""
with open(p) as f:
    j = json.load(f)
j.setdefault("Server", {})
j["Server"]["Url"] = r"""$CENTRAL_URL"""
j["Server"]["AllowUntrustedServerCertificate"] = True
et = r"""$ENROLLMENT_TOKEN"""
ak = r"""$API_KEY"""
if et:
    j["Server"]["EnrollmentToken"] = et
if ak:
    j["Server"]["ApiKey"] = ak
with open(p, "w") as f:
    json.dump(j, f, indent=2)
    f.write("\n")
print("OK:", j["Server"]["Url"])
PY
else
  sed -i "s|\"Url\": *\"[^\"]*\"|\"Url\": \"$CENTRAL_URL\"|g" "$APPSETTINGS"
  echo "OK (sed): $CENTRAL_URL"
fi

systemctl restart "$SERVICE_NAME"
systemctl --no-pager status "$SERVICE_NAME" || true
echo "Done. Check: journalctl -u $SERVICE_NAME -n 20"
