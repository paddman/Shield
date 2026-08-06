#!/usr/bin/env bash
# Uninstall NT Shield Linux Agent
set -euo pipefail

SERVICE_NAME="ntshield-agent"
INSTALL_ROOT="/opt/ntshield/agent"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Please run as root: sudo $0"
  exit 1
fi

systemctl stop "$SERVICE_NAME" 2>/dev/null || true
systemctl disable "$SERVICE_NAME" 2>/dev/null || true
rm -f "$SERVICE_FILE"
systemctl daemon-reload

if [[ -d "$INSTALL_ROOT" ]]; then
  rm -rf "$INSTALL_ROOT"
fi

# optional: keep logs
# rm -rf /var/log/ntshield

echo "NT Shield Linux Agent removed."
