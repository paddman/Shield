#!/bin/bash
# NT Shield legacy agent installer for CentOS/RHEL 6 (SysV init).
set -euo pipefail

INSTALL_DIR=/opt/ntshield/centos6-agent
CONFIG_DIR=/etc/ntshield-agent
CONFIG_FILE=$CONFIG_DIR/config.json
STATE_DIR=/var/lib/ntshield-agent
SPOOL_DIR=/var/spool/ntshield-agent
LOG_DIR=/var/log/ntshield
INIT_FILE=/etc/init.d/ntshield-agent
LOGROTATE_FILE=/etc/logrotate.d/ntshield-agent
SERVICE=ntshield-agent
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

CENTRAL_URL=""
ENROLLMENT_TOKEN=""
API_KEY=""
CA_FILE=""
SYSLOG_LISTEN="127.0.0.1:5514"
BINARY_SOURCE=""
INSECURE=0
DISABLE_SYSLOG=0
NO_START=0
FORCE_CONFIG=0

usage() {
    cat <<USAGE
Usage: sudo ./install-centos6.sh --url https://CENTRAL:7443 [options]

Required:
  --url URL                  NT Shield Central URL

Authentication/TLS:
  --enrollment-token TOKEN   Central enrollment token
  --api-key KEY              Existing agent API key (optional)
  --ca-file PATH             CA PEM used to verify Central
  --insecure                 Disable certificate verification (lab only)

Collection:
  --syslog-listen ADDR       UDP bind address (default 127.0.0.1:5514)
  --disable-syslog           Disable UDP listener; file tailing remains enabled

Install:
  --binary PATH              Static agent binary to install
  --force-config             Replace an existing config.json
  --no-start                 Install without starting the service
  -h, --help                 Show help

The installer does not open iptables ports. Remote syslog should be restricted to
known source networks before changing the bind address to 0.0.0.0:5514 or :514.
USAGE
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --url) CENTRAL_URL="${2:-}"; shift 2 ;;
        --enrollment-token) ENROLLMENT_TOKEN="${2:-}"; shift 2 ;;
        --api-key) API_KEY="${2:-}"; shift 2 ;;
        --ca-file) CA_FILE="${2:-}"; shift 2 ;;
        --syslog-listen) SYSLOG_LISTEN="${2:-}"; shift 2 ;;
        --binary) BINARY_SOURCE="${2:-}"; shift 2 ;;
        --insecure) INSECURE=1; shift ;;
        --disable-syslog) DISABLE_SYSLOG=1; shift ;;
        --force-config) FORCE_CONFIG=1; shift ;;
        --no-start) NO_START=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage; exit 2 ;;
    esac
done

[ "$(id -u)" -eq 0 ] || { echo "Run as root." >&2; exit 1; }
[ -n "$CENTRAL_URL" ] || { echo "--url is required." >&2; exit 2; }
case "$CENTRAL_URL" in
    http://*|https://*) ;;
    *) echo "--url must start with http:// or https://" >&2; exit 2 ;;
esac
CENTRAL_URL="${CENTRAL_URL%/}"

if [ -z "$BINARY_SOURCE" ]; then
    arch="$(uname -m)"
    case "$arch" in
        x86_64|amd64) names="ntshield-agent ntshield-agent-centos6-amd64" ;;
        i386|i486|i586|i686) names="ntshield-agent ntshield-agent-centos6-386" ;;
        *) echo "Unsupported architecture: $arch" >&2; exit 1 ;;
    esac
    for name in $names; do
        if [ -x "$SCRIPT_DIR/$name" ]; then
            BINARY_SOURCE="$SCRIPT_DIR/$name"
            break
        fi
        if [ -x "$SCRIPT_DIR/../dist/$name" ]; then
            BINARY_SOURCE="$SCRIPT_DIR/../dist/$name"
            break
        fi
    done
fi
[ -n "$BINARY_SOURCE" ] && [ -f "$BINARY_SOURCE" ] || {
    echo "Agent binary not found. Use --binary PATH or extract the release package." >&2
    exit 1
}

if [ -x "$INIT_FILE" ]; then
    "$INIT_FILE" stop >/dev/null 2>&1 || true
fi

install -d -m 0700 "$INSTALL_DIR" "$CONFIG_DIR" "$STATE_DIR" "$SPOOL_DIR" "$LOG_DIR"
install -m 0755 "$BINARY_SOURCE" "$INSTALL_DIR/ntshield-agent"

INIT_SOURCE=""
for candidate in "$SCRIPT_DIR/ntshield-agent.init" "$SCRIPT_DIR/../packaging/sysv/ntshield-agent"; do
    [ -f "$candidate" ] && INIT_SOURCE="$candidate" && break
done
[ -n "$INIT_SOURCE" ] || { echo "SysV init script not found." >&2; exit 1; }
install -m 0755 "$INIT_SOURCE" "$INIT_FILE"

LOGROTATE_SOURCE=""
for candidate in "$SCRIPT_DIR/ntshield-agent.logrotate" "$SCRIPT_DIR/../packaging/logrotate/ntshield-agent"; do
    [ -f "$candidate" ] && LOGROTATE_SOURCE="$candidate" && break
done
[ -n "$LOGROTATE_SOURCE" ] && install -m 0644 "$LOGROTATE_SOURCE" "$LOGROTATE_FILE"

if [ ! -f "$CONFIG_FILE" ] || [ "$FORCE_CONFIG" -eq 1 ]; then
    args=(
        -write-config "$CONFIG_FILE"
        -central-url "$CENTRAL_URL"
        -syslog-listen "$SYSLOG_LISTEN"
    )
    [ "$INSECURE" -eq 1 ] && args+=( -insecure )
    [ "$DISABLE_SYSLOG" -eq 1 ] && args+=( -disable-syslog )
    [ -n "$CA_FILE" ] && args+=( -ca-file "$CA_FILE" )
    NTSHIELD_BOOTSTRAP_ENROLLMENT_TOKEN="$ENROLLMENT_TOKEN" \
    NTSHIELD_BOOTSTRAP_API_KEY="$API_KEY" \
        "$INSTALL_DIR/ntshield-agent" "${args[@]}"
else
    echo "Keeping existing $CONFIG_FILE (use --force-config to replace it)."
fi
chmod 0600 "$CONFIG_FILE"

if [ -f "$SCRIPT_DIR/uninstall-centos6.sh" ]; then
    install -m 0755 "$SCRIPT_DIR/uninstall-centos6.sh" "$INSTALL_DIR/uninstall-centos6.sh"
fi

"$INSTALL_DIR/ntshield-agent" -config "$CONFIG_FILE" -check-config

if command -v chkconfig >/dev/null 2>&1; then
    chkconfig --add "$SERVICE"
    chkconfig "$SERVICE" on
fi

if [ "$NO_START" -eq 0 ]; then
    service "$SERVICE" restart
    sleep 2
    service "$SERVICE" status || true
fi

cat <<DONE

NT Shield CentOS 6 agent installed.
  Binary : $INSTALL_DIR/ntshield-agent
  Config : $CONFIG_FILE
  State  : $STATE_DIR/status.json
  Spool  : $SPOOL_DIR
  Log    : $LOG_DIR/centos6-agent.log
  Syslog : $([ "$DISABLE_SYSLOG" -eq 1 ] && echo disabled || echo "$SYSLOG_LISTEN/udp")

Commands:
  service ntshield-agent status
  tail -f /var/log/ntshield/centos6-agent.log
  cat /var/lib/ntshield-agent/status.json
DONE
