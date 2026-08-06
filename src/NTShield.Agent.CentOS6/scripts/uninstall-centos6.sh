#!/bin/bash
set -euo pipefail

PURGE=0
[ "${1:-}" = "--purge" ] && PURGE=1
[ "$(id -u)" -eq 0 ] || { echo "Run as root." >&2; exit 1; }

if [ -x /etc/init.d/ntshield-agent ]; then
    /etc/init.d/ntshield-agent stop >/dev/null 2>&1 || true
fi
if command -v chkconfig >/dev/null 2>&1; then
    chkconfig ntshield-agent off >/dev/null 2>&1 || true
    chkconfig --del ntshield-agent >/dev/null 2>&1 || true
fi
rm -f /etc/init.d/ntshield-agent /etc/logrotate.d/ntshield-agent
rm -rf /opt/ntshield/centos6-agent

if [ "$PURGE" -eq 1 ]; then
    rm -rf /etc/ntshield-agent /var/lib/ntshield-agent \
        /var/spool/ntshield-agent /var/log/ntshield
    echo "Agent and all local state purged."
else
    echo "Agent removed. Config, spool and logs were preserved. Use --purge to delete them."
fi
