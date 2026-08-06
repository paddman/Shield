# NT Shield CentOS 6 Legacy Agent

A small, dependency-free Linux agent for **CentOS/RHEL 6** hosts that cannot run the repository's current .NET 10/systemd agent. It builds as a static Go binary, runs under SysV init, and sends telemetry to the existing NT Shield Central API.

This module is intentionally isolated from `NTShield.Agent.Linux`; it does not replace or downgrade the modern Linux agent.

## What it collects

| Source | Collection method | Central payload |
|---|---|---|
| Network traffic metadata | `/proc/net/tcp`, `tcp6`, `udp`, `udp6`; socket inode mapped to `/proc/<pid>/fd` | `NetworkConnections` |
| Interface traffic rate | `/proc/net/dev` RX/TX deltas | heartbeat metrics |
| Local Syslog/security logs | Offset-persisted tail of `/var/log/messages`, `/var/log/secure`, and auditd | `SecurityEvents`, channel `syslog` |
| Network Syslog | UDP listener, default `127.0.0.1:5514` | `SecurityEvents`, channel `syslog` |
| ModSecurity/WAF | Apache/Nginx error lines, serial audit sections `A` through `Z`, and JSON audit records | `SecurityEvents`, channel `waf`, plus high/blocked `Alerts` |

The traffic collector stores **connection metadata**, not packet payloads or PCAP. This is deliberate. Full packet capture on a CentOS 6 production host is a resource and privacy problem wearing a technical hat.

## Reliability and security

- Static binary, no .NET runtime and no systemd dependency.
- SysV init service with `chkconfig` support.
- File offsets survive restart and handle rotation/truncation.
- Failed batches are written to a bounded disk spool before transmission.
- Central registration, heartbeat, API-key authentication, and idempotent `/api/v1/ingest` reuse the existing server contract.
- TLS verification is **enabled by default**. Use a CA PEM or the explicit `--insecure` lab option.
- UDP Syslog listens on loopback by default. The installer never opens iptables automatically.
- WAF raw evidence redacts `Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`, and common JSON secret fields before upload.
- The agent starts new log files at EOF by default, avoiding an accidental upload of old archives.

## Build

Use Go 1.20.x for the release build. The module has no third-party dependencies.

```bash
cd src/NTShield.Agent.CentOS6
make test vet
make build-amd64
```

Build both x86 targets and create release tarballs:

```bash
make package VERSION=0.1.0
ls -lh dist/
```

The amd64 build uses `CGO_ENABLED=0` and `GOAMD64=v1`. The 386 build uses software floating point for broad old-hardware compatibility.

## Install on CentOS 6

Extract the matching release package, then run:

```bash
tar -xzf NTShield-CentOS6-Agent-0.1.0-amd64.tar.gz
sudo ./install-centos6.sh \
  --url https://CENTRAL_IP:7443 \
  --enrollment-token 'CENTRAL_ENROLLMENT_TOKEN' \
  --ca-file /root/ntshield-central-ca.pem
```

For a self-signed lab Central where no CA file is available:

```bash
sudo ./install-centos6.sh \
  --url https://CENTRAL_IP:7443 \
  --enrollment-token 'CENTRAL_ENROLLMENT_TOKEN' \
  --insecure
```

The insecure switch is not the normal production setting. Certificates exist for a reason, despite humanity's recurring efforts to click past them.

Service commands:

```bash
service ntshield-agent status
service ntshield-agent restart
tail -f /var/log/ntshield/centos6-agent.log
cat /var/lib/ntshield-agent/status.json
```

Installed paths:

| Item | Path |
|---|---|
| Binary | `/opt/ntshield/centos6-agent/ntshield-agent` |
| Config | `/etc/ntshield-agent/config.json` |
| API key and offsets | `/var/lib/ntshield-agent/` |
| Offline spool | `/var/spool/ntshield-agent/` |
| Log | `/var/log/ntshield/centos6-agent.log` |
| Init script | `/etc/init.d/ntshield-agent` |

The process runs as root because CentOS 6 commonly restricts audit/security logs and `/proc/<pid>/fd` visibility. It performs collection only and does not expose arbitrary command execution or automatic remediation.

## Syslog modes

### Local files

Local file tailing is enabled by default:

```json
"log_files": [
  "/var/log/messages",
  "/var/log/secure",
  "/var/log/audit/audit.log"
]
```

### UDP listener

Default bind:

```json
"syslog": {
  "enabled": true,
  "listen": "127.0.0.1:5514"
}
```

To receive logs from network devices, change the bind address and restrict the source network. Example:

```bash
iptables -A INPUT -p udp -s 10.20.0.0/16 --dport 5514 -j ACCEPT
iptables -A INPUT -p udp --dport 5514 -j DROP
service iptables save
```

Then set:

```json
"listen": "0.0.0.0:5514"
```

Do not forward the same local messages to UDP while also tailing their files unless duplicate events are acceptable.

A local UDP smoke test:

```bash
python - <<'PY'
import socket
msg = '<134>Aug  5 12:00:00 centos6 sshd[999]: NT Shield syslog test'
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(msg, ('127.0.0.1', 5514))
PY
```

## WAF and ModSecurity

The default WAF patterns cover common ModSecurity v2/v3 locations:

```json
"waf_log_files": [
  "/var/log/modsec_audit.log",
  "/var/log/httpd/modsec_audit.log",
  "/var/log/httpd/error_log",
  "/var/log/modsecurity/audit.log",
  "/var/log/nginx/modsec_audit.log",
  "/var/log/nginx/error.log"
]
```

Add the actual `SecAuditLog` path used by the server. The parser understands:

- Single-line `ModSecurity: Access denied ... [id "..."]` records.
- Serial audit transactions with `--transaction-A--` through `--transaction-Z--` sections.
- JSON audit records from ModSecurity v3 and compatible WAF loggers.
- WAF events received through UDP Syslog.

High-severity or blocked WAF records create both an event and a `DetectionAlert`. Lower-severity detections remain searchable events without manufacturing an incident for every bot that discovers `/wp-admin` exists.

## Configuration notes

`config.example.json` contains all settings. Important limits:

| Key | Default | Purpose |
|---|---:|---|
| `connection_poll_seconds` | 30 | `/proc/net` snapshot interval |
| `flush_interval_seconds` | 15 | batch/spool interval |
| `max_connections` | 10000 | maximum open sockets per snapshot |
| `max_spool_bytes` | 256 MiB | offline queue cap |
| `max_waf_event_bytes` | 512 KiB | bounded audit transaction size |
| `start_at_end` | true | skip historical content on first observation |

Validate without starting the service:

```bash
/opt/ntshield/centos6-agent/ntshield-agent \
  -config /etc/ntshield-agent/config.json \
  -check-config
```

Run one collection cycle in the foreground:

```bash
service ntshield-agent stop
/opt/ntshield/centos6-agent/ntshield-agent \
  -config /etc/ntshield-agent/config.json \
  -once
service ntshield-agent start
```

## Tests performed by CI

- RFC 3164 and RFC 5424 parsing.
- ModSecurity single-line and multiline audit parsing.
- Secret-header redaction.
- `/proc/net` IPv4/IPv6 decoding and TCP-state mapping.
- Persistent tail offsets and oversized-line handling.
- Disk spool round trip.
- Central registration, issued API key, idempotency header, and ingest contract.
- Static amd64 and 386 builds.

A successful static build is not the same as boot-testing every vendor-patched CentOS 6 kernel. Before broad deployment, run the release binary on the exact oldest host image in use and verify registration, `/proc` access, TLS, rotation, and restart behavior.
