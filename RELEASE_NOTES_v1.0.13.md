# NT Shield v1.0.13

## Packages (local)

| File | Path |
|------|------|
| Full Setup | `artifacts/setup/NTShield-Setup-1.0.13.exe` (~133 MB) |
| Agent Setup | `artifacts/setup/NTShield-Agent-Setup-1.0.15.exe` (~58 MB) |
| Central Setup | `artifacts/setup/NTShield-Central-Setup-1.0.5.exe` (~36 MB) |
| Linux Agent | `artifacts/setup/NTShield-Linux-Agent-1.0.13-linux-x64.tar.gz` (~31 MB) |

## Publish to GitHub (after `gh auth login`)

```powershell
cd C:\data_nt\NTShieldAgent
gh release create v1.0.13 `
  artifacts\setup\NTShield-Setup-1.0.13.exe `
  artifacts\setup\NTShield-Agent-Setup-1.0.15.exe `
  artifacts\setup\NTShield-Central-Setup-1.0.5.exe `
  artifacts\setup\NTShield-Linux-Agent-1.0.13-linux-x64.tar.gz `
  --title "v1.0.13 — Auth, metrics fleet UI, Linux agent" `
  --notes-file RELEASE_NOTES_v1.0.13.md
```

## What's new

### Dashboard fleet (อลังการ)
- KPI strip: total / online / Windows / Linux / avg CPU·MEM
- Select agent → dark detail panel: CPU, MEM, DISK, load/queue, NET RX/TX, disk I/O, agent RAM
- Identity, integrity (SHA-256 / signed), policy version, Central URL
- CPU history sparkline from Central metrics samples

### Service health / metrics history (P1 foundation)
- Heartbeat fields: CPU, mem%, disk%, net rates, disk I/O, load
- Central table `agent_metrics` (last ~500 samples/agent)
- APIs: `GET /api/v1/agents/{id}`, `GET /api/v1/agents/{id}/metrics`

### Security (P0)
- Enrollment + agent/operator API keys, policy pull, audit log
- See `docs/security-auth-policy.md`

### Linux agent
- Metrics + multi-stack logs + remediation
- See `docs/linux-agent.md`
