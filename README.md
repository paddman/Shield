# NT Shield

![NT Shield — Unified AI Cyber Defense as a Service](assets/branding/ntshield-platform-hero.png)

**Unified AI Cyber Defense as a Service** — endpoint agents, Central API, cross-host correlation, AI Analyst, responsive Web Control Center, and native Windows Dashboard in one repository.

Windows Server **2012 → 2025** · Windows 10/11 · modern Linux distributions · CentOS 6 compatibility agent · self-contained installers.

NT Shield detects **password spray, brute force, lateral movement, suspicious processes/services, WAF events, syslog indicators, and abnormal network activity**. It preserves the context analysts need: which host, user, process, Windows service, IP, port, and related incident were involved.

The safe default is **IDS / detect-only**. IPS containment and remote response remain optional and operator-controlled.

## Platform highlights

- **Central Control Center:** responsive login and live dashboard served directly by Central at `https://<CENTRAL>:7443/`.
- **Multi-platform fleet:** Windows Agent + Tray, Linux Agent, and a lightweight CentOS 6 Go agent.
- **Cross-host correlation:** joins endpoint events and connections into incidents and lateral-movement campaigns.
- **NT Shield Brain:** tenant-isolated AI investigation with Qwen-compatible endpoints and human approval guardrails.
- **WAF/syslog intake:** receives infrastructure and application security signals in the same control plane.
- **Offline resilience:** local SQLite WAL queue with retry/backoff before telemetry reaches Central.

## Control Center preview

![NT Shield Control Center dashboard](docs/screenshots/control-center-dashboard.png)

The screenshots below are code-rendered desktop and mobile login previews. The dashboard preview uses synthetic telemetry for visual validation; the shipped Control Center reads live Central APIs and does not inject mock data.

| Desktop | Mobile |
|---|---|
| ![NT Shield desktop login](docs/screenshots/control-center-login-desktop.png) | ![NT Shield mobile login](docs/screenshots/control-center-login-mobile.png) |

---

## Build installers

This new repository does not claim a prebuilt release yet. Build version **1.1.0** from source into `artifacts/setup` and publish a GitHub Release only after validating the packages on the supported operating systems.

| File | Platform | Description | Size |
|------|----------|-------------|------|
| **NTShield-Setup-1.1.0.exe** | Windows | Central + Agent + Tray + native Dashboard + Web Control Center | Build-dependent |
| **NTShield-Agent-Setup-1.1.0.exe** | Windows | Agent + Tray | Build-dependent |
| **NTShield-Central-Setup-1.1.0.exe** | Windows | Central API + responsive Web Control Center | Build-dependent |
| **NTShield-Linux-Agent-1.1.0-linux-x64.tar.gz** | Linux x64 | Metrics + logs + auth + allowlisted remediation | Build-dependent |

```mermaid
%%{init: {'theme':'base', 'themeVariables': { 'primaryColor':'#FFC400','primaryTextColor':'#171C26','primaryBorderColor':'#171C26','lineColor':'#B37A00','secondaryColor':'#FFF4C2','tertiaryColor':'#F5F7FA'}}}%%
flowchart TB
  subgraph DL["📦 Download what you need"]
    F["Full Setup.exe<br/>Central + Agent + Dashboard"]
    A["Agent Setup.exe<br/>Windows endpoints"]
    C["Central Setup.exe<br/>server only"]
    L["Linux tar.gz<br/>install-agent.sh"]
  end
  subgraph ROLE["Where it runs"]
    Srv["🖥️ Central server<br/>:7443 HTTPS"]
    Win["💻 Windows endpoints"]
    Lin["🐧 Linux endpoints"]
    Ops["👤 Operator PC<br/>Dashboard"]
  end
  F --> Srv
  F --> Win
  F --> Ops
  C --> Srv
  A --> Win
  L --> Lin
  Win -->|heartbeat + ingest| Srv
  Lin -->|heartbeat + ingest + metrics| Srv
  Ops -->|HTTPS API| Srv
```

### Quick install

| Scenario | Steps |
|----------|--------|
| **One Windows server (lab/POC)** | Full Setup as Admin → **Full stack** → Dashboard `https://localhost:7443` |
| **Extra Windows PC** | Agent Setup → Central **IP** + port **7443** (not `localhost`) |
| **Linux host** | See bash block below |
| **Silent Windows agent** | `NTShield-Agent-Setup-1.1.0.exe /VERYSILENT /ServerHost=10.0.0.5 /Port=7443` |

```bash
# Linux (metrics + nginx/PHP/Docker/Node logs + allowlisted remediation)
tar -xzf NTShield-Linux-Agent-1.1.0-linux-x64.tar.gz
cd NTShield-Linux-Agent-1.1.0-linux-x64
sudo ./install-agent.sh --host <CENTRAL_IP> --port 7443
# status: cat /var/lib/ntshield/status.json
# docs: docs/linux-agent.md
```

---

## Big picture — system architecture

```mermaid
%%{init: {'theme':'base', 'themeVariables': { 'primaryColor':'#FFC400','primaryTextColor':'#171C26','lineColor':'#16A36A'}}}%%
flowchart TB
  subgraph FLEET["Endpoint fleet"]
    direction LR
    W1["Windows Agent<br/>Service + Tray"]
    W2["Windows Agent<br/>…"]
    LX["Linux Agent<br/>systemd"]
  end

  subgraph CENTRAL["Central Server :7443"]
    direction TB
    API["ASP.NET Core API<br/>register · heartbeat · ingest · actions"]
    CORR["Cross-host Correlator<br/>+ LateralMovementTracker"]
    SIG["Syslog UDP :5514<br/>+ OSS signatures"]
    DB[("SQLite default<br/>or PostgreSQL")]
    API --> CORR --> DB
    SIG --> DB
  end

  subgraph SOC["Operator"]
    DASH["Web + WPF Dashboard<br/>live data · versions · approved response"]
  end

  W1 -->|"HTTPS<br/>telemetry + HB"| API
  W2 -->|"HTTPS"| API
  LX -->|"HTTPS heartbeat"| API
  DASH -->|"HTTPS<br/>read + approve actions"| API
  API -.->|"PendingActions<br/>on next heartbeat"| W1
  API -.->|"PendingActions"| W2
```

> **Important:** Agent never talks to Dashboard. Both talk to **Central**.
> Remote agents must use Central **IP:7443**, not `localhost`.

---

## Data flow — collection → detection → central → response

```mermaid
sequenceDiagram
  autonumber
  participant OS as Windows OS
  participant Ag as Agent Service
  participant SQ as Local SQLite<br/>offline queue
  participant Ce as Central API
  participant Co as Correlator
  participant Da as Dashboard

  OS->>Ag: EventLog (4624/4625/4688/…)
  OS->>Ag: TCP/UDP table diff
  OS->>Ag: Process / Service / Tasks
  Ag->>Ag: Rule engine (IDS/IPS)
  Ag->>SQ: store + enqueue outbound
  Ag->>Ce: POST /api/v1/ingest
  Ag->>Ce: POST /api/v1/agents/heartbeat
  Ce->>Co: correlate cross-host
  Co->>Ce: incidents / campaigns
  Da->>Ce: GET agents / incidents / threats
  Da->>Ce: POST /api/v1/actions (approved)
  Note over Ce,Ag: Next heartbeat delivers PendingActions
  Ce-->>Ag: BlockIp / Isolate / StopService / …
  Ag->>OS: netsh / WMI / Kill (if allowed)
```

---

## Multi-host lateral path (what makes NT Shield distinctive)

```mermaid
flowchart LR
  subgraph SRC["Source host 10.0.105.35"]
    P["PID 1684<br/>svchost"]
    Svc["IPTVManagementService"]
    P --- Svc
  end
  subgraph DST1["Dest 10.0.105.190"]
    E1["4625 × N<br/>password spray"]
  end
  subgraph DST2["Dest 10.0.105.200"]
    E2["4624 type 3<br/>network logon"]
  end
  subgraph CTR["Central"]
    INC["Incident hops"]
    CAMP["Threat Campaign<br/>A → B → C"]
    INC --> CAMP
  end

  Svc -->|"TCP :80 / :445<br/>connection batch"| DST1
  Svc --> DST2
  DST1 -->|"events batch"| INC
  DST2 --> INC
  SRC -->|"connections batch<br/>+ process attribution"| INC
```

```mermaid
sequenceDiagram
  participant S as Source Agent
  participant D as Dest Agent
  participant C as Central

  S->>S: GetExtendedTcpTable diff
  S->>S: Resolve PID → process + services
  S->>C: connections/batch
  D->>D: Security 4625 spray
  D->>C: events/batch
  C->>C: Join by IP + time window + user
  C->>C: FormatDisplay analyst view
  Note over C: Campaign: 10.0.105.35 --spray--> 10.0.105.190 --logon--> 10.0.105.200
```

---

## Agent internals (Windows)

```mermaid
flowchart TB
  subgraph COLLECT["Collectors"]
    EV["EventLogWatcher<br/>Security + System"]
    NET["IP Helper<br/>TCP/UDP snapshot diff"]
    PR["Process / WMI"]
    SV["Service resolver"]
    TK["Scheduled Tasks"]
  end

  subgraph CORE["Core loops"]
    DET["Detection<br/>rules.json"]
    RESP["Response<br/>IDS or IPS"]
    FLUSH["Flush outbound"]
    HB["Heartbeat"]
    ST["status.json"]
  end

  subgraph LOCAL["Local store"]
    DB[("SQLite WAL<br/>agent.db")]
    Q[("outbound_queue")]
  end

  subgraph UI["User on endpoint"]
    TRAY["Tray icon"]
    MINI["Mini dashboard"]
    EDIT["Edit Central IP/Port"]
    TEST["Test connection"]
  end

  EV --> DET
  NET --> DET
  PR --> DB
  SV --> DET
  TK --> DB
  DET --> RESP
  DET --> DB
  DB --> Q
  Q --> FLUSH
  FLUSH -->|HTTPS| CEN["Central"]
  HB --> CEN
  TRAY --> MINI
  TRAY --> EDIT
  TRAY --> TEST
  ST --> TRAY
```

### IDS vs IPS mode

```mermaid
flowchart TD
  A[Alert raised] --> B{Mode?}
  B -->|IDS default| C[LogOnly<br/>alert → Central / syslog]
  B -->|IPS| D{Severity ≥ AutoBlockMin?}
  D -->|Yes| E[netsh BlockSource / BlockDest]
  D -->|No| C
  C --> F[Evidence optional]
  E --> F
  G[Dashboard operator] -->|POST /actions approved| H[PendingActions queue]
  H -->|next heartbeat| I[Agent executes<br/>firewall / stop service / kill]
```

| Mode | Config | Behavior |
|------|--------|----------|
| **IDS** | `Agent:Mode=Ids` / `DetectOnly=true` | Detect + log; no auto contain |
| **IPS** | `Mode=Ips` / sample `config/appsettings.Ips.sample.json` | Auto-block High+ source/dest IP |
| **Operator** | Dashboard Firewall panel | Always via Central → agent heartbeat |

---

## Central internals

```mermaid
flowchart LR
  subgraph IN["Ingress"]
    H1["/api/v1/agents/*"]
    H2["/api/v1/ingest"]
    H3["/api/v1/actions"]
    H4["Syslog UDP :5514"]
  end
  subgraph ENG["Engines"]
    AC["ActionService<br/>durable pending_actions"]
    IG["IngestService"]
    XC["CrossHostCorrelator"]
    LT["LateralMovementTracker<br/>durable campaigns"]
    SG["OpenSourceSignatureEngine"]
  end
  subgraph STORE["Persistence"]
    SQ[(SQLite central.db)]
    PG[(PostgreSQL optional)]
  end

  H1 --> AC
  H1 --> SQ
  H2 --> IG --> XC --> LT
  IG --> SQ
  H3 --> AC --> SQ
  H4 --> SG --> SQ
  XC --> SQ
  LT --> SQ
  SQ -.-> PG
```

### Health & versions

```bash
curl -k https://localhost:7443/api/v1/health
# { "status":"ok", "product":"NT Shield Central", "version":"1.0.11", ... }

curl -k https://localhost:7443/api/v1/agents
# online, hostIp, centralUrl, agentVersion, platform, lastError
```

| Surface | Shows version |
|---------|----------------|
| Dashboard sidebar / Settings / title | Dashboard vX · Central vY |
| Agent heartbeat / Endpoints grid | `agentVersion` |
| Tray menu | `NT Shield Agent vX` |
| `CONNECTION.txt` | Central product version |
| `GET /api/v1/health` | `version` / `productVersion` |

---

## Dashboard map

```mermaid
flowchart TB
  subgraph DASH["WPF Dashboard"]
    D1["Dashboard — KPIs live"]
    D2["Incidents"]
    D3["Lateral Paths / Campaigns"]
    D4["Endpoints — fleet inventory"]
    D5["Rules catalog"]
    D6["Firewall control"]
    D7["Settings — URL + About versions"]
  end
  D1 --> API["Central HTTPS"]
  D2 --> API
  D3 --> API
  D4 --> API
  D5 --> API
  D6 --> API
  D7 --> API
```

| Page | Data source |
|------|-------------|
| Dashboard | Live incidents / agents only — **no mock data** |
| Endpoints | `/api/v1/agents` (online/offline, OS, Central URL, last error) |
| Lateral Paths | `/api/v1/threats` + hop path |
| Firewall | `POST /api/v1/actions` → agent on next HB |
| Settings | Central URL + **About / Versions** |

---

## Deploy topology examples

### A) Lab — one machine

```mermaid
flowchart LR
  M["Single Windows host"]
  M --> C["Central :7443"]
  M --> A["Agent"]
  M --> D["Dashboard"]
  A --> C
  D --> C
```

### B) Production-like — server + endpoints

```mermaid
flowchart TB
  subgraph Server["Security server"]
    Ce["Central"]
    Da["Dashboard optional"]
  end
  subgraph Endpoints["Endpoints"]
    E1["Win Agent"]
    E2["Win Agent"]
    E3["Linux Agent"]
  end
  E1 -->|"https://SERVER:7443"| Ce
  E2 --> Ce
  E3 --> Ce
  Da --> Ce
```

| Wrong | Right |
|-------|--------|
| Agent2 `Server.Url = https://localhost:7443` | `https://<Central-IP>:7443` |
| Dashboard different URL than Agent | **Same** Central base URL |
| Central stopped during install | Start Central first; open firewall TCP 7443 |

---

## Threat coverage (chart + table)

```mermaid
mindmap
  root((NT Shield detection))
    Credential Access
      Internal password spray
      Distributed spray
      Brute force
      Spray then success
      Suspicious account names
    Lateral Movement
      Multiple internal targets
      Auth port fan-out
      Explicit credentials 4648
      Network logon burst
      RDP logon burst
    Privilege
      Priv logon after failures
      Group change 4728/4732
    Persistence
      New service 4697/7045
      Scheduled task 4698
      Account created 4720
    Execution heuristics
      Process burst 4688
      LOLBins / temp paths
      Suspicious cmdline
    Network noise
      WFP 5156/5157 bursts
    Syslog signatures
      SSH/RDP brute keywords
      Webshell / mimikatz tokens
```

| Category | Example rule IDs | Primary signals |
|----------|------------------|-----------------|
| Credential Access | `INTERNAL_PASSWORD_SPRAY`, `BRUTE_FORCE_SINGLE_ACCOUNT` | 4625 volume / patterns |
| Lateral | `MULTIPLE_INTERNAL_TARGETS`, `RDP_LOGON_BURST` | TCP fan-out + logon types |
| Privilege | `PRIVILEGED_LOGON_AFTER_FAILURES` | 4625→4624 + 4672 |
| Persistence | `NEW_SERVICE_INSTALLED`, `SCHEDULED_TASK_CREATED` | 4697 / 7045 / 4698 |
| Full list | [`config/rules.json`](config/rules.json) · [`docs/threat-coverage.md`](docs/threat-coverage.md) | |

```mermaid
pie showData
  title Detection signal mix focus
  "Credential / logon" : 35
  "Lateral / network" : 30
  "Persistence / privilege" : 20
  "Process heuristics" : 10
  "Syslog signatures" : 5
```

---

## API surface (Central)

```mermaid
flowchart LR
  subgraph Agents["Agent-facing"]
    R["POST /api/v1/agents/register"]
    H["POST /api/v1/agents/heartbeat"]
    I["POST /api/v1/ingest"]
    E["POST /api/v1/events/batch"]
    N["POST /api/v1/connections/batch"]
  end
  subgraph Ops["Operator-facing"]
    GA["GET /api/v1/agents"]
    GI["GET /api/v1/incidents"]
    GT["GET /api/v1/threats…"]
    PA["POST /api/v1/actions"]
    HE["GET /api/v1/health"]
    SG["GET /api/v1/signatures"]
  end
```

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/v1/health` | Health + **version** + syslog info |
| POST | `/api/v1/agents/register` | Enroll agent |
| POST | `/api/v1/agents/heartbeat` | Presence + deliver pending actions |
| GET | `/api/v1/agents` | Fleet inventory |
| POST | `/api/v1/ingest` | Telemetry batch |
| GET/POST | `/api/v1/incidents` | Incidents |
| POST/GET | `/api/v1/actions` | Operator response queue |
| GET | `/api/v1/threats` · `/threats/{id}/path` | Campaigns / hops |
| GET | `/api/v1/signatures` | Loaded OSS signatures |
| UDP | `:5514` | Syslog → signature engine |

---

## Solution map (code)

```mermaid
flowchart TB
  subgraph SRC["src/"]
    AG["Agent Windows"]
    TR["Agent.Tray"]
    LX["Agent.Linux"]
    SV["Server Central"]
    DA["Dashboard WPF"]
    DE["Detection"]
    RE["Response"]
    CO["Collectors.Windows"]
    ST["Storage SQLite"]
    TRN["Transport HTTPS + Syslog"]
    SH["Shared contracts"]
  end
  AG --> DE
  AG --> RE
  AG --> CO
  AG --> ST
  AG --> TRN
  TR --> AG
  LX --> SH
  LX --> TRN
  SV --> SH
  DA --> SH
  DE --> SH
  RE --> SH
```

```
NTShield.sln
├── src/
│   ├── NTShield.Agent          # Windows service
│   ├── NTShield.Agent.Tray     # tray + mini UI + IP editor
│   ├── NTShield.Agent.Linux    # Linux client
│   ├── NTShield.Server         # Central API
│   ├── NTShield.Dashboard      # WPF SOC console
│   ├── NTShield.Detection
│   ├── NTShield.Response
│   ├── NTShield.Collectors.Windows
│   ├── NTShield.Storage
│   ├── NTShield.Transport
│   └── NTShield.Shared
├── installer/   # Inno Setup + linux/*.sh
├── config/      # rules.json · signatures · samples
├── docs/
└── tests/
```

---

## Stack

| Layer | Technology |
|-------|------------|
| Language | C# / **.NET 10** |
| Windows Agent | `net10.0-windows`, **win-x64 self-contained** service |
| Linux Agent | `net10.0`, **linux-x64 self-contained**, systemd — CPU/RAM/disk/net/I/O, multi-stack logs, remediation |
| Local DB | SQLite WAL + offline queue |
| Central DB | **SQLite default** · PostgreSQL optional |
| UI | Responsive Web Control Center + WPF Dashboard + WinForms tray |
| Transport | HTTPS · optional mTLS · optional syslog UDP |
| Logging | Serilog rolling files |
| Installers | Inno Setup (Windows) · bash + tar.gz (Linux) |

---

## Build from source

```powershell
cd C:\data_nt\Shield   # or your clone path
dotnet restore
dotnet build NTShield.sln -c Release
dotnet test NTShield.sln -c Release

# Windows packages
.\installer\build-setup.ps1 -Version 1.1.0          # Full
.\installer\build-setup-agent.ps1 -Version 1.1.0    # Agent
.\installer\build-setup-central.ps1 -Version 1.1.0  # Central

# Linux package (full metrics + logs + response)
.\installer\build-agent-linux.ps1 -Version 1.1.0
# → artifacts\setup\NTShield-Linux-Agent-1.1.0-linux-x64.tar.gz
```

### Publish agent only

```powershell
dotnet publish src/NTShield.Agent/NTShield.Agent.csproj `
  -c Release -r win-x64 --self-contained true `
  -p:PublishSingleFile=true `
  -p:IncludeNativeLibrariesForSelfExtract=true `
  -o artifacts/agent-win-x64
```

---

## Install paths (Windows)

| Item | Path |
|------|------|
| Agent service | `NTShieldAgent` |
| Central service | `NTShieldCentral` |
| Agent install | `C:\Program Files\NT Shield Agent` or `...\NT Shield\Agent` |
| Data | `C:\ProgramData\NTShield\` |
| Agent logs | `...\Agent\logs` · `status.json` |
| Central logs | `...\Server\logs` · `central.db` |

**Tray (Windows):** Edit Central IP/Port · Test connection · Mini dashboard · shows **version**.

**Linux:** `/opt/ntshield/agent` · `systemctl status ntshield-agent`

---

## Roadmap (high level)

```mermaid
timeline
  title NT Shield product roadmap
  section Phase 0
    Durable actions + fleet inventory + versions + Linux client : done
  section Phase 1
    Enrollment token + API auth + policy + audit : done (v1.0.13)
  section Phase 2
    Timeline + process tree + isolate + evidence : next
  section Phase 3
    Light EPP hash/quarantine : planned
  section Phase 4
    Full Linux collectors journald/ss/proc : planned
  section Later
    Scale · reports · XDR connectors : planned
```

Details: [`docs/roadmap-trellix-class.md`](docs/roadmap-trellix-class.md)

---

## Documentation

| Doc | Topic |
|-----|--------|
| [Architecture](docs/architecture.md) | Sequence + modules |
| [Installation](docs/installation.md) | Deploy guide |
| [Detection rules](docs/detection-rules.md) | Rule engine |
| [Threat coverage](docs/threat-coverage.md) | What we detect / track |
| [IDS / IPS mode](docs/ids-ips-mode.md) | Mode switch |
| [Syslog + signatures](docs/syslog-and-signatures.md) | UDP 5514 |
| [Layered Antivirus](docs/antivirus.md) | Windows Agent EPP pipeline |
| [Incident response](docs/incident-response.md) | IR workflow |
| [Threat model](docs/threat-model.md) | Security assumptions |
| [Known limitations](docs/known-limitations.md) | Honest limits |
| [Linux agent](installer/linux/README.md) | Linux install |
| [Windows Server 2012](docs/windows-server-2012.md) | Legacy OS notes |

---

## What NT Shield does **not** do

```mermaid
flowchart LR
  X1["✗ Attack / scan other hosts from agent"]
  X2["✗ Clear Security Event Log"]
  X3["✗ Auto kill/block in IDS mode"]
  X4["✗ Agent ↔ Dashboard direct link"]
  X5["✗ Full cloud NGAV / email XDR yet"]
```

---

## License

Proprietary — NT Shield Team / internal use.

**Repo:** https://github.com/paddman/Shield
**Releases:** https://github.com/paddman/Shield/releases
