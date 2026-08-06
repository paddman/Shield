# Installation

## Architecture (สำคัญ: Agent ไม่ต่อ Dashboard โดยตรง)

```text
  [Endpoint PC/Server]              [Central host]              [Operator PC]
  NTShield.Agent  --HTTPS-->  NTShield.Server  <--  Dashboard (WPF)
  (Windows Service)                 :7443  + PostgreSQL         Settings URL
```

- **Agent** ส่ง heartbeat / telemetry ไปที่ **Central API** เท่านั้น (`Server.Url`)
- **Dashboard** อ่าน agents / incidents จาก **Central API** ตัวเดียวกัน
- ถ้า Agent ขึ้นใน Dashboard ได้ ต้องให้ **URL ตรงกันทั้งสองฝั่ง**

ตัวอย่าง URL เดียวกัน: `https://10.0.0.5:7443` หรือ `https://sentinel.corp.local:7443`

---

## Prerequisites

### Build machine

- .NET 10 SDK
- Windows x64
- Inno Setup 6 (สำหรับสร้าง Setup EXE)

### Endpoint (agent)

- Windows Server **2012 / 2012 R2 / 2016 / 2019 / 2022 / 2025** x64 (หรือ Windows 10/11 x64)
- Local Administrator for install
- **Microsoft Visual C++ Redistributable x64** (2015–2022 recommended)
- No Docker, Python, or Node.js required
- Self-contained publish embeds the .NET runtime

### Central server

- Windows or Linux hosting ASP.NET Core
- PostgreSQL 14+
- TLS certificate for HTTPS (lab: self-signed + `AllowUntrustedServerCertificate`)

---

## 1) ติดตั้ง / รัน Central Server ก่อน (จำเป็น)

Agent และ Dashboard **ไม่คุยกันโดยตรง** — ทั้งคู่ชี้ **Central** เดียวกัน

### ติดตั้ง Central แยก — Setup EXE (แนะนำ)

```powershell
cd C:\data_nt\NTShieldAgent
.\installer\build-setup-central.ps1
# → artifacts\setup\NTShield-Central-Setup-1.0.0.exe
```

รัน **Run as Administrator** → ใส่พอร์ต HTTPS (default **7443**)

| รายการ | ค่า |
|--------|-----|
| Service | `NTShieldCentral` |
| Install | `C:\Program Files\NT Shield Central` |
| Data / DB | `C:\ProgramData\NTShield\Server\central.db` (SQLite) |
| URL | `https://localhost:7443` หรือ `https://<host>:7443` |

Silent:

```powershell
.\artifacts\setup\NTShield-Central-Setup-1.0.0.exe /VERYSILENT /Port=7443
```

หรือ PowerShell:

```powershell
.\installer\install-central.ps1
```

ตรวจ health:

```powershell
# ยอมรับ self-signed
# GET https://localhost:7443/api/v1/health  → 200
# GET https://localhost:7443/api/v1/agents  → รายการ agent
```

### PostgreSQL (optional production)

ตั้ง `Database:Provider` = `Postgres` และ connection string ใน Central `appsettings.json`

API (default port **7443**):

- `GET  /api/v1/health`
- `POST /api/v1/heartbeat`
- `POST /api/v1/ingest`
- `GET  /api/v1/incidents`
- `GET  /api/v1/agents`

---

## 2) Agent แยก — Setup EXE (แนะนำบน endpoint)

### Build ตัวติดตั้ง Agent อย่างเดียว

```powershell
cd C:\data_nt\NTShieldAgent
.\installer\build-setup-agent.ps1
```

ได้ไฟล์:

```text
artifacts\setup\NTShield-Agent-Setup-1.0.5.exe
```

### ติดตั้งแบบ GUI

1. รัน **Run as Administrator**
2. หน้า **Central Server URL** ใส่ URL ของ Central เช่น `https://10.0.0.5:7443`
3. เลือกโฟลเดอร์ (ค่าเริ่มต้น `C:\Program Files\NT Shield Agent`)
4. ติ๊ก Start service หลังติดตั้ง
5. Finish

ตัวติดตั้งจะ:
- วางไฟล์ Agent + **tray icon** (`NTShield.Agent.Tray.exe`)
- เขียน `Server.Url` ใน `appsettings.json`
- ลงทะเบียน Windows Service ชื่อ **`NTShieldAgent`**
- เปิด **system tray / notification area** (ไอคอนเล็กมุม taskbar) หลัง login

### System tray icon

Windows Service อยู่ Session 0 โชว์ tray ใน user desktop ไม่ได้ จึงมี companion:

| รายการ | ค่า |
|--------|-----|
| โปรเซส | `NTShield.Agent.Tray.exe` |
| ตำแหน่ง | notification area (มุมขวาล่าง; บางทีอยู่ใน ^ overflow) |
| คลิกขวา | สถานะ service, host, Central URL, เปิด logs |
| Exit tray | ปิดแค่ไอคอน — **ไม่หยุด** service |

Start Menu → **Show tray icon** ถ้ายังไม่เห็น

### ติดตั้งแบบ Silent

```powershell
.\artifacts\setup\NTShield-Agent-Setup-1.0.5.exe `
  /VERYSILENT `
  /CentralUrl=https://10.0.0.5:7443
```

### เปลี่ยน Central URL ทีหลัง

Start Menu → **NT Shield Agent → Reconfigure Central URL**
หรือ:

```powershell
# Elevated
& "${env:ProgramFiles}\NT Shield Agent\Installer\set-agent-central-url.ps1" `
  -CentralUrl https://10.0.0.5:7443
```

แก้ไฟล์เอง:

```text
C:\Program Files\NT Shield Agent\appsettings.json
```

```json
"Server": {
  "Url": "https://10.0.0.5:7443",
  "AllowUntrustedServerCertificate": true
}
```

แล้ว `Restart-Service NTShieldAgent`

| รายการ | ค่า |
|--------|-----|
| Service | `NTShieldAgent` |
| Install | `C:\Program Files\NT Shield Agent` |
| Data | `C:\ProgramData\NTShield\Agent` |
| Logs | `C:\ProgramData\NTShield\Agent\logs` |

---

## 3) คอนฟิก Dashboard ให้เห็น Agent

Dashboard **ไม่ได้** เชื่อม Agent โดยตรง — ใส่ **Central URL เดียวกับที่ Agent ใช้**

1. เปิด **NT Shield Dashboard**
2. ไปที่ **Settings** (หรือช่อง URL บนแถบบน)
3. ใส่ เช่น `https://10.0.0.5:7443`
4. กด **Apply & Refresh**
5. หน้ารายการ Agents ควรโชว์ hostname ของ endpoint ภายใน ~1 นาที (หลัง heartbeat)

ถ้าไม่ขึ้น:

| ตรวจ | คำสั่ง / จุด |
|------|----------------|
| Central ขึ้นไหม | `Invoke-WebRequest https://...:7443/api/v1/health` |
| Agent service | `Get-Service NTShieldAgent` |
| Agent URL | เปิด `appsettings.json` → `Server.Url` |
| Firewall | เปิดพอร์ต **7443** จาก endpoint → central |
| Logs | `C:\ProgramData\NTShield\Agent\logs` |

Lab ใช้ self-signed: บน Agent ตั้ง `Server.AllowUntrustedServerCertificate = true` (ค่า default ใน dev)

---

## 4) Full stack Setup (Agent + Dashboard เครื่องเดียวกัน)

```powershell
.\installer\build-setup.ps1
# → artifacts\setup\NTShield-Setup-*.exe
```

เลือก Full / Agent only / Dashboard only ใน wizard

---

## 5) ติดตั้ง Agent แบบ PowerShell (ไม่ใช้ EXE)

```powershell
dotnet publish src\NTShield.Agent\NTShield.Agent.csproj `
  -c Release -r win-x64 --self-contained true `
  -o .\artifacts\agent-win-x64

# Elevated
.\installer\install-agent.ps1 `
  -SourceDir .\artifacts\agent-win-x64 `
  -CentralUrl https://sentinel.example.local:7443
```

## Upgrade / Uninstall

```powershell
.\installer\upgrade-agent.ps1 -SourceDir .\artifacts\agent-win-x64
.\installer\uninstall-agent.ps1
# optional wipe of SQLite + logs:
.\installer\uninstall-agent.ps1 -RemoveData
```

หรือ Uninstall จาก **Apps & features** / Start Menu (ตัวติดตั้ง Agent แยก)

---

## Audit policy (endpoints)

For rich detection, enable advanced audit on monitored servers:

- Logon/Logoff success & failure
- Account Management
- Process Creation (4688) — optionally with command line auditing
- Object Access / Filtering Platform Connection (5156/5157) if using Windows Filtering Platform auditing

## mTLS (optional)

1. Issue client certs per agent; place PFX on endpoint.
2. Set agent `Server:EnableMtls=true` and certificate path.
3. Set server `Security:EnableMtls=true` and configure Kestrel client certificate mode.
