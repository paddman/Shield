# Threat Coverage & Multi-host Tracking

> **ขอบเขต:** ระบบนี้ **ตรวจจับ / ตามรอย / รายงาน** ภัยคุกคามเท่านั้น
> **ไม่** โจมตี แพร่กระจาย หรือ “คุกคาม” เครื่องอื่น

## ภัยคุกคามที่ตรวจได้

| หมวด | ชื่อ | Rule ID | Event / Signal | ตามรอยข้ามเครื่อง |
|------|-----|---------|----------------|-------------------|
| Credential Access | Internal Password Spray | `INTERNAL_PASSWORD_SPRAY` | 4625 | Source process/service → dest |
| Credential Access | Distributed Spray | `DISTRIBUTED_PASSWORD_SPRAY` | 4625 multi-source | Many → one dest |
| Credential Access | Brute Force | `BRUTE_FORCE_SINGLE_ACCOUNT` | 4625 | Source→dest |
| Credential Access | Spray Then Success | `SPRAY_THEN_SUCCESS` | 4625→4624 | Hop + credential theft signal |
| Credential Access | Suspicious Names | `SUSPICIOUS_ACCOUNT_NAMES` | 4624/4625 volume | Gated by count |
| Lateral Movement | Multi Internal Targets | `MULTIPLE_INTERNAL_TARGETS` | TCP auth ports | Fan-out map |
| Lateral Movement | Auth Port Fan-out | `LATERAL_AUTH_PORT_SCAN` | TCP scan pattern | Prep for pivot |
| Lateral Movement | Explicit Credentials | `EXPLICIT_CREDENTIALS_LATERAL` | 4648 | Origin host |
| Lateral Movement | Network Logon Burst | `NETWORK_LOGON_BURST` | 4624 type 3 | SMB/WinRM style |
| Lateral Movement | RDP Logon Burst | `RDP_LOGON_BURST` | 4624/4625 type 10/7 | RDP path |
| Privilege | Priv Logon After Failures | `PRIVILEGED_LOGON_AFTER_FAILURES` | 4625→4624+4672 | After spray success |
| Privilege | Group Change | `PRIVILEGED_GROUP_CHANGE` | 4728/4732 | Local + post-pivot |
| Persistence | New Service | `NEW_SERVICE_INSTALLED` | 4697/7045 | After foothold |
| Persistence | Scheduled Task | `SCHEDULED_TASK_CREATED` | 4698 | After foothold |
| Persistence | Account Created | `ACCOUNT_CREATED` | 4720 | After foothold |

## ตามรอยไปยังเครื่องอื่น (Lateral Path)

เมื่อ agent ติดตั้งทั้งต้นทางและปลายทาง Central จะ:

1. สร้าง **Incident** ต่อ hop (source IP/process/service → destination auth)
2. รวม hop เป็น **Threat Campaign** ผ่าน `LateralMovementTracker`
3. เชื่อม pivot: ถ้าเครื่อง B เคยเป็นปลายทาง แล้วกลายเป็นต้นทางไป C → chain `A → B → C`

### API

| Method | Path | ความหมาย |
|--------|------|----------|
| GET | `/api/v1/threats/catalog` | รายการภัยคุกคามที่รองรับ |
| GET | `/api/v1/threats` | campaigns ล่าสุด |
| GET | `/api/v1/threats/{id}` | รายละเอียด campaign |
| GET | `/api/v1/threats/{id}/path` | path/hops สำหรับ analyst |
| GET | `/api/v1/threats/by-host/{hostOrIp}` | หาทุก threat ที่แตะ host/IP นี้ |

### ตัวอย่าง path

```
10.0.105.35 (PID 1684 svchost / IPTVManagementService)
    --password_spray:80--> 10.0.105.190
    --network_logon:445--> 10.0.105.200
```

## สิ่งที่ระบบจะไม่ทำ

- ไม่ scan/โจมตีเครื่องอื่นจาก agent
- ไม่ส่ง payload ไปยังเป้าหมาย
- ไม่ kill/block โดยอัตโนมัติ (DetectOnly + approval)
- ไม่ clear Security Event Log

## การติดตั้งเพื่อตามรอยครบ

ติดตั้ง agent บน **ทุก host ที่สำคัญ** (อย่างน้อย workstation/jump + servers ที่เป็นเป้าหมาย auth)
แล้ว query:

```http
GET /api/v1/threats/by-host/10.0.105.35
GET /api/v1/threats/{campaignId}/path
```
