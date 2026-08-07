# NT Shield AI Analyst Web

หน้า `AI Analyst` ใน Central Web Dashboard เป็น Evidence-first investigation view:

- เลือก Incident จากข้อมูลจริงของ `/api/v1/incidents`
- แสดง Verdict, Confidence, Attack Chain, Evidence ledger, Alternative explanation และ Missing evidence
- ปุ่ม `วิเคราะห์ Incident` จะลองเรียก Central → NT Shield Brain
- หาก Brain ไม่พร้อมหรือ timeout หน้าเว็บจะแสดง `Central Evidence engine` และไม่อ้างว่าเป็นคำตอบจาก LLM
- ทุก Response เป็นข้อเสนอ และปุ่มอนุมัติจะส่ง Action แบบมี `approved=true` หลัง Operator กดเท่านั้น
- หน้าเว็บจะไม่ส่งคำสั่งแบบ broadcast หากหา `TargetAgentId` ไม่พบ

## Brain bridge

Central รองรับ endpoint:

```http
POST /api/v1/incidents/{incident_id}/ai/analyze
```

ตั้งค่าบน Central ผ่าน environment file หรือ secret manager เท่านั้น:

```text
AIAnalyst__Enabled=true
AIAnalyst__BaseUrl=http://127.0.0.1:8088
AIAnalyst__TenantId=production
AIAnalyst__ApiKey=<server-side-brain-tenant-key>
AIAnalyst__SkipTlsVerify=false
AIAnalyst__TimeoutSeconds=90
```

`AIAnalyst__ApiKey` ไม่ควรอยู่ใน Git, browser storage, HTML หรือ Agent configuration. Central เป็นผู้ส่งต่อ key ไปยัง Brain ส่วน Browser ใช้เฉพาะ Operator API Key กับ Central.

## Approval boundary

AI Analyst ไม่มีสิทธิ์รัน shell หรือเรียก Agent โดยตรง การตอบสนองต้องผ่าน:

```text
Evidence → Analyst recommendation → Operator approval → Central action queue → Agent → Audit
```

การทดสอบควรยืนยันทั้งกรณี Brain พร้อมใช้งานและกรณี deterministic fallback รวมถึงยืนยันว่า Action ที่ไม่ผ่านปุ่มอนุมัติไม่ถูกส่งเข้า queue.
