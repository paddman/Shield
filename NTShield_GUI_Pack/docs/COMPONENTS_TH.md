# แผนผัง Component

1. **Sidebar** — Dashboard, Incidents, Endpoints, Detections, Evidence, Actions, Rules, Settings
2. **Agent Status** — Healthy/Degraded/Offline และ Last check-in
3. **Overview Cards** — Active incidents, detections, at-risk endpoints, protected endpoints
4. **Incident List** — severity, rule name, source/destination, last seen
5. **Failed Login Chart** — จำนวน 4625 ต่อช่วงเวลา
6. **Analytics Widgets** — distinct usernames, top source, top destination, process/service correlation
7. **Recent Response Actions** — ใครสั่ง, เป้าหมาย, ผลลัพธ์, rollback status
8. **NT Shield AI Analyst** — สรุปเหตุการณ์และเสนอ next action โดยให้คนอนุมัติการตอบสนอง
9. **Incident Detail** — Source, destination, PID, process, service, logon type, attempt count
10. **Quick Actions** — Block Destination, Capture Evidence, Quarantine Host, Export Report

## แนวทางใช้งานจริง

ควรสร้าง control ด้วย XAML แทนการใช้ภาพ screenshot เป็นปุ่ม เพื่อรองรับ DPI, resizing, localization และ data binding ส่วนภาพที่ตัดไว้ใช้เป็น reference หรือ background ประกอบเท่านั้น
