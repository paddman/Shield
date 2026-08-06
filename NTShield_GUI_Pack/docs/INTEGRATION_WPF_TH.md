# วิธีต่อ WPF GUI เข้ากับ NT Shield Agent

## โครงสร้างที่แนะนำ

- Windows Service: เก็บ Event/Network/Process และส่ง API
- GUI: รันแยกจาก Service ด้วยสิทธิ์ผู้ใช้ปกติ
- Local IPC: Named Pipe สำหรับ status และคำสั่งที่ผ่าน allowlist
- Central API: HTTPS/mTLS สำหรับ incidents และ response approvals

## การแทนข้อมูลตัวอย่าง

1. สร้าง `DashboardViewModel` และใช้ `INotifyPropertyChanged`
2. เปลี่ยน `DataContext = Actions` เป็น ViewModel หลัก
3. Bind `ItemsSource` ของ DataGrid กับ `ObservableCollection<ResponseAction>`
4. เมื่อเลือก Incident ให้โหลดรายละเอียดเข้า right rail
5. ปุ่มตอบสนองต้องส่ง request ID, reason และ approval token

## Assets ใน WPF

ไฟล์ใน `Assets` ตั้ง Build Action เป็น `Resource` แล้วอ้างแบบ:

```xml
<Image Source="Assets/ntshield_full.png" />
```

## Compatibility

GUI ตัวอย่าง target `.NET Framework 4.8` เพื่อใช้กับ Windows Server รุ่นเก่าได้ง่ายกว่า runtime .NET รุ่นใหม่ แต่ควรทดสอบจริงกับ image ของ Windows Server ที่องค์กรใช้อยู่
