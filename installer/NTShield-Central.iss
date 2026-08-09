; NT Shield Central — dedicated Central API installer (Windows Service)
; Build with: installer\build-setup-central.ps1
; Requires: Inno Setup 6 + published artifacts under repo\artifacts\server-win-x64\
;
; Architecture:
;   Agent  -->  THIS Central API  <--  Dashboard
;
; Silent example:
;   NTShield-Central-Setup-1.3.1.exe /VERYSILENT /Port=7443 /PublicHost=shield.example.go.th

#define MyAppName "NT Shield Central"
#ifndef MyAppVersion
  #define MyAppVersion "1.3.1"
#endif
#define MyAppPublisher "NT Shield Team"
#define MyAppURL "https://github.com/paddman/Shield"

#ifndef SourceRoot
  #define SourceRoot ".."
#endif

[Setup]
AppId={{C9E5F1A3-7D46-6B0C-1A23-0E4F3D2C1B99}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
DefaultDirName={autopf}\NT Shield Central
DefaultGroupName=NT Shield Central
DisableProgramGroupPage=no
OutputDir={#SourceRoot}\artifacts\setup
OutputBaseFilename=NTShield-Central-Setup-{#MyAppVersion}
SetupIconFile={#SourceRoot}\assets\icons\NTShield.ico
UninstallDisplayIcon={app}\NTShield.ico
SetupMutex=NTShieldCentralSetupMutex
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
WizardImageFile={#SourceRoot}\assets\installer\WizardImage.bmp,{#SourceRoot}\assets\installer\WizardImage@2x.bmp
WizardSmallImageFile={#SourceRoot}\assets\installer\WizardSmallImage.bmp,{#SourceRoot}\assets\installer\WizardSmallImage@2x.bmp
WizardImageStretch=yes
WizardImageBackColor=clWhite
WizardImageAlphaFormat=none
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=6.1sp1
DisableWelcomePage=no
SetupLogging=yes
CloseApplications=force
CloseApplicationsFilter=*.exe,*.dll
RestartApplications=no
AppCopyright=Copyright (C) NT Shield Team
VersionInfoCompany=NT Shield Team
VersionInfoProductName=NT Shield Central
VersionInfoDescription=NT Shield Central Server Setup

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Messages]
WelcomeLabel1=NT Shield Central Setup
WelcomeLabel2=ยินดีต้อนรับสู่ตัวติดตั้ง Central Server%n%nCentral คือศูนย์ควบคุมที่ Agent ส่ง telemetry และ Operator ใช้อนุมัติ response%n%nการติดตั้งใหม่เปิด API authentication เป็นค่าเริ่มต้น สร้าง EnrollmentToken, OperatorApiKey และ action-signing key ใน protected secrets.json%n%nThis installs the authenticated Central API Windows Service on HTTPS port 7443.
FinishedHeadingLabel=ติดตั้ง Central สำเร็จ
FinishedLabelNoIcons=NT Shield Central ติดตั้งเรียบร้อยแล้ว!
FinishedLabel=NT Shield Central ติดตั้งเรียบร้อยแล้ว!%n%nService: NTShieldCentral%nURL: https://localhost:<port>%n%nอ่าน EnrollmentToken / OperatorApiKey จาก protected Server\secrets.json ด้วยสิทธิ์ Administrator%nแจก central.cer ให้ Agent ถ้าไม่ได้ใช้ public PKI
ClickFinish=คลิก Finish เพื่อปิดตัวติดตั้ง
ButtonNext=Next >
ButtonBack=< Back
ButtonCancel=Cancel
ButtonFinish=Finish
SelectDirLabel3=เลือกโฟลเดอร์ติดตั้ง Central
WizardSelectDir=เลือกตำแหน่งติดตั้ง
WizardReady=พร้อมติดตั้ง
WizardInstalling=กำลังติดตั้ง...
StatusExtractFiles=กำลังติดตั้งไฟล์...

[Tasks]
Name: "startservice"; Description: "Start Central service after install"; GroupDescription: "Service:"; Flags: checkedonce
Name: "desktopicon"; Description: "Create a &desktop icon"; GroupDescription: "Additional icons:"; Flags: checkedonce
Name: "openfirewall"; Description: "Open Windows Firewall for Central HTTPS port"; GroupDescription: "Network:"; Flags: unchecked

[Files]
Source: "{#SourceRoot}\installer\setup-helpers\stop-central-for-upgrade.ps1"; DestDir: "{tmp}"; Flags: dontcopy

Source: "{#SourceRoot}\assets\icons\NTShield.ico"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceRoot}\artifacts\server-win-x64\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#SourceRoot}\assets\icons\NTShield.ico"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceRoot}\installer\templates\CONNECTION.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceRoot}\installer\templates\Open-Central-Info.cmd"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceRoot}\config\signatures\opensource-signatures.json"; DestDir: "{app}\signatures"; Flags: ignoreversion skipifsourcedoesntexist
Source: "{#SourceRoot}\installer\setup-helpers\register-central-service.ps1"; DestDir: "{app}\Installer"; Flags: ignoreversion
Source: "{#SourceRoot}\installer\setup-helpers\unregister-central-service.ps1"; DestDir: "{app}\Installer"; Flags: ignoreversion
Source: "{#SourceRoot}\installer\setup-helpers\stop-central-for-upgrade.ps1"; DestDir: "{app}\Installer"; Flags: ignoreversion
Source: "{#SourceRoot}\installer\setup-helpers\write-connection-info.ps1"; DestDir: "{app}\Installer"; Flags: ignoreversion
Source: "{#SourceRoot}\installer\setup-helpers\regenerate-central-cert.ps1"; DestDir: "{app}\Installer"; Flags: ignoreversion

[Dirs]
Name: "{commonappdata}\NTShield\Server"
Name: "{commonappdata}\NTShield\Server\logs"
Name: "{commonappdata}\NTShield\Server\certs"

[Icons]
Name: "{group}\Central Install Folder"; Filename: "{app}"; IconFilename: "{app}\NTShield.ico"
Name: "{group}\Central Logs"; Filename: "{commonappdata}\NTShield\Server\logs"; IconFilename: "{app}\NTShield.ico"
Name: "{group}\Connection Info"; Filename: "{app}\Open-Central-Info.cmd"; IconFilename: "{app}\NTShield.ico"; WorkingDir: "{app}"
Name: "{group}\Central Folder"; Filename: "{app}"; IconFilename: "{app}\NTShield.ico"
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"; IconFilename: "{app}\NTShield.ico"
Name: "{autodesktop}\NT Shield Central"; Filename: "{app}\Open-Central-Info.cmd"; IconFilename: "{app}\NTShield.ico"; WorkingDir: "{app}"; Comment: "Central public connection info (service runs in background)"; Tasks: desktopicon

[Run]
Filename: "powershell.exe"; \
  Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\Installer\register-central-service.ps1"" -InstallDir ""{app}"" -DataDir ""{commonappdata}\NTShield\Server"" -ServiceName ""NTShieldCentral"" -StartService {code:StartServiceFlag} -Port ""{code:GetPort}"" -PublicHost ""{code:GetPublicHost}"" -TrustCertificate ""1"" -RegenerateCertificate ""1"""; \
  StatusMsg: "Registering authenticated Central service + HTTPS certificate..."; \
  Flags: runhidden waituntilterminated

Filename: "powershell.exe"; \
  Parameters: "-NoProfile -ExecutionPolicy Bypass -Command ""New-NetFirewallRule -DisplayName 'NT Shield Central' -Direction Inbound -Action Allow -Protocol TCP -LocalPort {code:GetPort} -ErrorAction SilentlyContinue"""; \
  StatusMsg: "Opening firewall port..."; \
  Flags: runhidden waituntilterminated; \
  Tasks: openfirewall

[UninstallRun]
Filename: "powershell.exe"; \
  Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\Installer\unregister-central-service.ps1"" -ServiceName ""NTShieldCentral"""; \
  RunOnceId: "StopCentralService"; \
  Flags: runhidden waituntilterminated
Filename: "powershell.exe"; \
  Parameters: "-NoProfile -ExecutionPolicy Bypass -Command ""Remove-NetFirewallRule -DisplayName 'NT Shield Central' -ErrorAction SilentlyContinue"""; \
  RunOnceId: "RemoveCentralFirewall"; \
  Flags: runhidden waituntilterminated

[Code]
var
  PortPage: TInputQueryWizardPage;
  GPort: String;
  GPublicHost: String;

function GetCommandLineParam(const ParamName: String): String;
var
  i: Integer;
  S, Prefix: String;
begin
  Result := '';
  Prefix := '/' + ParamName + '=';
  for i := 1 to ParamCount do
  begin
    S := ParamStr(i);
    if CompareText(Copy(S, 1, Length(Prefix)), Prefix) = 0 then
    begin
      Result := Copy(S, Length(Prefix) + 1, MaxInt);
      if (Length(Result) >= 2) and (Result[1] = '"') and (Result[Length(Result)] = '"') then
        Result := Copy(Result, 2, Length(Result) - 2);
      Exit;
    end;
  end;
end;

procedure InitializeWizard;
var
  CmdPort, CmdHost: String;
begin
  PortPage := CreateInputQueryPage(wpSelectDir,
    'Central HTTPS',
    'พอร์ต + Public IP/DNS สำหรับ certificate SAN',
    'Agent และ Dashboard เชื่อมต่อ https://<host>:<port>' + #13#10 +
    'ใส่ DNS/Public/NAT IP ที่ Agent ใช้จริง เพื่อป้องกัน certificate name mismatch' + #13#10 +
    'ว่างไว้ได้สำหรับ localhost + LAN NIC IPs' + #13#10 +
    'Silent: /Port=7443 /PublicHost=shield.example.go.th');
  PortPage.Add('HTTPS Port:', False);
  PortPage.Add('Public Host / IP (optional):', False);

  CmdPort := GetCommandLineParam('Port');
  if CmdPort <> '' then PortPage.Values[0] := CmdPort else PortPage.Values[0] := '7443';

  CmdHost := GetCommandLineParam('PublicHost');
  if CmdHost = '' then CmdHost := GetCommandLineParam('ServerHost');
  PortPage.Values[1] := CmdHost;
end;

procedure KillCentralProcesses;
var
  ResultCode: Integer;
begin
  Exec('sc.exe', 'stop NTShieldCentral', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Sleep(800);
  Exec('taskkill.exe', '/F /IM NTShield.Server.exe /T', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Sleep(400);
end;

function NextButtonClick(CurPageID: Integer): Boolean;
var
  P: String;
  PortNum: Integer;
begin
  Result := True;
  if CurPageID = PortPage.ID then
  begin
    P := Trim(PortPage.Values[0]);
    PortNum := StrToIntDef(P, -1);
    if (PortNum < 1) or (PortNum > 65535) then
    begin
      MsgBox('Port must be a number between 1 and 65535.' + #13#10 + 'Example: 7443', mbError, MB_OK);
      Result := False;
      Exit;
    end;
    PortPage.Values[0] := IntToStr(PortNum);
    GPort := PortPage.Values[0];
    GPublicHost := Trim(PortPage.Values[1]);
  end;

  if CurPageID = wpReady then KillCentralProcesses;
end;

function GetPort(Param: String): String;
var
  CmdPort: String;
begin
  if GPort <> '' then
    Result := GPort
  else if Assigned(PortPage) and (PortPage.Values[0] <> '') then
    Result := Trim(PortPage.Values[0])
  else
  begin
    CmdPort := GetCommandLineParam('Port');
    if CmdPort <> '' then Result := CmdPort else Result := '7443';
  end;
end;

function GetPublicHost(Param: String): String;
var
  CmdHost: String;
begin
  if GPublicHost <> '' then
    Result := GPublicHost
  else if Assigned(PortPage) then
    Result := Trim(PortPage.Values[1])
  else
  begin
    CmdHost := GetCommandLineParam('PublicHost');
    if CmdHost = '' then CmdHost := GetCommandLineParam('ServerHost');
    Result := CmdHost;
  end;
end;

function StartServiceFlag(Param: String): String;
begin
  if WizardIsTaskSelected('startservice') then Result := '1' else Result := '0';
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ResultCode: Integer;
  Ps1: String;
begin
  Result := '';
  NeedsRestart := False;
  KillCentralProcesses;
  ExtractTemporaryFile('stop-central-for-upgrade.ps1');
  Ps1 := ExpandConstant('{tmp}\stop-central-for-upgrade.ps1');
  if FileExists(Ps1) then
  begin
    Exec('powershell.exe',
      '-NoProfile -ExecutionPolicy Bypass -File "' + Ps1 + '" -ServiceName "NTShieldCentral" -InstallDir "' + ExpandConstant('{app}') + '"',
      '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end;
  KillCentralProcesses;
end;

function InitializeSetup(): Boolean;
begin
  Result := True;
  if not IsWin64 then
  begin
    MsgBox('NT Shield Central requires a 64-bit Windows operating system.', mbError, MB_OK);
    Result := False;
  end;
end;

function UpdateReadyMemo(Space, NewLine, MemoUserInfoInfo, MemoDirInfo, MemoTypeInfo,
  MemoComponentsInfo, MemoGroupInfo, MemoTasksInfo: String): String;
var
  HostHint: String;
begin
  HostHint := GetPublicHost('');
  if HostHint = '' then HostHint := '<this-host-or-LAN-IP>';
  Result :=
    MemoDirInfo + NewLine + NewLine +
    'Authenticated Central HTTPS URL:' + NewLine +
    Space + 'https://localhost:' + GetPort('') + NewLine +
    Space + 'https://' + HostHint + ':' + GetPort('') + NewLine + NewLine +
    'Security defaults:' + NewLine +
    Space + 'RequireAuth=true' + NewLine +
    Space + 'Operator and enrollment keys in protected secrets.json' + NewLine +
    Space + 'RSA-signed, target-bound response actions' + NewLine +
    Space + 'Self-signed public certificate exported as central.cer' + NewLine + NewLine +
    'Agent: import/trust central.cer or pass it as CaCertificatePath. Do not disable TLS validation.' + NewLine +
    MemoTasksInfo;
end;
