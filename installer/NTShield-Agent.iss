; NT Shield Agent — dedicated endpoint installer (Windows Service only)
; Build with: installer\build-setup-agent.ps1
; Requires: Inno Setup 6 + published artifacts under repo\artifacts\agent-win-x64\
;
; Architecture:
;   Agent  -->  Central API  <--  Dashboard
; Agent does NOT connect to the Dashboard. Both use the same Central Server URL.
;
; Silent example:
;   NTShield-Agent-Setup.exe /VERYSILENT /ServerHost=10.0.0.5 /Port=7443 \
;     /EnrollmentToken=<token> /CaCertificatePath=C:\secure\central.cer

#define MyAppName "NT Shield Agent"
#ifndef MyAppVersion
  #define MyAppVersion "1.3.1"
#endif
#define MyAppPublisher "NT Shield Team"
#define MyAppURL "https://github.com/paddman/Shield"
#define MyAgentExeName "NTShield.Agent.exe"

#ifndef SourceRoot
  #define SourceRoot ".."
#endif

[Setup]
AppId={{B8D4F0E2-6C35-5A9B-0F12-9D3E2C1B0A88}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
DefaultDirName={autopf}\NT Shield Agent
DefaultGroupName=NT Shield Agent
DisableProgramGroupPage=no
OutputDir={#SourceRoot}\artifacts\setup
OutputBaseFilename=NTShield-Agent-Setup-{#MyAppVersion}
SetupIconFile={#SourceRoot}\assets\icons\NTShield.ico
UninstallDisplayIcon={app}\NTShield.ico
SetupMutex=NTShieldAgentSetupMutex
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
VersionInfoProductName=NT Shield Agent
VersionInfoDescription=NT Shield Agent (endpoint) Setup

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Messages]
WelcomeLabel1=NT Shield Agent Setup
WelcomeLabel2=ยินดีต้อนรับสู่ตัวติดตั้ง Agent แยก (endpoint only)%n%nติดตั้ง Windows Service บนเครื่องเป้าหมาย — ตรวจจับ password spray, lateral movement และ process ผิดปกติ%n%nAgent ส่งข้อมูลไป Central ผ่าน HTTPS ที่ตรวจสอบ certificate แล้วเท่านั้น%n%nThis installs the monitoring Agent only. Configure the trusted Central URL on the next page.
FinishedHeadingLabel=ติดตั้ง Agent สำเร็จ
FinishedLabelNoIcons=NT Shield Agent ติดตั้งเรียบร้อยแล้ว!
FinishedLabel=NT Shield Agent ติดตั้งเรียบร้อยแล้ว!%n%nService: NTShieldAgent%n%nตรวจเวอร์ชัน: เปิด %ProgramFiles%\NT Shield Agent\VERSION.txt%nหรือ status.json ต้องเป็น {#MyAppVersion}%n%nตรวจว่า Central ทำงาน ใช้ HTTPS certificate ที่เชื่อถือได้ และ Dashboard ชี้ URL เดียวกัน
ClickFinish=คลิก Finish เพื่อปิดตัวติดตั้ง
ButtonNext=Next >
ButtonBack=< Back
ButtonCancel=Cancel
ButtonFinish=Finish
SelectDirLabel3=เลือกโฟลเดอร์ติดตั้ง Agent
WizardSelectDir=เลือกตำแหน่งติดตั้ง
WizardReady=พร้อมติดตั้ง
WizardInstalling=กำลังติดตั้ง...
StatusExtractFiles=กำลังติดตั้งไฟล์...

[Tasks]
Name: "startservice"; Description: "Start Agent service after install"; GroupDescription: "Service:"
Name: "trayicon"; Description: "Show small Agent icon in system tray (notification area)"; GroupDescription: "Tray:"
Name: "desktopicon"; Description: "Create a &desktop icon (tray / mini dashboard)"; GroupDescription: "Additional icons:"; Flags: unchecked

[Files]
Source: "{#SourceRoot}\installer\setup-helpers\stop-agent-for-upgrade.ps1"; DestDir: "{tmp}"; Flags: dontcopy

Source: "{#SourceRoot}\assets\icons\NTShield.ico"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceRoot}\artifacts\agent-win-x64\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#SourceRoot}\assets\icons\NTShield.ico"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceRoot}\config\rules.json"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceRoot}\config\allowlist.json"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist
Source: "{#SourceRoot}\config\rules.json"; DestDir: "{app}\config"; Flags: ignoreversion
Source: "{#SourceRoot}\config\allowlist.json"; DestDir: "{app}\config"; Flags: ignoreversion skipifsourcedoesntexist
Source: "{#SourceRoot}\config\protection-pack.json"; DestDir: "{app}\config"; Flags: ignoreversion skipifsourcedoesntexist
Source: "{#SourceRoot}\tools\yara64.exe"; DestDir: "{app}\tools"; Flags: ignoreversion skipifsourcedoesntexist
Source: "{#SourceRoot}\installer\setup-helpers\register-agent-service.ps1"; DestDir: "{app}\Installer"; Flags: ignoreversion
Source: "{#SourceRoot}\installer\setup-helpers\unregister-agent-service.ps1"; DestDir: "{app}\Installer"; Flags: ignoreversion
Source: "{#SourceRoot}\installer\setup-helpers\set-agent-central-url.ps1"; DestDir: "{app}\Installer"; Flags: ignoreversion
Source: "{#SourceRoot}\installer\setup-helpers\register-agent-tray.ps1"; DestDir: "{app}\Installer"; Flags: ignoreversion
Source: "{#SourceRoot}\installer\setup-helpers\unregister-agent-tray.ps1"; DestDir: "{app}\Installer"; Flags: ignoreversion
Source: "{#SourceRoot}\installer\setup-helpers\stop-agent-for-upgrade.ps1"; DestDir: "{app}\Installer"; Flags: ignoreversion
Source: "{#SourceRoot}\installer\setup-helpers\verify-agent-install.ps1"; DestDir: "{app}\Installer"; Flags: ignoreversion

[Dirs]
Name: "{commonappdata}\NTShield\Agent"
Name: "{commonappdata}\NTShield\Agent\logs"
Name: "{commonappdata}\NTShield\Agent\evidence"

[Icons]
Name: "{group}\Agent Logs"; Filename: "{commonappdata}\NTShield\Agent\logs"; IconFilename: "{app}\NTShield.ico"
Name: "{group}\Agent Install Folder"; Filename: "{app}"; IconFilename: "{app}\NTShield.ico"
Name: "{group}\Show tray icon"; Filename: "{app}\NTShield.Agent.Tray.exe"; Parameters: "--install-dir ""{app}"""; IconFilename: "{app}\NTShield.ico"; WorkingDir: "{app}"
Name: "{group}\Reconfigure Central URL"; Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\Installer\set-agent-central-url.ps1"" -InstallDir ""{app}"""; IconFilename: "{app}\NTShield.ico"
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"; IconFilename: "{app}\NTShield.ico"
Name: "{autodesktop}\NT Shield Agent"; Filename: "{app}\NTShield.Agent.Tray.exe"; Parameters: "--install-dir ""{app}"""; IconFilename: "{app}\NTShield.ico"; WorkingDir: "{app}"; Comment: "Agent tray + mini dashboard"; Tasks: desktopicon

[Run]
Filename: "powershell.exe"; \
  Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\Installer\register-agent-service.ps1"" -InstallDir ""{app}"" -DataDir ""{commonappdata}\NTShield\Agent"" -ServiceName ""NTShieldAgent"" -StartService {code:StartServiceFlag} -CentralUrl ""{code:GetCentralUrl}"" -EnrollmentToken ""{code:GetEnrollmentToken}"" -CaCertificatePath ""{code:GetCaCertificatePath}"""; \
  StatusMsg: "Registering Agent service with authenticated HTTPS Central..."; \
  Flags: runhidden waituntilterminated

Filename: "powershell.exe"; \
  Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\Installer\verify-agent-install.ps1"" -InstallDir ""{app}"" -ServiceName ""NTShieldAgent"" -MinVersion ""{#MyAppVersion}"""; \
  StatusMsg: "Verifying Agent binary version..."; \
  Flags: runhidden waituntilterminated

Filename: "powershell.exe"; \
  Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\Installer\register-agent-tray.ps1"" -InstallDir ""{app}"" -StartNow 1 -RunAtLogon {code:TrayFlag}"; \
  StatusMsg: "Enabling system tray icon..."; \
  Flags: runhidden waituntilterminated; \
  Tasks: trayicon

[UninstallRun]
Filename: "powershell.exe"; \
  Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\Installer\unregister-agent-tray.ps1"" -InstallDir ""{app}"""; \
  RunOnceId: "StopAgentTray"; \
  Flags: runhidden waituntilterminated
Filename: "powershell.exe"; \
  Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\Installer\unregister-agent-service.ps1"" -ServiceName ""NTShieldAgent"""; \
  RunOnceId: "StopAgentService"; \
  Flags: runhidden waituntilterminated

[Code]
var
  CentralPage: TInputQueryWizardPage;
  GCentralUrl: String;

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
  CmdUrl, CmdHost, CmdPort, CmdCa: String;
begin
  CentralPage := CreateInputQueryPage(wpSelectDir,
    'Trusted Central HTTPS',
    'Agent ส่งข้อมูลไป Central เท่านั้น (ไม่ต่อ Dashboard)',
    'ใช้ HTTPS URL ของ Central และ certificate ที่ Windows เชื่อถือ' + #13#10 +
    'ถ้า Central ใช้ self-signed certificate ให้ระบุ central.cer ที่ export จาก Central' + #13#10 +
    'EnrollmentToken อ่านจาก protected Server\secrets.json โดย Administrator' + #13#10 +
    'Silent: /ServerHost=10.0.0.5 /Port=7443 /EnrollmentToken=... /CaCertificatePath=C:\secure\central.cer');
  CentralPage.Add('Central Server IP or Host name (NOT localhost for remote):', False);
  CentralPage.Add('HTTPS Port:', False);
  CentralPage.Add('Enrollment Token:', False);
  CentralPage.Add('Central CA / certificate path (blank = Windows trust store):', False);

  CmdUrl := GetCommandLineParam('CentralUrl');
  CmdHost := GetCommandLineParam('ServerHost');
  if CmdHost = '' then CmdHost := GetCommandLineParam('ServerIp');
  CmdPort := GetCommandLineParam('Port');
  CmdCa := GetCommandLineParam('CaCertificatePath');
  if CmdCa = '' then CmdCa := GetCommandLineParam('CaCertificate');

  if CmdUrl <> '' then
  begin
    CentralPage.Values[0] := CmdUrl;
    CentralPage.Values[1] := '7443';
  end
  else
  begin
    if CmdHost <> '' then CentralPage.Values[0] := CmdHost else CentralPage.Values[0] := 'localhost';
    if CmdPort <> '' then CentralPage.Values[1] := CmdPort else CentralPage.Values[1] := '7443';
  end;
  CentralPage.Values[2] := GetCommandLineParam('EnrollmentToken');
  CentralPage.Values[3] := CmdCa;
end;

procedure KillAgentProcesses; forward;

function NextButtonClick(CurPageID: Integer): Boolean;
var
  H, P, U, CaPath: String;
  PortNum: Integer;
begin
  Result := True;
  if CurPageID = CentralPage.ID then
  begin
    H := Trim(CentralPage.Values[0]);
    P := Trim(CentralPage.Values[1]);
    CaPath := Trim(CentralPage.Values[3]);
    if H = '' then
    begin
      MsgBox('Enter Central Server IP or host name.' + #13#10 + 'Example: 10.0.0.5', mbError, MB_OK);
      Result := False;
      Exit;
    end;
    if Pos('http://', LowerCase(H)) = 1 then
    begin
      MsgBox('Plain HTTP is disabled. NT Shield Agent requires HTTPS.', mbError, MB_OK);
      Result := False;
      Exit;
    end;
    if (CaPath <> '') and (not FileExists(CaPath)) then
    begin
      MsgBox('Central CA/certificate file not found:' + #13#10 + CaPath, mbError, MB_OK);
      Result := False;
      Exit;
    end;
    if P = '' then P := '7443';
    PortNum := StrToIntDef(P, -1);
    if (PortNum < 1) or (PortNum > 65535) then
    begin
      MsgBox('Invalid port. Use 1-65535 (default 7443).', mbError, MB_OK);
      Result := False;
      Exit;
    end;
    P := IntToStr(PortNum);
    CentralPage.Values[1] := P;
    if Pos('https://', LowerCase(H)) = 1 then
    begin
      U := H;
      while (Length(U) > 0) and (U[Length(U)] = '/') do
        Delete(U, Length(U), 1);
      GCentralUrl := U;
    end
    else
      GCentralUrl := 'https://' + H + ':' + P;
  end;

  if CurPageID = wpReady then
    KillAgentProcesses;
end;

function GetEnrollmentToken(Param: String): String;
begin
  Result := GetCommandLineParam('EnrollmentToken');
  if (Result = '') and Assigned(CentralPage) then
    Result := Trim(CentralPage.Values[2]);
end;

function GetCaCertificatePath(Param: String): String;
begin
  Result := GetCommandLineParam('CaCertificatePath');
  if Result = '' then Result := GetCommandLineParam('CaCertificate');
  if (Result = '') and Assigned(CentralPage) then
    Result := Trim(CentralPage.Values[3]);
end;

function GetCentralUrl(Param: String): String;
var
  CmdUrl, H, P: String;
begin
  if GCentralUrl <> '' then
    Result := GCentralUrl
  else
  begin
    CmdUrl := GetCommandLineParam('CentralUrl');
    if CmdUrl <> '' then
      Result := CmdUrl
    else if Assigned(CentralPage) then
    begin
      H := Trim(CentralPage.Values[0]);
      P := Trim(CentralPage.Values[1]);
      if P = '' then P := '7443';
      if H = '' then H := 'localhost';
      if Pos('https://', LowerCase(H)) = 1 then
        Result := H
      else
        Result := 'https://' + H + ':' + P;
    end
    else
      Result := 'https://localhost:7443';
  end;
end;

function StartServiceFlag(Param: String): String;
begin
  if WizardIsTaskSelected('startservice') then Result := '1' else Result := '0';
end;

function TrayFlag(Param: String): String;
begin
  if WizardIsTaskSelected('trayicon') then Result := '1' else Result := '0';
end;

function InitializeSetup(): Boolean;
begin
  Result := True;
  if not IsWin64 then
  begin
    MsgBox('NT Shield Agent requires a 64-bit Windows operating system.', mbError, MB_OK);
    Result := False;
  end;
end;

procedure KillAgentProcesses;
var
  ResultCode: Integer;
begin
  Exec('sc.exe', 'stop NTShieldAgent', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Sleep(1000);
  Exec('taskkill.exe', '/F /IM NTShield.Agent.exe /T', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec('taskkill.exe', '/F /IM NTShield.Agent.Tray.exe /T', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec('taskkill.exe', '/F /IM NTShield.Dashboard.exe /T', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Sleep(600);
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ResultCode: Integer;
  Ps1: String;
begin
  Result := '';
  NeedsRestart := False;
  KillAgentProcesses;
  ExtractTemporaryFile('stop-agent-for-upgrade.ps1');
  Ps1 := ExpandConstant('{tmp}\stop-agent-for-upgrade.ps1');
  if FileExists(Ps1) then
  begin
    Exec('powershell.exe',
      '-NoProfile -ExecutionPolicy Bypass -File "' + Ps1 + '" -ServiceName "NTShieldAgent" -InstallDir "' + ExpandConstant('{app}') + '"',
      '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end;
  KillAgentProcesses;
end;

function UpdateReadyMemo(Space, NewLine, MemoUserInfoInfo, MemoDirInfo, MemoTypeInfo,
  MemoComponentsInfo, MemoGroupInfo, MemoTasksInfo: String): String;
var
  CaText: String;
begin
  CaText := GetCaCertificatePath('');
  if CaText = '' then CaText := 'Windows certificate trust store';
  Result :=
    MemoDirInfo + NewLine + NewLine +
    'Central Server URL:' + NewLine +
    Space + GetCentralUrl('') + NewLine +
    'TLS trust:' + NewLine +
    Space + CaText + NewLine + NewLine +
    'Service name: NTShieldAgent' + NewLine +
    'Data: %ProgramData%\NTShield\Agent' + NewLine +
    'Default mode: IDS / DetectOnly' + NewLine + NewLine +
    'Upgrade: existing Agent service / tray will be stopped before files are replaced.' + NewLine +
    'Dashboard must use the same authenticated Central URL.' + NewLine +
    MemoTasksInfo;
end;
