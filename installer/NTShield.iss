; NT Shield — Full Stack Windows Setup (EXE)
; Build with: installer\build-setup.ps1
; Components: Central Server + Agent + Dashboard (all-in-one)

#define MyAppName "NT Shield"
#ifndef MyAppVersion
  #define MyAppVersion "1.1.0"
#endif
#define MyAppPublisher "NT Shield Team"
#define MyAppURL "https://github.com/paddman/Shield"
#define MyAppExeName "NTShield.Dashboard.exe"

#ifndef SourceRoot
  #define SourceRoot ".."
#endif

[Setup]
AppId={{A7C3E9D1-5B24-4F8A-9E01-8C2D1B0A9F77}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
DefaultDirName={autopf}\NT Shield
DefaultGroupName=NT Shield
DisableProgramGroupPage=no
OutputDir={#SourceRoot}\artifacts\setup
OutputBaseFilename=NTShield-Setup-{#MyAppVersion}
SetupIconFile={#SourceRoot}\assets\icons\NTShield.ico
UninstallDisplayIcon={app}\NTShield.ico
SetupMutex=NTShieldSetupMutex
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
VersionInfoProductName=NT Shield
VersionInfoDescription=NT Shield Full Stack Setup (Central + Agent + Dashboard)

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Messages]
WelcomeLabel1=NT Shield Setup
WelcomeLabel2=ยินดีต้อนรับ — ติดตั้งครบชุดในตัวเดียว%n%n• Central Server (API + Syslog + signatures)%n• Agent (IDS/IPS endpoint service)%n• Dashboard (desktop UI)%n%nรวม .NET runtime แล้ว — เครื่องปลายทางไม่ต้องติดตั้ง .NET%nSelf-contained: no separate .NET install required.%n%nแนะนำให้ปิดโปรแกรมอื่นก่อนดำเนินการต่อ
FinishedHeadingLabel=ติดตั้งสำเร็จ
FinishedLabelNoIcons=NT Shield ติดตั้งเรียบร้อยแล้ว!
FinishedLabel=NT Shield ติดตั้งเรียบร้อยแล้ว!%n%nCentral : https://localhost:7443%nService : NTShieldCentral + NTShieldAgent%n%nเปิด Dashboard จาก Start Menu / Desktop
ClickFinish=คลิก Finish เพื่อเริ่มใช้งาน
ButtonNext=Next >
ButtonBack=< Back
ButtonCancel=Cancel
ButtonFinish=Finish
SelectDirLabel3=เลือกตำแหน่งติดตั้ง
SelectComponentsLabel2=เลือกส่วนประกอบ (Full = ครบชุด)
WizardSelectDir=เลือกตำแหน่งติดตั้ง
WizardSelectComponents=เลือกประเภทการติดตั้ง
WizardReady=พร้อมติดตั้ง
WizardInstalling=กำลังติดตั้ง...
StatusExtractFiles=กำลังติดตั้งไฟล์...

[Types]
Name: "full"; Description: "Full stack (Central + Agent + Dashboard) — แนะนำ"
Name: "server"; Description: "Central Server only"
Name: "endpoint"; Description: "Agent + Dashboard (connect to existing Central)"
Name: "agent"; Description: "Agent only"
Name: "dashboard"; Description: "Dashboard only"
Name: "custom"; Description: "Custom"; Flags: iscustom

[Components]
Name: "central"; Description: "Central Server (API :7443 + Syslog :5514 + open-source signatures)"; Types: full server custom
Name: "agent"; Description: "Agent Windows Service (IDS/IPS endpoint)"; Types: full endpoint agent custom
Name: "dashboard"; Description: "Desktop Dashboard (live UI + Firewall panel)"; Types: full endpoint dashboard custom

[Tasks]
Name: "desktopicon"; Description: "Create desktop icon (Dashboard)"; GroupDescription: "Icons:"; Components: dashboard; Flags: checkedonce
Name: "desktopcentral"; Description: "Create desktop icon (Central info)"; GroupDescription: "Icons:"; Components: central; Flags: checkedonce
; Default checked (omit checkedonce) so silent re-upgrade still starts services
Name: "startcentral"; Description: "Start Central service after install"; GroupDescription: "Central:"; Components: central
Name: "startagent"; Description: "Start Agent service after install"; GroupDescription: "Agent:"; Components: agent
Name: "trayicon"; Description: "Show Agent tray icon + mini dashboard"; GroupDescription: "Agent:"; Components: agent
Name: "openfirewall"; Description: "Open Windows Firewall for Central (7443 TCP + 5514 UDP)"; GroupDescription: "Central:"; Components: central; Flags: checkedonce

[Files]
Source: "{#SourceRoot}\assets\icons\NTShield.ico"; DestDir: "{app}"; Flags: ignoreversion

; ---- Central ----
Source: "{#SourceRoot}\artifacts\server-win-x64\*"; DestDir: "{app}\Central"; Flags: ignoreversion recursesubdirs createallsubdirs; Components: central
Source: "{#SourceRoot}\assets\icons\NTShield.ico"; DestDir: "{app}\Central"; Flags: ignoreversion; Components: central
Source: "{#SourceRoot}\installer\templates\CONNECTION.txt"; DestDir: "{app}\Central"; Flags: ignoreversion; Components: central
Source: "{#SourceRoot}\installer\templates\Open-Central-Info.cmd"; DestDir: "{app}\Central"; Flags: ignoreversion; Components: central
Source: "{#SourceRoot}\config\signatures\opensource-signatures.json"; DestDir: "{app}\Central\signatures"; Flags: ignoreversion skipifsourcedoesntexist; Components: central
Source: "{#SourceRoot}\installer\setup-helpers\register-central-service.ps1"; DestDir: "{app}\Installer"; Flags: ignoreversion; Components: central
Source: "{#SourceRoot}\installer\setup-helpers\unregister-central-service.ps1"; DestDir: "{app}\Installer"; Flags: ignoreversion; Components: central
Source: "{#SourceRoot}\installer\setup-helpers\stop-central-for-upgrade.ps1"; DestDir: "{app}\Installer"; Flags: ignoreversion; Components: central
Source: "{#SourceRoot}\installer\setup-helpers\write-connection-info.ps1"; DestDir: "{app}\Installer"; Flags: ignoreversion; Components: central
Source: "{#SourceRoot}\installer\setup-helpers\regenerate-central-cert.ps1"; DestDir: "{app}\Installer"; Flags: ignoreversion; Components: central
Source: "{#SourceRoot}\installer\setup-helpers\stop-central-for-upgrade.ps1"; DestDir: "{tmp}"; Flags: dontcopy

; ---- Agent ----
Source: "{#SourceRoot}\artifacts\agent-win-x64\*"; DestDir: "{app}\Agent"; Flags: ignoreversion recursesubdirs createallsubdirs; Components: agent
Source: "{#SourceRoot}\assets\icons\NTShield.ico"; DestDir: "{app}\Agent"; Flags: ignoreversion; Components: agent
Source: "{#SourceRoot}\config\rules.json"; DestDir: "{app}\Agent"; Flags: ignoreversion; Components: agent
Source: "{#SourceRoot}\config\allowlist.json"; DestDir: "{app}\Agent"; Flags: ignoreversion skipifsourcedoesntexist; Components: agent
Source: "{#SourceRoot}\config\rules.json"; DestDir: "{app}\Agent\config"; Flags: ignoreversion; Components: agent
Source: "{#SourceRoot}\installer\setup-helpers\register-agent-service.ps1"; DestDir: "{app}\Installer"; Flags: ignoreversion; Components: agent
Source: "{#SourceRoot}\installer\setup-helpers\unregister-agent-service.ps1"; DestDir: "{app}\Installer"; Flags: ignoreversion; Components: agent
Source: "{#SourceRoot}\installer\setup-helpers\register-agent-tray.ps1"; DestDir: "{app}\Installer"; Flags: ignoreversion; Components: agent
Source: "{#SourceRoot}\installer\setup-helpers\unregister-agent-tray.ps1"; DestDir: "{app}\Installer"; Flags: ignoreversion; Components: agent
Source: "{#SourceRoot}\installer\setup-helpers\stop-agent-for-upgrade.ps1"; DestDir: "{app}\Installer"; Flags: ignoreversion; Components: agent
Source: "{#SourceRoot}\installer\setup-helpers\verify-agent-install.ps1"; DestDir: "{app}\Installer"; Flags: ignoreversion; Components: agent
Source: "{#SourceRoot}\installer\setup-helpers\set-agent-central-url.ps1"; DestDir: "{app}\Installer"; Flags: ignoreversion; Components: agent
Source: "{#SourceRoot}\installer\templates\Set-Agent-Server.cmd"; DestDir: "{app}\Installer"; Flags: ignoreversion; Components: agent
Source: "{#SourceRoot}\installer\setup-helpers\stop-agent-for-upgrade.ps1"; DestDir: "{tmp}"; Flags: dontcopy

; ---- Dashboard ----
Source: "{#SourceRoot}\artifacts\dashboard-win-x64\*"; DestDir: "{app}\Dashboard"; Flags: ignoreversion recursesubdirs createallsubdirs; Components: dashboard
Source: "{#SourceRoot}\assets\icons\NTShield.ico"; DestDir: "{app}\Dashboard"; Flags: ignoreversion; Components: dashboard

[Dirs]
Name: "{commonappdata}\NTShield\Agent"; Components: agent
Name: "{commonappdata}\NTShield\Agent\logs"; Components: agent
Name: "{commonappdata}\NTShield\Agent\evidence"; Components: agent
Name: "{commonappdata}\NTShield\Server"; Components: central
Name: "{commonappdata}\NTShield\Server\logs"; Components: central
Name: "{commonappdata}\NTShield\Server\certs"; Components: central
Name: "{commonappdata}\NTShield\Server\signatures"; Components: central

[Icons]
Name: "{group}\NT Shield Dashboard"; Filename: "{app}\Dashboard\{#MyAppExeName}"; IconFilename: "{app}\NTShield.ico"; Components: dashboard
Name: "{group}\Central Connection Info"; Filename: "{app}\Central\Open-Central-Info.cmd"; IconFilename: "{app}\NTShield.ico"; WorkingDir: "{app}\Central"; Components: central
Name: "{group}\Agent Logs"; Filename: "{commonappdata}\NTShield\Agent\logs"; IconFilename: "{app}\NTShield.ico"; Components: agent
Name: "{group}\Central Logs"; Filename: "{commonappdata}\NTShield\Server\logs"; IconFilename: "{app}\NTShield.ico"; Components: central
Name: "{group}\Show tray icon"; Filename: "{app}\Agent\NTShield.Agent.Tray.exe"; Parameters: "--install-dir ""{app}\Agent"""; IconFilename: "{app}\NTShield.ico"; WorkingDir: "{app}\Agent"; Components: agent
Name: "{group}\Configure Agent Server (IP/Port)"; Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\Installer\set-agent-central-url.ps1"" -InstallDir ""{app}\Agent"""; IconFilename: "{app}\NTShield.ico"; Components: agent
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"; IconFilename: "{app}\NTShield.ico"
Name: "{autodesktop}\NT Shield Dashboard"; Filename: "{app}\Dashboard\{#MyAppExeName}"; IconFilename: "{app}\NTShield.ico"; Tasks: desktopicon; Components: dashboard
Name: "{autodesktop}\NT Shield Central"; Filename: "{app}\Central\Open-Central-Info.cmd"; IconFilename: "{app}\NTShield.ico"; WorkingDir: "{app}\Central"; Tasks: desktopcentral; Components: central

[Run]
; 1) Central first (so Agent can point to localhost)
Filename: "powershell.exe"; \
  Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\Installer\register-central-service.ps1"" -InstallDir ""{app}\Central"" -DataDir ""{commonappdata}\NTShield\Server"" -ServiceName ""NTShieldCentral"" -StartService {code:StartCentralFlag} -Port ""{code:GetCentralPort}"" -PublicHost ""{code:GetCentralHost}"" -TrustCertificate ""1"" -RegenerateCertificate ""1"""; \
  StatusMsg: "Registering Central Server + HTTPS certificate..."; \
  Flags: runhidden waituntilterminated; \
  Components: central

Filename: "powershell.exe"; \
  Parameters: "-NoProfile -ExecutionPolicy Bypass -Command ""New-NetFirewallRule -DisplayName 'NT Shield HTTPS' -Direction Inbound -Action Allow -Protocol TCP -LocalPort {code:GetCentralPort} -ErrorAction SilentlyContinue; New-NetFirewallRule -DisplayName 'NT Shield Syslog 5514' -Direction Inbound -Action Allow -Protocol UDP -LocalPort 5514 -ErrorAction SilentlyContinue"""; \
  StatusMsg: "Opening firewall ports..."; \
  Flags: runhidden waituntilterminated; \
  Components: central; \
  Tasks: openfirewall

; 2) Agent → Central URL from wizard (IP + port)
Filename: "powershell.exe"; \
  Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\Installer\register-agent-service.ps1"" -InstallDir ""{app}\Agent"" -DataDir ""{commonappdata}\NTShield\Agent"" -ServiceName ""NTShieldAgent"" -StartService {code:StartAgentFlag} -CentralUrl ""{code:GetCentralUrl}"""; \
  StatusMsg: "Registering Agent service (pointing at Central)..."; \
  Flags: runhidden waituntilterminated; \
  Components: agent

Filename: "powershell.exe"; \
  Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\Installer\verify-agent-install.ps1"" -InstallDir ""{app}\Agent"" -ServiceName ""NTShieldAgent"" -MinVersion ""{#MyAppVersion}"""; \
  StatusMsg: "Verifying Agent binary version..."; \
  Flags: runhidden waituntilterminated; \
  Components: agent

; Patch agent HTTPS + syslog host from wizard host
Filename: "powershell.exe"; \
  Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\Installer\set-agent-central-url.ps1"" -InstallDir ""{app}\Agent"" -CentralUrl ""{code:GetCentralUrl}"" -EnableSyslog -SyslogHost ""{code:GetCentralHost}"" -SyslogPort 5514 -AllowUntrustedServerCertificate -NoRestart"; \
  StatusMsg: "Linking Agent to Central (HTTPS + Syslog)..."; \
  Flags: runhidden waituntilterminated; \
  Components: agent

Filename: "powershell.exe"; \
  Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\Installer\register-agent-tray.ps1"" -InstallDir ""{app}\Agent"" -StartNow 1 -RunAtLogon 1"; \
  StatusMsg: "Enabling system tray..."; \
  Flags: runhidden waituntilterminated; \
  Components: agent; \
  Tasks: trayicon

Filename: "{app}\Dashboard\{#MyAppExeName}"; Description: "Launch Dashboard"; Flags: nowait postinstall skipifsilent; Components: dashboard

[UninstallRun]
Filename: "powershell.exe"; \
  Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\Installer\unregister-agent-tray.ps1"" -InstallDir ""{app}\Agent"""; \
  RunOnceId: "StopAgentTray"; Flags: runhidden waituntilterminated; Components: agent
Filename: "powershell.exe"; \
  Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\Installer\unregister-agent-service.ps1"" -ServiceName ""NTShieldAgent"""; \
  RunOnceId: "StopAgentService"; Flags: runhidden waituntilterminated; Components: agent
Filename: "powershell.exe"; \
  Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\Installer\unregister-central-service.ps1"" -ServiceName ""NTShieldCentral"""; \
  RunOnceId: "StopCentralService"; Flags: runhidden waituntilterminated; Components: central

[Code]
var
  CentralPage: TInputQueryWizardPage;
  GCentralHost: String;
  GCentralPort: String;
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

function BuildUrl(const Host, Port: String): String;
begin
  Result := 'https://' + Host + ':' + Port;
end;

procedure InitializeWizard;
var
  CmdUrl, CmdHost, CmdPort: String;
begin
  CentralPage := CreateInputQueryPage(wpSelectComponents,
    'Central Server (Agent target)',
    'Agent sends data to Central — enter IP and Port',
    'Agent does NOT talk to Dashboard directly.' + #13#10 +
    'This PC full stack → localhost' + #13#10 +
    'Remote Agent → IP of Central machine, port 7443' + #13#10 +
    'Silent: /ServerHost=10.0.0.5 /Port=7443');
  CentralPage.Add('Central Server IP or Host name:', False);
  CentralPage.Add('HTTPS Port:', False);

  CmdUrl := GetCommandLineParam('CentralUrl');
  CmdHost := GetCommandLineParam('ServerHost');
  if CmdHost = '' then CmdHost := GetCommandLineParam('ServerIp');
  CmdPort := GetCommandLineParam('Port');

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
end;

function ShouldSkipPage(PageID: Integer): Boolean;
begin
  Result := False;
  if Assigned(CentralPage) and (PageID = CentralPage.ID) then
  begin
    if not WizardIsComponentSelected('agent') and not WizardIsComponentSelected('central') then
      Result := True;
  end;
end;

function NextButtonClick(CurPageID: Integer): Boolean;
var
  H, P, U: String;
  PortNum: Integer;
begin
  Result := True;
  if Assigned(CentralPage) and (CurPageID = CentralPage.ID) then
  begin
    H := Trim(CentralPage.Values[0]);
    P := Trim(CentralPage.Values[1]);
    if H = '' then
    begin
      MsgBox('Enter Central Server IP or host.' + #13#10 + 'Example: 10.0.0.5 or localhost', mbError, MB_OK);
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

    if (Pos('https://', LowerCase(H)) = 1) or (Pos('http://', LowerCase(H)) = 1) then
    begin
      U := H;
      while (Length(U) > 0) and (U[Length(U)] = '/') do
        Delete(U, Length(U), 1);
      GCentralUrl := U;
      GCentralHost := H;
      GCentralPort := P;
    end
    else
    begin
      GCentralHost := H;
      GCentralPort := P;
      GCentralUrl := BuildUrl(H, P);
    end;
  end;
end;

function GetCentralUrl(Param: String): String;
var
  CmdUrl, H, P: String;
begin
  if GCentralUrl <> '' then begin Result := GCentralUrl; Exit; end;
  CmdUrl := GetCommandLineParam('CentralUrl');
  if CmdUrl <> '' then begin Result := CmdUrl; Exit; end;
  if Assigned(CentralPage) then
  begin
    H := Trim(CentralPage.Values[0]);
    P := Trim(CentralPage.Values[1]);
    if P = '' then P := '7443';
    if H = '' then H := 'localhost';
    if (Pos('https://', LowerCase(H)) = 1) or (Pos('http://', LowerCase(H)) = 1) then
      Result := H
    else
      Result := BuildUrl(H, P);
    Exit;
  end;
  Result := 'https://localhost:7443';
end;

function GetCentralHost(Param: String): String;
var
  H, U: String;
  i: Integer;
begin
  if GCentralHost <> '' then H := GCentralHost
  else if Assigned(CentralPage) then H := Trim(CentralPage.Values[0])
  else H := '127.0.0.1';
  if H = '' then H := '127.0.0.1';
  if (Pos('https://', LowerCase(H)) = 1) or (Pos('http://', LowerCase(H)) = 1) then
  begin
    U := H;
    if Pos('://', U) > 0 then Delete(U, 1, Pos('://', U) + 2);
    i := Pos(':', U);
    if i > 0 then U := Copy(U, 1, i - 1);
    Result := U;
  end
  else
    Result := H;
end;

function GetCentralPort(Param: String): String;
begin
  if GCentralPort <> '' then Result := GCentralPort
  else if Assigned(CentralPage) and (Trim(CentralPage.Values[1]) <> '') then Result := Trim(CentralPage.Values[1])
  else begin
    Result := GetCommandLineParam('Port');
    if Result = '' then Result := '7443';
  end;
end;

function StartCentralFlag(Param: String): String;
begin
  if WizardIsTaskSelected('startcentral') then Result := '1' else Result := '0';
end;

function StartAgentFlag(Param: String): String;
begin
  if WizardIsTaskSelected('startagent') then Result := '1' else Result := '0';
end;

procedure KillAll;
var
  ResultCode: Integer;
begin
  Exec('sc.exe', 'stop NTShieldCentral', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec('sc.exe', 'stop NTShieldAgent', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Sleep(600);
  Exec('taskkill.exe', '/F /IM NTShield.Server.exe /T', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec('taskkill.exe', '/F /IM NTShield.Agent.exe /T', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec('taskkill.exe', '/F /IM NTShield.Agent.Tray.exe /T', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec('taskkill.exe', '/F /IM NTShield.Dashboard.exe /T', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Sleep(400);
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ResultCode: Integer;
  Ps1: String;
begin
  Result := '';
  NeedsRestart := False;
  KillAll;
  ExtractTemporaryFile('stop-agent-for-upgrade.ps1');
  Ps1 := ExpandConstant('{tmp}\stop-agent-for-upgrade.ps1');
  if FileExists(Ps1) then
    Exec('powershell.exe',
      '-NoProfile -ExecutionPolicy Bypass -File "' + Ps1 + '" -ServiceName "NTShieldAgent" -InstallDir "' + ExpandConstant('{app}\Agent') + '"',
      '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  ExtractTemporaryFile('stop-central-for-upgrade.ps1');
  Ps1 := ExpandConstant('{tmp}\stop-central-for-upgrade.ps1');
  if FileExists(Ps1) then
    Exec('powershell.exe',
      '-NoProfile -ExecutionPolicy Bypass -File "' + Ps1 + '" -ServiceName "NTShieldCentral" -InstallDir "' + ExpandConstant('{app}\Central') + '"',
      '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  KillAll;
end;

function InitializeSetup(): Boolean;
begin
  Result := True;
  if not IsWin64 then
  begin
    MsgBox('NT Shield requires a 64-bit Windows OS.', mbError, MB_OK);
    Result := False;
  end;
end;

function UpdateReadyMemo(Space, NewLine, MemoUserInfoInfo, MemoDirInfo, MemoTypeInfo,
  MemoComponentsInfo, MemoGroupInfo, MemoTasksInfo: String): String;
begin
  Result :=
    MemoDirInfo + NewLine + NewLine +
    MemoComponentsInfo + NewLine + NewLine +
    'Agent will send data to Central:' + NewLine +
    Space + GetCentralUrl('') + NewLine +
    Space + 'Host=' + GetCentralHost('') + '  Port=' + GetCentralPort('') + NewLine + NewLine +
    'Dashboard Settings must use the same URL.' + NewLine + NewLine +
    MemoTasksInfo;
end;
