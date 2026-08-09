; NT Shield — Full Stack Windows Setup (EXE)
; Build with: installer\build-setup.ps1
; Components: authenticated Central + Agent + Dashboard
;
; Silent full-stack example:
;   NTShield-Setup-1.3.1.exe /VERYSILENT /Port=7443 /PublicHost=shield.example.go.th
;
; Silent endpoint example:
;   NTShield-Setup-1.3.1.exe /TYPE=endpoint /VERYSILENT \
;     /CentralUrl=https://10.0.0.5:7443 /EnrollmentToken=<token> \
;     /CaCertificatePath=C:\secure\central.cer

#define MyAppName "NT Shield"
#ifndef MyAppVersion
  #define MyAppVersion "1.3.1"
#endif
#define MyAppPublisher "NT Shield Team"
#define MyAppURL "https://github.com/paddman/Shield"
#define MyDashboardExe "NTShield.Dashboard.exe"

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
WelcomeLabel2=ติดตั้ง NT Shield v{#MyAppVersion}%n%n• Central: authenticated HTTPS control plane%n• Agent: IDS endpoint telemetry and approved response%n• Dashboard: operator console%n%nค่าเริ่มต้นด้านความปลอดภัย:%n• API authentication เปิดทันที%n• Agent ใช้ per-agent key%n• Response ที่แก้ระบบต้องมีลายเซ็นและอายุสั้น%n• TLS certificate ต้องเชื่อถือได้%n%nSelf-contained: no separate .NET installation required.
FinishedHeadingLabel=ติดตั้งสำเร็จ
FinishedLabelNoIcons=NT Shield ติดตั้งเรียบร้อยแล้ว!
FinishedLabel=NT Shield ติดตั้งเรียบร้อยแล้ว!%n%nCentral: authenticated HTTPS on port 7443%nServices: NTShieldCentral / NTShieldAgent%n%nอ่าน EnrollmentToken และ OperatorApiKey จาก protected Server\secrets.json ด้วยสิทธิ์ Administrator%nห้ามปิด TLS validation ในระบบใช้งานจริง
ClickFinish=คลิก Finish เพื่อเริ่มใช้งาน
ButtonNext=Next >
ButtonBack=< Back
ButtonCancel=Cancel
ButtonFinish=Finish
SelectDirLabel3=เลือกตำแหน่งติดตั้ง
SelectComponentsLabel2=เลือกส่วนประกอบ
WizardSelectDir=เลือกตำแหน่งติดตั้ง
WizardSelectComponents=เลือกประเภทการติดตั้ง
WizardReady=พร้อมติดตั้ง
WizardInstalling=กำลังติดตั้ง...
StatusExtractFiles=กำลังติดตั้งไฟล์...

[Types]
Name: "full"; Description: "Full stack: Central + Agent + Dashboard"
Name: "server"; Description: "Central Server only"
Name: "endpoint"; Description: "Agent + Dashboard connected to an existing Central"
Name: "agent"; Description: "Agent only"
Name: "dashboard"; Description: "Dashboard only"
Name: "custom"; Description: "Custom"; Flags: iscustom

[Components]
Name: "central"; Description: "Central Server: authenticated API :7443 + Syslog :5514"; Types: full server custom
Name: "agent"; Description: "Windows Agent Service: IDS by default + signed approved response"; Types: full endpoint agent custom
Name: "dashboard"; Description: "Desktop Dashboard: incidents, fleet and response workflow"; Types: full endpoint dashboard custom

[Tasks]
Name: "desktopicon"; Description: "Create desktop icon for Dashboard"; GroupDescription: "Icons:"; Components: dashboard; Flags: checkedonce
Name: "desktopcentral"; Description: "Create desktop icon for Central connection info"; GroupDescription: "Icons:"; Components: central; Flags: checkedonce
Name: "startcentral"; Description: "Start Central service after install"; GroupDescription: "Central:"; Components: central
Name: "startagent"; Description: "Start Agent service after secure provisioning"; GroupDescription: "Agent:"; Components: agent
Name: "trayicon"; Description: "Show Agent tray icon and mini dashboard"; GroupDescription: "Agent:"; Components: agent
Name: "openfirewall"; Description: "Open Windows Firewall for Central TCP 7443 and Syslog UDP 5514"; GroupDescription: "Central:"; Components: central; Flags: unchecked

[Files]
Source: "{#SourceRoot}\assets\icons\NTShield.ico"; DestDir: "{app}"; Flags: ignoreversion

; Central
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

; Agent
Source: "{#SourceRoot}\artifacts\agent-win-x64\*"; DestDir: "{app}\Agent"; Flags: ignoreversion recursesubdirs createallsubdirs; Components: agent
Source: "{#SourceRoot}\assets\icons\NTShield.ico"; DestDir: "{app}\Agent"; Flags: ignoreversion; Components: agent
Source: "{#SourceRoot}\config\rules.json"; DestDir: "{app}\Agent"; Flags: ignoreversion; Components: agent
Source: "{#SourceRoot}\config\allowlist.json"; DestDir: "{app}\Agent"; Flags: ignoreversion skipifsourcedoesntexist; Components: agent
Source: "{#SourceRoot}\config\rules.json"; DestDir: "{app}\Agent\config"; Flags: ignoreversion; Components: agent
Source: "{#SourceRoot}\config\allowlist.json"; DestDir: "{app}\Agent\config"; Flags: ignoreversion skipifsourcedoesntexist; Components: agent
Source: "{#SourceRoot}\config\protection-pack.json"; DestDir: "{app}\Agent\config"; Flags: ignoreversion skipifsourcedoesntexist; Components: agent
Source: "{#SourceRoot}\tools\yara64.exe"; DestDir: "{app}\Agent\tools"; Flags: ignoreversion skipifsourcedoesntexist; Components: agent
Source: "{#SourceRoot}\installer\setup-helpers\register-agent-service.ps1"; DestDir: "{app}\Installer"; Flags: ignoreversion; Components: agent
Source: "{#SourceRoot}\installer\setup-helpers\unregister-agent-service.ps1"; DestDir: "{app}\Installer"; Flags: ignoreversion; Components: agent
Source: "{#SourceRoot}\installer\setup-helpers\register-agent-tray.ps1"; DestDir: "{app}\Installer"; Flags: ignoreversion; Components: agent
Source: "{#SourceRoot}\installer\setup-helpers\unregister-agent-tray.ps1"; DestDir: "{app}\Installer"; Flags: ignoreversion; Components: agent
Source: "{#SourceRoot}\installer\setup-helpers\stop-agent-for-upgrade.ps1"; DestDir: "{app}\Installer"; Flags: ignoreversion; Components: agent
Source: "{#SourceRoot}\installer\setup-helpers\verify-agent-install.ps1"; DestDir: "{app}\Installer"; Flags: ignoreversion; Components: agent
Source: "{#SourceRoot}\installer\setup-helpers\set-agent-central-url.ps1"; DestDir: "{app}\Installer"; Flags: ignoreversion; Components: agent
Source: "{#SourceRoot}\installer\templates\Set-Agent-Server.cmd"; DestDir: "{app}\Installer"; Flags: ignoreversion; Components: agent
Source: "{#SourceRoot}\installer\setup-helpers\stop-agent-for-upgrade.ps1"; DestDir: "{tmp}"; Flags: dontcopy

; Dashboard
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
Name: "{group}\NT Shield Dashboard"; Filename: "{app}\Dashboard\{#MyDashboardExe}"; IconFilename: "{app}\NTShield.ico"; Components: dashboard
Name: "{group}\Central Connection Info"; Filename: "{app}\Central\Open-Central-Info.cmd"; IconFilename: "{app}\NTShield.ico"; WorkingDir: "{app}\Central"; Components: central
Name: "{group}\Agent Logs"; Filename: "{commonappdata}\NTShield\Agent\logs"; IconFilename: "{app}\NTShield.ico"; Components: agent
Name: "{group}\Central Logs"; Filename: "{commonappdata}\NTShield\Server\logs"; IconFilename: "{app}\NTShield.ico"; Components: central
Name: "{group}\Show Agent tray icon"; Filename: "{app}\Agent\NTShield.Agent.Tray.exe"; Parameters: "--install-dir ""{app}\Agent"""; IconFilename: "{app}\NTShield.ico"; WorkingDir: "{app}\Agent"; Components: agent
Name: "{group}\Configure Agent Central"; Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\Installer\set-agent-central-url.ps1"" -InstallDir ""{app}\Agent"""; IconFilename: "{app}\NTShield.ico"; Components: agent
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"; IconFilename: "{app}\NTShield.ico"
Name: "{autodesktop}\NT Shield Dashboard"; Filename: "{app}\Dashboard\{#MyDashboardExe}"; IconFilename: "{app}\NTShield.ico"; Tasks: desktopicon; Components: dashboard
Name: "{autodesktop}\NT Shield Central"; Filename: "{app}\Central\Open-Central-Info.cmd"; IconFilename: "{app}\NTShield.ico"; WorkingDir: "{app}\Central"; Tasks: desktopcentral; Components: central

[Run]
; Central must start before a bundled Agent can enroll and receive policy.
Filename: "powershell.exe"; \
  Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\Installer\register-central-service.ps1"" -InstallDir ""{app}\Central"" -DataDir ""{commonappdata}\NTShield\Server"" -ServiceName ""NTShieldCentral"" -StartService {code:GetCentralBootstrapStartFlag} -Port ""{code:GetCentralPort}"" -PublicHost ""{code:GetPublicHost}"" -TrustCertificate ""1"" -RegenerateCertificate ""1"""; \
  StatusMsg: "Registering authenticated Central and protected secrets..."; \
  Flags: runhidden waituntilterminated; \
  Components: central

Filename: "powershell.exe"; \
  Parameters: "-NoProfile -ExecutionPolicy Bypass -Command ""New-NetFirewallRule -DisplayName 'NT Shield HTTPS' -Direction Inbound -Action Allow -Protocol TCP -LocalPort {code:GetCentralPort} -ErrorAction SilentlyContinue; New-NetFirewallRule -DisplayName 'NT Shield Syslog 5514' -Direction Inbound -Action Allow -Protocol UDP -LocalPort 5514 -ErrorAction SilentlyContinue"""; \
  StatusMsg: "Opening selected firewall ports..."; \
  Flags: runhidden waituntilterminated; \
  Components: central; \
  Tasks: openfirewall

; Configure Agent while stopped, then apply syslog and start only after all trust material is written.
Filename: "powershell.exe"; \
  Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\Installer\register-agent-service.ps1"" -InstallDir ""{app}\Agent"" -DataDir ""{commonappdata}\NTShield\Agent"" -ServiceName ""NTShieldAgent"" -StartService 0 -CentralUrl ""{code:GetAgentCentralUrl}"" -EnrollmentToken ""{code:GetEnrollmentToken}"" -CaCertificatePath ""{code:GetAgentCaPath}"""; \
  StatusMsg: "Registering Agent with trusted Central HTTPS..."; \
  Flags: runhidden waituntilterminated; \
  Components: agent

Filename: "powershell.exe"; \
  Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\Installer\set-agent-central-url.ps1"" -InstallDir ""{app}\Agent"" -CentralUrl ""{code:GetAgentCentralUrl}"" -EnrollmentToken ""{code:GetEnrollmentToken}"" -CaCertificatePath ""{code:GetAgentCaPath}"" -EnableSyslog -SyslogHost ""{code:GetAgentCentralHost}"" -SyslogPort 5514 -NoRestart"; \
  StatusMsg: "Applying authenticated Agent connection and syslog destination..."; \
  Flags: runhidden waituntilterminated; \
  Components: agent

Filename: "powershell.exe"; \
  Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\Installer\verify-agent-install.ps1"" -InstallDir ""{app}\Agent"" -ServiceName ""NTShieldAgent"" -MinVersion ""{#MyAppVersion}"""; \
  StatusMsg: "Verifying Agent binary version..."; \
  Flags: runhidden waituntilterminated; \
  Components: agent

Filename: "powershell.exe"; \
  Parameters: "-NoProfile -ExecutionPolicy Bypass -Command ""Start-Service NTShieldAgent; Start-Sleep -Seconds 2; if ((Get-Service NTShieldAgent).Status -ne 'Running') { throw 'NTShieldAgent failed to start' }"""; \
  StatusMsg: "Starting securely provisioned Agent..."; \
  Flags: runhidden waituntilterminated; \
  Components: agent; \
  Tasks: startagent

Filename: "powershell.exe"; \
  Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\Installer\register-agent-tray.ps1"" -InstallDir ""{app}\Agent"" -StartNow 1 -RunAtLogon 1"; \
  StatusMsg: "Enabling Agent tray icon..."; \
  Flags: runhidden waituntilterminated; \
  Components: agent; \
  Tasks: trayicon

Filename: "{app}\Dashboard\{#MyDashboardExe}"; Description: "Launch NT Shield Dashboard"; Flags: nowait postinstall skipifsilent; Components: dashboard

[UninstallRun]
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\Installer\unregister-agent-tray.ps1"" -InstallDir ""{app}\Agent"""; RunOnceId: "StopAgentTray"; Flags: runhidden waituntilterminated; Components: agent
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\Installer\unregister-agent-service.ps1"" -ServiceName ""NTShieldAgent"""; RunOnceId: "StopAgentService"; Flags: runhidden waituntilterminated; Components: agent
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\Installer\unregister-central-service.ps1"" -ServiceName ""NTShieldCentral"""; RunOnceId: "StopCentralService"; Flags: runhidden waituntilterminated; Components: central
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -Command ""Remove-NetFirewallRule -DisplayName 'NT Shield HTTPS' -ErrorAction SilentlyContinue; Remove-NetFirewallRule -DisplayName 'NT Shield Syslog 5514' -ErrorAction SilentlyContinue"""; RunOnceId: "RemoveShieldFirewall"; Flags: runhidden waituntilterminated; Components: central

[Code]
var
  CentralInstallPage: TInputQueryWizardPage;
  ExistingCentralPage: TInputQueryWizardPage;
  GCentralPort: String;
  GPublicHost: String;
  GAgentUrl: String;

function GetCommandLineParam(const ParamName: String): String;
var
  I: Integer;
  S, Prefix: String;
begin
  Result := '';
  Prefix := '/' + ParamName + '=';
  for I := 1 to ParamCount do
  begin
    S := ParamStr(I);
    if CompareText(Copy(S, 1, Length(Prefix)), Prefix) = 0 then
    begin
      Result := Copy(S, Length(Prefix) + 1, MaxInt);
      if (Length(Result) >= 2) and (S[Length(Prefix) + 1] = '"') and
         (Result[Length(Result)] = '"') then
        Result := Copy(Result, 2, Length(Result) - 2);
      Exit;
    end;
  end;
end;

procedure InitializeWizard;
var
  CmdPort, CmdHost, CmdUrl, CmdToken, CmdCa: String;
begin
  CentralInstallPage := CreateInputQueryPage(wpSelectComponents,
    'Central HTTPS and certificate identity',
    'Used when this setup installs Central',
    'Choose the HTTPS port and the DNS/Public IP that Agents will actually use.' + #13#10 +
    'The installer creates protected credentials and exports central.cer.' + #13#10 +
    'Silent: /Port=7443 /PublicHost=shield.example.go.th');
  CentralInstallPage.Add('HTTPS Port:', False);
  CentralInstallPage.Add('Public DNS / IP for certificate SAN (optional):', False);

  CmdPort := GetCommandLineParam('Port');
  CmdHost := GetCommandLineParam('PublicHost');
  if CmdHost = '' then CmdHost := GetCommandLineParam('ServerHost');
  if CmdPort <> '' then CentralInstallPage.Values[0] := CmdPort else CentralInstallPage.Values[0] := '7443';
  CentralInstallPage.Values[1] := CmdHost;

  ExistingCentralPage := CreateInputQueryPage(CentralInstallPage.ID,
    'Existing authenticated Central',
    'Used for Agent or Endpoint installation without Central',
    'Use an HTTPS URL, EnrollmentToken from protected Central secrets.json, and' + #13#10 +
    'central.cer/CA certificate unless the certificate is already trusted by Windows.' + #13#10 +
    'Silent: /CentralUrl=https://10.0.0.5:7443 /EnrollmentToken=... /CaCertificatePath=C:\secure\central.cer');
  ExistingCentralPage.Add('Central HTTPS URL or host:', False);
  ExistingCentralPage.Add('HTTPS Port:', False);
  ExistingCentralPage.Add('Enrollment Token:', False);
  ExistingCentralPage.Add('Central CA / certificate path (blank = Windows trust store):', False);

  CmdUrl := GetCommandLineParam('CentralUrl');
  CmdHost := GetCommandLineParam('ServerHost');
  if CmdHost = '' then CmdHost := GetCommandLineParam('ServerIp');
  CmdToken := GetCommandLineParam('EnrollmentToken');
  CmdCa := GetCommandLineParam('CaCertificatePath');
  if CmdCa = '' then CmdCa := GetCommandLineParam('CaCertificate');

  if CmdUrl <> '' then ExistingCentralPage.Values[0] := CmdUrl
  else if CmdHost <> '' then ExistingCentralPage.Values[0] := CmdHost
  else ExistingCentralPage.Values[0] := 'localhost';
  if CmdPort <> '' then ExistingCentralPage.Values[1] := CmdPort else ExistingCentralPage.Values[1] := '7443';
  ExistingCentralPage.Values[2] := CmdToken;
  ExistingCentralPage.Values[3] := CmdCa;
end;

function ShouldSkipPage(PageID: Integer): Boolean;
begin
  Result := False;
  if Assigned(CentralInstallPage) and (PageID = CentralInstallPage.ID) then
    Result := not WizardIsComponentSelected('central')
  else if Assigned(ExistingCentralPage) and (PageID = ExistingCentralPage.ID) then
    Result := (not WizardIsComponentSelected('agent')) or WizardIsComponentSelected('central');
end;

function NormalizeHttpsUrl(const HostOrUrl, Port: String): String;
var
  Value: String;
begin
  Value := Trim(HostOrUrl);
  while (Length(Value) > 0) and (Value[Length(Value)] = '/') do
    Delete(Value, Length(Value), 1);
  if Pos('https://', LowerCase(Value)) = 1 then
    Result := Value
  else
    Result := 'https://' + Value + ':' + Port;
end;

function ExtractHost(const UrlOrHost: String): String;
var
  Value: String;
  P: Integer;
begin
  Value := Trim(UrlOrHost);
  P := Pos('://', Value);
  if P > 0 then Delete(Value, 1, P + 2);
  P := Pos('/', Value);
  if P > 0 then Value := Copy(Value, 1, P - 1);
  P := Pos(':', Value);
  if P > 0 then Value := Copy(Value, 1, P - 1);
  if Value = '' then Value := '127.0.0.1';
  Result := Value;
end;

function ValidatePort(const Value: String; var Normalized: String): Boolean;
var
  PortNumber: Integer;
begin
  PortNumber := StrToIntDef(Trim(Value), -1);
  Result := (PortNumber >= 1) and (PortNumber <= 65535);
  if Result then Normalized := IntToStr(PortNumber);
end;

function NextButtonClick(CurPageID: Integer): Boolean;
var
  PortValue, HostValue, CaPath: String;
begin
  Result := True;

  if Assigned(CentralInstallPage) and (CurPageID = CentralInstallPage.ID) then
  begin
    if not ValidatePort(CentralInstallPage.Values[0], PortValue) then
    begin
      MsgBox('Central HTTPS port must be between 1 and 65535.', mbError, MB_OK);
      Result := False;
      Exit;
    end;
    GCentralPort := PortValue;
    GPublicHost := Trim(CentralInstallPage.Values[1]);
  end;

  if Assigned(ExistingCentralPage) and (CurPageID = ExistingCentralPage.ID) then
  begin
    HostValue := Trim(ExistingCentralPage.Values[0]);
    if HostValue = '' then
    begin
      MsgBox('Central HTTPS host or URL is required.', mbError, MB_OK);
      Result := False;
      Exit;
    end;
    if Pos('http://', LowerCase(HostValue)) = 1 then
    begin
      MsgBox('Plain HTTP is disabled. Use HTTPS.', mbError, MB_OK);
      Result := False;
      Exit;
    end;
    if not ValidatePort(ExistingCentralPage.Values[1], PortValue) then
    begin
      MsgBox('Central HTTPS port must be between 1 and 65535.', mbError, MB_OK);
      Result := False;
      Exit;
    end;
    CaPath := Trim(ExistingCentralPage.Values[3]);
    if (CaPath <> '') and (not FileExists(CaPath)) then
    begin
      MsgBox('Central CA/certificate file not found:' + #13#10 + CaPath, mbError, MB_OK);
      Result := False;
      Exit;
    end;
    GAgentUrl := NormalizeHttpsUrl(HostValue, PortValue);
  end;
end;

function GetCentralPort(Param: String): String;
begin
  if GCentralPort <> '' then Result := GCentralPort
  else if Assigned(CentralInstallPage) and (Trim(CentralInstallPage.Values[0]) <> '') then Result := Trim(CentralInstallPage.Values[0])
  else
  begin
    Result := GetCommandLineParam('Port');
    if Result = '' then Result := '7443';
  end;
end;

function GetPublicHost(Param: String): String;
begin
  if GPublicHost <> '' then Result := GPublicHost
  else if Assigned(CentralInstallPage) then Result := Trim(CentralInstallPage.Values[1])
  else
  begin
    Result := GetCommandLineParam('PublicHost');
    if Result = '' then Result := GetCommandLineParam('ServerHost');
  end;
end;

function GetAgentCentralUrl(Param: String): String;
var
  HostValue, PortValue: String;
begin
  if WizardIsComponentSelected('central') then
  begin
    Result := 'https://localhost:' + GetCentralPort('');
    Exit;
  end;
  if GAgentUrl <> '' then
  begin
    Result := GAgentUrl;
    Exit;
  end;
  Result := GetCommandLineParam('CentralUrl');
  if Result <> '' then Exit;
  HostValue := GetCommandLineParam('ServerHost');
  if HostValue = '' then HostValue := 'localhost';
  PortValue := GetCommandLineParam('Port');
  if PortValue = '' then PortValue := '7443';
  if Assigned(ExistingCentralPage) then
  begin
    HostValue := Trim(ExistingCentralPage.Values[0]);
    PortValue := Trim(ExistingCentralPage.Values[1]);
  end;
  Result := NormalizeHttpsUrl(HostValue, PortValue);
end;

function GetAgentCentralHost(Param: String): String;
begin
  Result := ExtractHost(GetAgentCentralUrl(''));
end;

function GetEnrollmentToken(Param: String): String;
begin
  if WizardIsComponentSelected('central') then
  begin
    Result := '';
    Exit;
  end;
  Result := GetCommandLineParam('EnrollmentToken');
  if (Result = '') and Assigned(ExistingCentralPage) then
    Result := Trim(ExistingCentralPage.Values[2]);
end;

function GetAgentCaPath(Param: String): String;
begin
  if WizardIsComponentSelected('central') then
  begin
    Result := ExpandConstant('{commonappdata}\NTShield\Server\certs\central.cer');
    Exit;
  end;
  Result := GetCommandLineParam('CaCertificatePath');
  if Result = '' then Result := GetCommandLineParam('CaCertificate');
  if (Result = '') and Assigned(ExistingCentralPage) then
    Result := Trim(ExistingCentralPage.Values[3]);
end;

function GetCentralBootstrapStartFlag(Param: String): String;
begin
  if WizardIsComponentSelected('agent') or WizardIsTaskSelected('startcentral') then Result := '1'
  else Result := '0';
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
  ScriptPath: String;
begin
  Result := '';
  NeedsRestart := False;
  KillAll;

  ExtractTemporaryFile('stop-agent-for-upgrade.ps1');
  ScriptPath := ExpandConstant('{tmp}\stop-agent-for-upgrade.ps1');
  if FileExists(ScriptPath) then
    Exec('powershell.exe',
      '-NoProfile -ExecutionPolicy Bypass -File "' + ScriptPath + '" -ServiceName "NTShieldAgent" -InstallDir "' + ExpandConstant('{app}\Agent') + '"',
      '', SW_HIDE, ewWaitUntilTerminated, ResultCode);

  ExtractTemporaryFile('stop-central-for-upgrade.ps1');
  ScriptPath := ExpandConstant('{tmp}\stop-central-for-upgrade.ps1');
  if FileExists(ScriptPath) then
    Exec('powershell.exe',
      '-NoProfile -ExecutionPolicy Bypass -File "' + ScriptPath + '" -ServiceName "NTShieldCentral" -InstallDir "' + ExpandConstant('{app}\Central') + '"',
      '', SW_HIDE, ewWaitUntilTerminated, ResultCode);

  KillAll;
end;

function InitializeSetup(): Boolean;
begin
  Result := True;
  if not IsWin64 then
  begin
    MsgBox('NT Shield requires a 64-bit Windows operating system.', mbError, MB_OK);
    Result := False;
  end;
end;

function UpdateReadyMemo(Space, NewLine, MemoUserInfoInfo, MemoDirInfo, MemoTypeInfo,
  MemoComponentsInfo, MemoGroupInfo, MemoTasksInfo: String): String;
var
  SecurityInfo: String;
begin
  SecurityInfo :=
    'Security defaults:' + NewLine +
    Space + 'Central API authentication required' + NewLine +
    Space + 'Per-agent enrollment and API keys' + NewLine +
    Space + 'Trusted HTTPS certificate validation' + NewLine +
    Space + 'Signed, target-bound, expiring one-time response actions';

  Result := MemoDirInfo + NewLine + NewLine + MemoComponentsInfo + NewLine + NewLine;
  if WizardIsComponentSelected('central') then
    Result := Result + 'Central: https://localhost:' + GetCentralPort('') + NewLine + NewLine;
  if WizardIsComponentSelected('agent') then
    Result := Result + 'Agent target: ' + GetAgentCentralUrl('') + NewLine +
      'TLS trust: ' + GetAgentCaPath('') + NewLine + NewLine;
  Result := Result + SecurityInfo + NewLine + NewLine + MemoTasksInfo;
end;
