; Kavach Antivirus — Inno Setup script
; Developed by Cecil Baraik
; Build with: build.ps1 (or open this file in Inno Setup 6 and press Compile after running build.ps1)

#define AppName "Kavach Antivirus"
#ifndef AppVersion
  #define AppVersion "1.1.0"
#endif
#define AppPublisher "Cecil Baraik"
#define AppExe "Kavach.exe"
#define ServiceName "KavachService"

[Setup]
AppId={{6E1F4C2A-8B7D-4A55-9C0E-4B6A7D1C2E90}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
AppCopyright=© 2026 {#AppPublisher}
VersionInfoCompany={#AppPublisher}
VersionInfoProductName={#AppName}
VersionInfoVersion={#AppVersion}
DefaultDirName={autopf}\Kavach
DefaultGroupName=Kavach
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.17763
OutputDir=Output
OutputBaseFilename=KavachSetup-{#AppVersion}
SetupIconFile=..\src\Kavach.App\Assets\kavach.ico
WizardSmallImageFile=wizard-small.bmp
WizardImageFile=wizard-large.bmp
UninstallDisplayIcon={app}\{#AppExe}
UninstallDisplayName={#AppName}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
CloseApplications=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Shortcuts:"

[Dirs]
; The app (normal user) and the service (SYSTEM) share this data folder
Name: "{commonappdata}\Kavach"; Permissions: users-modify

[Files]
Source: "..\publish\App\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\publish\Service\*"; DestDir: "{app}\Service"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\Kavach Antivirus"; Filename: "{app}\{#AppExe}"
Name: "{autodesktop}\Kavach Antivirus"; Filename: "{app}\{#AppExe}"; Tasks: desktopicon

[Run]
; Install the always-on protection service (runs as LocalSystem, starts with Windows, restarts if stopped)
Filename: "{sys}\sc.exe"; Parameters: "create {#ServiceName} binPath= ""\""{app}\Service\KavachService.exe\"""" start= auto DisplayName= ""Kavach Antivirus Protection"""; Flags: runhidden waituntilterminated; StatusMsg: "Installing the protection service..."
Filename: "{sys}\sc.exe"; Parameters: "description {#ServiceName} ""Kavach Antivirus real-time, ransomware and USB protection. Developed by Cecil Baraik."""; Flags: runhidden waituntilterminated
Filename: "{sys}\sc.exe"; Parameters: "failure {#ServiceName} reset= 86400 actions= restart/5000/restart/5000/restart/15000"; Flags: runhidden waituntilterminated
; Let Kavach place its ransomware bait files when Windows "Controlled folder access" is on
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -Command ""try {{ Add-MpPreference -ControlledFolderAccessAllowedApplications '{app}\Service\KavachService.exe','{app}\{#AppExe}' }} catch {{}}"""; Flags: runhidden waituntilterminated; StatusMsg: "Allowing Kavach in Windows ransomware protection..."
Filename: "{sys}\sc.exe"; Parameters: "start {#ServiceName}"; Flags: runhidden waituntilterminated; StatusMsg: "Starting protection..."
; Open Kavach as the normal (non-admin) user
Filename: "{app}\{#AppExe}"; Description: "Open Kavach Antivirus"; Flags: postinstall nowait runasoriginaluser

[UninstallRun]
Filename: "{sys}\taskkill.exe"; Parameters: "/F /IM {#AppExe}"; Flags: runhidden; RunOnceId: "KillApp"
Filename: "{sys}\sc.exe"; Parameters: "stop {#ServiceName}"; Flags: runhidden waituntilterminated; RunOnceId: "StopService"
Filename: "{sys}\sc.exe"; Parameters: "delete {#ServiceName}"; Flags: runhidden waituntilterminated; RunOnceId: "DeleteService"
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -Command ""try {{ Remove-MpPreference -ControlledFolderAccessAllowedApplications '{app}\Service\KavachService.exe','{app}\{#AppExe}' }} catch {{}}"""; Flags: runhidden waituntilterminated; RunOnceId: "RemoveCfaAllow"

[Registry]
; Remove the per-user "start with Windows" entry and right-click menu on uninstall
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: none; ValueName: "Kavach"; Flags: uninsdeletevalue dontcreatekey
Root: HKCU; Subkey: "Software\Classes\*\shell\KavachScan"; Flags: uninsdeletekey dontcreatekey
Root: HKCU; Subkey: "Software\Classes\Directory\shell\KavachScan"; Flags: uninsdeletekey dontcreatekey
Root: HKCU; Subkey: "Software\Classes\Drive\shell\KavachScan"; Flags: uninsdeletekey dontcreatekey

[Code]
// Stop an older Kavach (service and app) before files are replaced during an upgrade
procedure CurStepChanged(CurStep: TSetupStep);
var
  ResultCode: Integer;
begin
  if CurStep = ssInstall then
  begin
    Exec(ExpandConstant('{sys}\sc.exe'), 'stop {#ServiceName}', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM {#AppExe}', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Sleep(1500);
    Exec(ExpandConstant('{sys}\sc.exe'), 'delete {#ServiceName}', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Sleep(500);
  end;
end;
