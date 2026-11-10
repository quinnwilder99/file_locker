; Inno Setup script for File Locker. Build it with scripts\build-installer.ps1,
; which compiles the release binaries and fetches the WinFsp installer first.

#define AppName "File Locker"
#define AppVersion "0.1.0"
#define AppExe "FileLocker.exe"
#define WinFspMsi "winfsp-2.1.25156.msi"

[Setup]
AppId={{6C1C7B5E-2F44-4C1B-9E1D-5A0B8F3E7A21}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppName}
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
; WinFsp is a driver and the Explorer integration is machine-wide.
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
OutputDir=..\dist
OutputBaseFilename=FileLocker-Setup-{#AppVersion}
SetupIconFile=..\crates\flk-app\assets\app.ico
UninstallDisplayIcon={app}\{#AppExe}
UninstallDisplayName={#AppName}
WizardStyle=modern
Compression=lzma2/max
SolidCompression=yes
CloseApplications=yes
RestartApplications=no
ChangesAssociations=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "startup"; Description: "Start File Locker when I sign in to Windows"; GroupDescription: "Options:"

[Files]
Source: "..\target\release\{#AppExe}"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\target\release\flk.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "THIRD-PARTY-NOTICES.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\target\redist\{#WinFspMsi}"; DestDir: "{tmp}"; Flags: deleteafterinstall; Check: not WinFspInstalled

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExe}"
Name: "{group}\Uninstall {#AppName}"; Filename: "{uninstallexe}"

[Registry]
; Double-click "Unlock vault.flkvault" in a vault folder to unlock it.
Root: HKLM; Subkey: "Software\Classes\.flkvault"; ValueType: string; ValueData: "FileLocker.Vault"; Flags: uninsdeletekey
Root: HKLM; Subkey: "Software\Classes\FileLocker.Vault"; ValueType: string; ValueData: "File Locker vault"; Flags: uninsdeletekey
Root: HKLM; Subkey: "Software\Classes\FileLocker.Vault\DefaultIcon"; ValueType: string; ValueData: "{app}\{#AppExe},0"
Root: HKLM; Subkey: "Software\Classes\FileLocker.Vault\shell\open"; ValueType: string; ValueData: "Unlock vault"
Root: HKLM; Subkey: "Software\Classes\FileLocker.Vault\shell\open\command"; ValueType: string; ValueData: """{app}\{#AppExe}"" --unlock ""%1"""
; Right-click any file or folder: "Move into vault…" (under "Show more options" on Windows 11).
Root: HKLM; Subkey: "Software\Classes\*\shell\FileLocker.MoveInto"; ValueType: string; ValueData: "Move into vault…"; Flags: uninsdeletekey
Root: HKLM; Subkey: "Software\Classes\*\shell\FileLocker.MoveInto"; ValueType: string; ValueName: "Icon"; ValueData: "{app}\{#AppExe},0"
Root: HKLM; Subkey: "Software\Classes\*\shell\FileLocker.MoveInto\command"; ValueType: string; ValueData: """{app}\{#AppExe}"" --move-into ""%1"""
Root: HKLM; Subkey: "Software\Classes\Directory\shell\FileLocker.MoveInto"; ValueType: string; ValueData: "Move into vault…"; Flags: uninsdeletekey
Root: HKLM; Subkey: "Software\Classes\Directory\shell\FileLocker.MoveInto"; ValueType: string; ValueName: "Icon"; ValueData: "{app}\{#AppExe},0"
Root: HKLM; Subkey: "Software\Classes\Directory\shell\FileLocker.MoveInto\command"; ValueType: string; ValueData: """{app}\{#AppExe}"" --move-into ""%1"""
; Start at sign-in (the app's Settings window can change this later).
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "File Locker"; ValueData: """{app}\{#AppExe}"" --tray"; Flags: uninsdeletevalue; Tasks: startup

[Run]
Filename: "msiexec.exe"; Parameters: "/i ""{tmp}\{#WinFspMsi}"" /qn /norestart"; StatusMsg: "Installing WinFsp (lets vaults open as drives)…"; Flags: waituntilterminated; Check: not WinFspInstalled
Filename: "{app}\{#AppExe}"; Description: "Open File Locker"; Flags: nowait postinstall skipifsilent runasoriginaluser

[UninstallRun]
; Lock every vault before removing the app.
Filename: "{sys}\taskkill.exe"; Parameters: "/im {#AppExe}"; Flags: runhidden; RunOnceId: "CloseFileLocker"

[UninstallDelete]
Type: files; Name: "{app}\*.log"

[Code]
function WinFspInstalled: Boolean;
var
  Dir: String;
begin
  Result := RegQueryStringValue(HKLM32, 'SOFTWARE\WinFsp', 'InstallDir', Dir)
    and FileExists(AddBackslash(Dir) + 'bin\winfsp-x64.dll');
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
    SuppressibleMsgBox('File Locker was removed. Your vault folders and the files in them were not touched.' + #13#10#13#10 +
      'WinFsp was left installed because other programs may use it. You can remove it from Settings > Apps.',
      mbInformation, MB_OK, IDOK);
end;
