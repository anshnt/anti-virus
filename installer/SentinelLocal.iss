; Per-user installer: no administrator rights, no service, no driver.
; Build with tools/build_exe.py (passes /DAppVersion).
#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif

[Setup]
AppId={{1DF1C7F2-CC55-42ED-940C-58E56661C0AD}
AppName=Sentinel Local
AppVersion={#AppVersion}
AppVerName=Sentinel Local {#AppVersion}
AppPublisher=anshnt
AppPublisherURL=https://github.com/anshnt/anti-virus
AppSupportURL=https://github.com/anshnt/anti-virus/issues
DefaultDirName={localappdata}\Programs\Sentinel Local
DisableProgramGroupPage=yes
DisableDirPage=auto
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
OutputDir=..\dist
OutputBaseFilename=SentinelLocal-Setup-{#AppVersion}
SetupIconFile=..\assets\sentinel.ico
UninstallDisplayIcon={app}\SentinelLocal.exe
UninstallDisplayName=Sentinel Local
WizardStyle=modern
Compression=lzma2
SolidCompression=yes
; Ask to close the running console before files are replaced or removed.
AppMutex=SentinelLocal.Running
CloseApplications=yes

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"

[Files]
Source: "..\dist\SentinelLocal\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\Sentinel Local"; Filename: "{app}\SentinelLocal.exe"
Name: "{autodesktop}\Sentinel Local"; Filename: "{app}\SentinelLocal.exe"; Tasks: desktopicon

[Registry]
; Remove the optional sign-in launch entry on uninstall. Quarantine and history
; in %LOCALAPPDATA%\SentinelLocal are kept so nothing is lost by uninstalling.
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: none; ValueName: "Sentinel Local Antivirus"; Flags: uninsdeletevalue dontcreatekey

[Run]
Filename: "{app}\SentinelLocal.exe"; Description: "{cm:LaunchProgram,Sentinel Local}"; Flags: nowait postinstall skipifsilent
