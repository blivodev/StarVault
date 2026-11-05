; Inno Setup script for the StarVault installer.
;
; StarVault is a single PyInstaller one-file exe, so the installer simply wraps
; that exe with a Start Menu entry, an "Apps & features" row and an uninstaller.
; Build it with installer\make_installer.ps1, which fills in the defines below.
;
; Per-user by default (no administrator prompt). The app keeps its vault in
; %LOCALAPPDATA%\StarVault, so the install folder is never written to and an
; uninstall leaves the user's vault alone.

#ifndef AppVersion
  #error Pass /DAppVersion=<version>
#endif
#ifndef StageDir
  #error Pass /DStageDir=<the staged folder>
#endif
#ifndef OutputDir
  #error Pass /DOutputDir=<where the installer goes>
#endif

#define AppName "StarVault"
#define AppPublisher "sektor9.dev"
#define AppExeName "StarVault.exe"
#define AppURL "https://starvault.sektor9.dev"

[Setup]
; A STABLE AppId: Inno uses it to recognise an earlier install, so an upgrade
; replaces the old version. Never change it.
AppId={{4C7E1D92-8A35-4B61-9F0E-2D5C8B7A31F6}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppURL}
AppSupportURL={#AppURL}
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
DisableProgramGroupPage=yes
OutputDir={#OutputDir}
OutputBaseFilename=StarVault-{#AppVersion}-setup
SetupIconFile={#StageDir}\starvault.ico
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
UninstallDisplayName={#AppName} {#AppVersion}
UninstallDisplayIcon={app}\{#AppExeName}
LicenseFile={#StageDir}\README.md

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "{#StageDir}\{#AppExeName}"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#StageDir}\starvault.ico"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#StageDir}\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#StageDir}\licenses\*"; DestDir: "{app}\licenses"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\{#AppName}"; Filename: "{app}\{#AppExeName}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#AppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(AppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
; PyInstaller's one-file mode unpacks to %TEMP%\_MEI* at runtime and cleans up
; after itself; nothing of the user's is written to {app}, so no extra deletes.
Type: filesandordirs; Name: "{app}\licenses"
