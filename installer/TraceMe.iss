; Inno Setup script for the TraceMe Windows installer.
; Build with installer\build.ps1 (publishes a self-contained build first), or:
;   ISCC.exe /DAppVersion=1.0.0 /DSourceDir=..\artifacts\publish TraceMe.iss

#ifndef AppVersion
  #define AppVersion "1.0.0"
#endif
#ifndef SourceDir
  #define SourceDir "..\artifacts\publish"
#endif

[Setup]
AppId={{B5F2A0C4-7E3D-4C1A-9A52-3D6E8F1B7C20}
AppName=TraceMe
AppVersion={#AppVersion}
AppVerName=TraceMe {#AppVersion}
AppPublisher=Sayed Saeed
DefaultDirName={autopf}\TraceMe
DefaultGroupName=TraceMe
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
LicenseFile=..\LICENSE
OutputDir=..\artifacts
OutputBaseFilename=TraceMe-Setup-{#AppVersion}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
UninstallDisplayName=TraceMe
UninstallDisplayIcon={app}\TraceMe.exe

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Shortcuts:"

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Excludes: "*.cmd,*.pdb"; Flags: recursesubdirs createallsubdirs ignoreversion
Source: "..\LICENSE"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\THIRD-PARTY-NOTICES.md"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\TraceMe"; Filename: "{app}\TraceMe.exe"; Parameters: "--open"; WorkingDir: "{app}"; Comment: "Start TraceMe and open it in your browser"
Name: "{autodesktop}\TraceMe"; Filename: "{app}\TraceMe.exe"; Parameters: "--open"; WorkingDir: "{app}"; Tasks: desktopicon

[Registry]
; UDP/TCP traces and the Apps section need administrator rights, so Windows always asks for them when TraceMe starts.
Root: HKLM; Subkey: "SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers"; ValueType: string; \
  ValueName: "{app}\TraceMe.exe"; ValueData: "~ RUNASADMIN"; Flags: uninsdeletevalue

[Run]
Filename: "{app}\TraceMe.exe"; Parameters: "--open"; WorkingDir: "{app}"; Description: "Start TraceMe now"; Flags: nowait postinstall skipifsilent

[Code]
procedure StopRunningTraceMe;
var
  code: Integer;
begin
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /T /IM TraceMe.exe', '', SW_HIDE, ewWaitUntilTerminated, code);
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  StopRunningTraceMe;
  Result := '';
end;

function InitializeUninstall: Boolean;
begin
  StopRunningTraceMe;
  Result := True;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  dataDir: String;
begin
  if (CurUninstallStep = usPostUninstall) and (not UninstallSilent) then
  begin
    dataDir := ExpandConstant('{localappdata}\TraceMe');
    if DirExists(dataDir) then
      if MsgBox('Also delete your TraceMe data (trace history, alert rules, settings)?' + #13#10 + dataDir,
                mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES then
        DelTree(dataDir, True, True, True);
  end;
end;
