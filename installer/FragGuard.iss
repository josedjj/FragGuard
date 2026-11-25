; =====================================================================================
;  Instalador de FragGuard (Inno Setup 6)
;  Se genera con:  .\scripts\build-installer.ps1
;  Espera en SourceDir la publicación autocontenida: Service\, UI\, browser-extension\, LICENSE,
;  THIRD_PARTY_NOTICES.md. No necesita .NET instalado en el equipo de destino.
; =====================================================================================

#ifndef AppVersion
  #define AppVersion "0.1.0"
#endif
#ifndef SourceDir
  #define SourceDir "..\artifacts\package"
#endif
#ifndef OutputDir
  #define OutputDir "..\artifacts\installer"
#endif

[Setup]
; AppId identifica la instalación para actualizar y desinstalar: NO cambiarlo nunca.
AppId={{8C1E5B52-3F0A-4D7E-9B61-6E2A4F9D0C17}
AppName=FragGuard
AppVersion={#AppVersion}
AppVerName=FragGuard {#AppVersion}
AppPublisher=FragGuard (código abierto, GPL-3.0)
AppPublisherURL=https://github.com/josedjj/FragGuard
AppSupportURL=https://github.com/josedjj/FragGuard/issues
AppUpdatesURL=https://github.com/josedjj/FragGuard/releases
AppCopyright=Copyright (C) 2026 josedjj y colaboradores de FragGuard
VersionInfoVersion={#AppVersion}
; Siempre en Program Files: el servicio corre como SYSTEM y sus binarios deben estar en una carpeta
; que solo puedan modificar los administradores.
DefaultDirName={autopf}\FragGuard
DisableDirPage=yes
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.17763
LicenseFile=..\LICENSE
OutputDir={#OutputDir}
OutputBaseFilename=FragGuard-Setup-{#AppVersion}
SetupIconFile=..\src\FragGuard.UI\Assets\fragguard.ico
UninstallDisplayIcon={app}\UI\FragGuard.exe
UninstallDisplayName=FragGuard
WizardStyle=modern
Compression=lzma2/max
SolidCompression=yes
; Cerramos FragGuard nosotros (servicio incluido) en PrepareToInstall.
CloseApplications=no
SetupLogging=yes

[Languages]
Name: "es"; MessagesFile: "compiler:Languages\Spanish.isl"
Name: "en"; MessagesFile: "compiler:Default.isl"

[CustomMessages]
es.ServiceStartFailed=El servicio de protección de FragGuard no ha podido arrancar (código %1). Revisa los registros en %2.
en.ServiceStartFailed=The FragGuard protection service could not start (code %1). Check the logs in %2.
es.PurgeData=¿Quieres borrar también el historial, los ajustes y la CUARENTENA de FragGuard?%n%nSi vas a reinstalarlo, elige No para conservarlos.
en.PurgeData=Do you also want to delete FragGuard's history, settings and QUARANTINE?%n%nChoose No to keep them if you plan to reinstall.
es.TrayComment=FragGuard: antivirus ligero para gamers
en.TrayComment=FragGuard: lightweight antivirus for gamers

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[InstallDelete]
; Sin restos de versiones anteriores (p. ej. DLL que ya no se usan).
Type: filesandordirs; Name: "{app}\Service"
Type: filesandordirs; Name: "{app}\UI"
Type: filesandordirs; Name: "{app}\browser-extension"

[UninstallDelete]
; Si la carpeta la creó una instalación anterior con scripts\install.ps1, Inno no la borraría por sí solo.
Type: dirifempty; Name: "{app}"

[Files]
Source: "{#SourceDir}\Service\*"; DestDir: "{app}\Service"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#SourceDir}\UI\*"; DestDir: "{app}\UI"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#SourceDir}\browser-extension\*"; DestDir: "{app}\browser-extension"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#SourceDir}\LICENSE"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\THIRD_PARTY_NOTICES.md"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{commonprograms}\FragGuard"; Filename: "{app}\UI\FragGuard.exe"; WorkingDir: "{app}\UI"; Comment: "{cm:TrayComment}"
Name: "{commondesktop}\FragGuard"; Filename: "{app}\UI\FragGuard.exe"; WorkingDir: "{app}\UI"; Comment: "{cm:TrayComment}"; Tasks: desktopicon

[Registry]
; La interfaz arranca en la bandeja al iniciar sesión (todos los usuarios).
Root: HKLM; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "FragGuard"; ValueData: """{app}\UI\FragGuard.exe"" --tray"; Flags: uninsdeletevalue

[Run]
; Se abre como el usuario normal (sin elevar), aunque el instalador sea de administrador.
Filename: "{app}\UI\FragGuard.exe"; Description: "{cm:LaunchProgram,FragGuard}"; Flags: postinstall nowait skipifsilent runasoriginaluser

[Code]
const
  ServiceName = 'FragGuardService';
  ServiceDisplayName = 'FragGuard Protection Service';
  ServiceDescription = 'Antivirus ligero para gamers: protección en tiempo real, cuarentena y modo juego.';

function RunHidden(const FileName, Params: String): Integer;
var
  Code: Integer;
begin
  if not Exec(FileName, Params, '', SW_HIDE, ewWaitUntilTerminated, Code) then
    Code := -1;
  Log(Format('%s %s -> %d', [FileName, Params, Code]));
  Result := Code;
end;

function Sys(const Exe: String): String;
begin
  Result := ExpandConstant('{sys}\') + Exe;
end;

function ServiceProcessRunning(): Boolean;
begin
  Result := RunHidden(Sys('cmd.exe'), '/c tasklist /FI "IMAGENAME eq FragGuard.Service.exe" /NH | find /I "FragGuard.Service.exe" >nul') = 0;
end;

{ Cierra la interfaz de todos los usuarios y detiene el servicio, esperando a que su proceso salga:
  "detenido" no garantiza que el proceso haya terminado y sus DLL seguirían bloqueadas. }
procedure StopFragGuard();
var
  i: Integer;
begin
  RunHidden(Sys('taskkill.exe'), '/F /IM FragGuard.exe');
  RunHidden(Sys('net.exe'), 'stop ' + ServiceName);
  for i := 1 to 30 do
  begin
    if not ServiceProcessRunning() then
      Exit;
    Sleep(500);
  end;
  RunHidden(Sys('taskkill.exe'), '/F /IM FragGuard.Service.exe');
  Sleep(1000);
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  StopFragGuard();
  Result := '';
end;

procedure InstallService();
var
  Exe, BinPath: String;
  Code: Integer;
begin
  Exe := ExpandConstant('{app}\Service\FragGuard.Service.exe');
  BinPath := 'binPath= "\"' + Exe + '\""';
  { Si ya existía (actualización), "create" falla y "config" deja la configuración al día. }
  RunHidden(Sys('sc.exe'), 'create ' + ServiceName + ' ' + BinPath + ' start= delayed-auto DisplayName= "' + ServiceDisplayName + '"');
  RunHidden(Sys('sc.exe'), 'config ' + ServiceName + ' ' + BinPath + ' start= delayed-auto DisplayName= "' + ServiceDisplayName + '"');
  RunHidden(Sys('sc.exe'), 'description ' + ServiceName + ' "' + ServiceDescription + '"');
  RunHidden(Sys('sc.exe'), 'failure ' + ServiceName + ' reset= 86400 actions= restart/5000/restart/10000/restart/60000');
  Code := RunHidden(Sys('net.exe'), 'start ' + ServiceName);
  if (Code <> 0) and not WizardSilent then
    MsgBox(FmtMessage(CustomMessage('ServiceStartFailed'), [IntToStr(Code), ExpandConstant('{commonappdata}\FragGuard\logs')]), mbError, MB_OK);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
    InstallService();
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  DataDir: String;
begin
  if CurUninstallStep = usUninstall then
  begin
    StopFragGuard();
    { Deshace los cambios en el sistema: señuelos, auditoría de cuentas y DNS protegido. }
    RunHidden(ExpandConstant('{app}\Service\FragGuard.Service.exe'), '--uninstall-cleanup');
    RunHidden(Sys('sc.exe'), 'delete ' + ServiceName);
  end;

  if CurUninstallStep = usPostUninstall then
  begin
    DataDir := ExpandConstant('{commonappdata}\FragGuard');
    if DirExists(DataDir) and not UninstallSilent then
      if MsgBox(CustomMessage('PurgeData'), mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES then
        DelTree(DataDir, True, True, True);
  end;
end;
