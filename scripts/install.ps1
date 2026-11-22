#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Compila, publica e instala FragGuard (servicio + interfaz).

.DESCRIPTION
    Servicio (FragGuard.Service):
      - Se publica en Release (win-x64) y se copia a %ProgramFiles%\FragGuard\Service.
      - Se registra como LocalSystem con inicio automático RETRASADO (no compite con el arranque de Windows).
      - Recuperación: se reinicia solo si se cae.
    Interfaz (FragGuard.exe):
      - Se copia a %ProgramFiles%\FragGuard\UI.
      - Acceso directo en el menú Inicio para todos los usuarios.
      - Arranque automático en la bandeja al iniciar sesión (clave Run de HKLM).

    Ejecutar desde una consola de PowerShell abierta "como administrador".

.PARAMETER SelfContained
    Incluye el runtime de .NET (no requiere tener .NET 8 Desktop Runtime instalado; ocupa más en disco).

.PARAMETER SkipUI
    Instala solo el servicio.

.PARAMETER CertificateThumbprint
    Huella del certificado de firma de código a usar. Si no se indica, se usa el de desarrollo
    (new-dev-certificate.ps1) si existe. Sin certificado, se instala sin firmar (con aviso).

.PARAMETER PfxPath
    Certificado comercial en .pfx (se pedirá la contraseña).

.PARAMETER NoSign
    No firmar los binarios.

.EXAMPLE
    .\scripts\install.ps1
    .\scripts\install.ps1 -SelfContained
#>
param(
    [string]$InstallRoot = (Join-Path $env:ProgramFiles 'FragGuard'),
    [switch]$SelfContained,
    [switch]$SkipUI,
    [string]$CertificateThumbprint,
    [string]$PfxPath,
    [switch]$NoSign
)

$ErrorActionPreference = 'Stop'
$ServiceName = 'FragGuardService'
$DisplayName = 'FragGuard Protection Service'
$Description = 'Antivirus ligero para gamers: protección en tiempo real, cuarentena y modo juego.'

$repoRoot   = Split-Path $PSScriptRoot -Parent
$serviceDir = Join-Path $InstallRoot 'Service'
$uiDir      = Join-Path $InstallRoot 'UI'
$sc         = if ($SelfContained) { 'true' } else { 'false' }

function Publish([string]$project, [string]$output) {
    Write-Host "==> Publicando $(Split-Path $project -Leaf) (Release, win-x64)..." -ForegroundColor Cyan
    # Carpeta limpia: así no se cuela ningún binario viejo (sin firmar) de una publicación anterior.
    if (Test-Path $output) { Remove-Item $output -Recurse -Force }
    dotnet publish (Join-Path $repoRoot $project) -c Release -r win-x64 --self-contained $sc -o $output -nologo
    if ($LASTEXITCODE -ne 0) { throw "dotnet publish falló para $project" }
    Sign $output
}

# ---------------------------------------------------------------- Firma
$signArgs = @{}
if ($PfxPath) { $signArgs.PfxPath = $PfxPath; $signArgs.PfxPassword = Read-Host 'Contraseña del .pfx' -AsSecureString }
elseif ($CertificateThumbprint) { $signArgs.Thumbprint = $CertificateThumbprint }

$signScript = Join-Path $PSScriptRoot 'sign.ps1'
$canSign = -not $NoSign
if ($canSign -and -not $PfxPath -and -not $CertificateThumbprint) {
    # ¿Hay certificado de desarrollo?
    $dev = Get-ChildItem Cert:\CurrentUser\My, Cert:\LocalMachine\My -CodeSigningCert -ErrorAction SilentlyContinue |
        Where-Object { $_.Subject -eq 'CN=FragGuard Dev Code Signing, O=FragGuard (desarrollo)' -and $_.NotAfter -gt (Get-Date) -and $_.HasPrivateKey }
    if (-not $dev) {
        Write-Host 'AVISO: no hay certificado de firma; se instalará SIN FIRMAR. Crea uno con .\scripts\new-dev-certificate.ps1' -ForegroundColor Yellow
        $canSign = $false
    }
}

function Sign([string]$folder) {
    if ($script:canSign) { & $signScript -Path $folder @signArgs }
}

# ---------------------------------------------------------------- Servicio
$servicePublish = Join-Path $repoRoot 'artifacts\service'
Publish 'src\FragGuard.Service\FragGuard.Service.csproj' $servicePublish

$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing -and $existing.Status -ne 'Stopped') {
    Write-Host '==> Deteniendo el servicio existente...' -ForegroundColor Cyan
    Stop-Service -Name $ServiceName -Force
    (Get-Service $ServiceName).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
}

Write-Host "==> Copiando el servicio a $serviceDir..." -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path $serviceDir | Out-Null
Copy-Item -Path (Join-Path $servicePublish '*') -Destination $serviceDir -Recurse -Force

$serviceExe = Join-Path $serviceDir 'FragGuard.Service.exe'
if (-not $existing) {
    Write-Host '==> Registrando el servicio...' -ForegroundColor Cyan
    New-Service -Name $ServiceName -BinaryPathName "`"$serviceExe`"" -DisplayName $DisplayName `
        -Description $Description -StartupType Automatic | Out-Null
}
sc.exe config $ServiceName start= delayed-auto | Out-Null
sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/10000/restart/60000 | Out-Null

Write-Host '==> Iniciando el servicio...' -ForegroundColor Cyan
Start-Service -Name $ServiceName
(Get-Service $ServiceName).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))

# ---------------------------------------------------------------- Interfaz
if (-not $SkipUI) {
    Get-Process FragGuard -ErrorAction SilentlyContinue | Stop-Process -Force

    $uiPublish = Join-Path $repoRoot 'artifacts\ui'
    Publish 'src\FragGuard.UI\FragGuard.UI.csproj' $uiPublish

    Write-Host "==> Copiando la interfaz a $uiDir..." -ForegroundColor Cyan
    New-Item -ItemType Directory -Force -Path $uiDir | Out-Null
    Copy-Item -Path (Join-Path $uiPublish '*') -Destination $uiDir -Recurse -Force
    $uiExe = Join-Path $uiDir 'FragGuard.exe'

    # Acceso directo en el menú Inicio (todos los usuarios)
    $shortcutPath = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\FragGuard.lnk'
    $shell = New-Object -ComObject WScript.Shell
    $lnk = $shell.CreateShortcut($shortcutPath)
    $lnk.TargetPath = $uiExe
    $lnk.WorkingDirectory = $uiDir
    $lnk.IconLocation = "$uiExe,0"
    $lnk.Description = 'FragGuard - antivirus ligero para gamers'
    $lnk.Save()

    # Arranque en la bandeja al iniciar sesión (todos los usuarios)
    New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name 'FragGuard' `
        -Value "`"$uiExe`" --tray" -PropertyType String -Force | Out-Null

    Write-Host '==> Abriendo FragGuard...' -ForegroundColor Cyan
    # Se abre SIN elevar (como el usuario normal), aunque este script sea de administrador.
    Start-Process explorer.exe -ArgumentList "`"$uiExe`""
}

Write-Host ''
Write-Host 'FragGuard instalado y en ejecución.' -ForegroundColor Green
Write-Host "  Servicio : $serviceDir"
if (-not $SkipUI) { Write-Host "  Interfaz : $uiDir (menú Inicio → FragGuard)" }
Write-Host "  Datos    : $env:ProgramData\FragGuard (base de datos, cuarentena)"
Write-Host "  Logs     : $env:ProgramData\FragGuard\logs\service-*.log  y  %LOCALAPPDATA%\FragGuard\logs\ui-*.log"
