#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Desinstala FragGuard (servicio + interfaz).

.PARAMETER PurgeData
    Borra también %ProgramData%\FragGuard (historial, configuración, logs y ¡la CUARENTENA!).
    Sin este parámetro los datos se conservan para una futura reinstalación.

.EXAMPLE
    .\scripts\uninstall.ps1
    .\scripts\uninstall.ps1 -PurgeData
#>
param(
    [string]$InstallRoot = (Join-Path $env:ProgramFiles 'FragGuard'),
    [switch]$PurgeData
)

$ErrorActionPreference = 'Stop'
$ServiceName = 'FragGuardService'

# Interfaz: cerrar, quitar arranque automático y acceso directo
Get-Process FragGuard -ErrorAction SilentlyContinue | Stop-Process -Force
Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name 'FragGuard' -ErrorAction SilentlyContinue
Remove-Item (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\FragGuard.lnk') -ErrorAction SilentlyContinue

# Servicio
$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($service) {
    if ($service.Status -ne 'Stopped') {
        Write-Host '==> Deteniendo el servicio...' -ForegroundColor Cyan
        Stop-Service -Name $ServiceName -Force
        (Get-Service $ServiceName).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    }
    Write-Host '==> Eliminando el servicio...' -ForegroundColor Cyan
    sc.exe delete $ServiceName | Out-Null
} else {
    Write-Host 'El servicio no estaba instalado.' -ForegroundColor Yellow
}

if (Test-Path $InstallRoot) {
    Write-Host "==> Borrando $InstallRoot..." -ForegroundColor Cyan
    Remove-Item -Recurse -Force $InstallRoot
}

$dataDir = Join-Path $env:ProgramData 'FragGuard'
if ($PurgeData -and (Test-Path $dataDir)) {
    Write-Host "==> Borrando datos en $dataDir (incluida la cuarentena)..." -ForegroundColor Cyan
    Remove-Item -Recurse -Force $dataDir
} elseif (Test-Path $dataDir) {
    Write-Host "Datos conservados en $dataDir (usa -PurgeData para borrarlos)." -ForegroundColor Yellow
}

Write-Host 'FragGuard desinstalado.' -ForegroundColor Green
