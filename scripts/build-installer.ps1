<#
.SYNOPSIS
    Genera el instalador de FragGuard: artifacts\installer\FragGuard-Setup-<versión>.exe

.DESCRIPTION
    1. Publica el servicio y la interfaz AUTOCONTENIDOS (incluyen .NET: el usuario no tiene que instalar nada).
    2. Firma los binarios propios si hay certificado (comercial, de desarrollo o ninguno con -NoSign).
    3. Compila installer\FragGuard.iss con Inno Setup 6 y firma también el instalador.

    No necesita permisos de administrador.

.PARAMETER Version
    Versión del instalador. Por defecto, la de Directory.Build.props.

.EXAMPLE
    .\scripts\build-installer.ps1
    .\scripts\build-installer.ps1 -NoSign
    .\scripts\build-installer.ps1 -CertificateThumbprint 0123ABCD...
#>
param(
    [string]$Version,
    [string]$CertificateThumbprint,
    [string]$PfxPath,
    [switch]$NoSign,
    [string]$Iscc
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path $PSScriptRoot -Parent
$package  = Join-Path $repoRoot 'artifacts\package'
$output   = Join-Path $repoRoot 'artifacts\installer'

if (-not $Version) {
    $Version = ([xml](Get-Content (Join-Path $repoRoot 'Directory.Build.props') -Raw)).Project.PropertyGroup.Version | Select-Object -First 1
}
Write-Host "==> FragGuard $Version" -ForegroundColor Cyan

# ---------------------------------------------------------------- Inno Setup
if (-not $Iscc) {
    $Iscc = @(
        (Get-Command iscc.exe -ErrorAction SilentlyContinue).Source,
        "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
        "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
        "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe"
    ) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
}
if (-not $Iscc) { throw 'No se encontró Inno Setup 6 (ISCC.exe). Instálalo con: winget install JRSoftware.InnoSetup' }

# ---------------------------------------------------------------- Firma
$signScript = Join-Path $PSScriptRoot 'sign.ps1'
$signArgs = @{}
if ($PfxPath) { $signArgs.PfxPath = $PfxPath; $signArgs.PfxPassword = Read-Host 'Contraseña del .pfx' -AsSecureString }
elseif ($CertificateThumbprint) { $signArgs.Thumbprint = $CertificateThumbprint }

$canSign = -not $NoSign
if ($canSign -and -not $PfxPath -and -not $CertificateThumbprint) {
    $dev = Get-ChildItem Cert:\CurrentUser\My, Cert:\LocalMachine\My -CodeSigningCert -ErrorAction SilentlyContinue |
        Where-Object { $_.Subject -eq 'CN=FragGuard Dev Code Signing, O=FragGuard (desarrollo)' -and $_.NotAfter -gt (Get-Date) -and $_.HasPrivateKey }
    if (-not $dev) {
        Write-Host 'AVISO: no hay certificado de firma; el instalador se generará SIN FIRMAR.' -ForegroundColor Yellow
        $canSign = $false
    } else {
        Write-Host 'AVISO: se firmará con el certificado de DESARROLLO (solo válido en este PC). No lo distribuyas así.' -ForegroundColor Yellow
    }
}
function Sign([string]$folder) { if ($script:canSign) { & $signScript -Path $folder @signArgs } }

# ---------------------------------------------------------------- Publicación
if (Test-Path $package) { Remove-Item $package -Recurse -Force }
foreach ($p in @(@{ Project = 'src\FragGuard.Service\FragGuard.Service.csproj'; Out = 'Service' },
                 @{ Project = 'src\FragGuard.UI\FragGuard.UI.csproj';           Out = 'UI' })) {
    $dest = Join-Path $package $p.Out
    Write-Host "==> Publicando $($p.Out) (autocontenido, win-x64)..." -ForegroundColor Cyan
    dotnet publish (Join-Path $repoRoot $p.Project) -c Release -r win-x64 --self-contained true -o $dest -nologo
    if ($LASTEXITCODE -ne 0) { throw "dotnet publish falló para $($p.Project)" }
    Sign $dest
}
Copy-Item (Join-Path $repoRoot 'browser-extension') (Join-Path $package 'browser-extension') -Recurse
Copy-Item (Join-Path $repoRoot 'LICENSE'), (Join-Path $repoRoot 'THIRD_PARTY_NOTICES.md') $package

# ---------------------------------------------------------------- Instalador
Write-Host '==> Compilando el instalador con Inno Setup...' -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path $output | Out-Null
& $Iscc /Q "/DAppVersion=$Version" "/DSourceDir=$package" "/DOutputDir=$output" (Join-Path $repoRoot 'installer\FragGuard.iss')
if ($LASTEXITCODE -ne 0) { throw "Inno Setup falló (código $LASTEXITCODE)" }
Sign $output

$setup = Get-Item (Join-Path $output "FragGuard-Setup-$Version.exe")
$hash  = (Get-FileHash $setup.FullName -Algorithm SHA256).Hash
"$hash  $($setup.Name)" | Set-Content (Join-Path $output "$($setup.Name).sha256") -Encoding ascii

Write-Host ''
Write-Host "Instalador: $($setup.FullName)" -ForegroundColor Green
Write-Host ("Tamaño    : {0:N1} MB" -f ($setup.Length / 1MB))
Write-Host "SHA-256   : $hash"
Write-Host "Firma     : $((Get-AuthenticodeSignature $setup.FullName).Status)"
