<#
.SYNOPSIS
    Firma con Authenticode los binarios PROPIOS de FragGuard en una carpeta publicada.

.DESCRIPTION
    Solo firma nuestros archivos (FragGuard*.exe / FragGuard*.dll). No toca los de terceros:
    los de Microsoft ya vienen firmados y libyara/SQLite no son nuestros.

    Elección del certificado (en este orden):
      1. -PfxPath (+ -PfxPassword): certificado comercial exportado a .pfx.
      2. -Thumbprint: certificado instalado en CurrentUser\My o LocalMachine\My.
      3. Automático: el certificado de desarrollo creado con new-dev-certificate.ps1.

    Por defecto añade un SELLO DE TIEMPO (timestamp): la firma sigue siendo válida aunque
    el certificado caduque después. Para ello se envía el HASH de cada archivo (no el archivo)
    al servidor de sellado indicado. Usa -NoTimestamp para firmar sin conexión.

.EXAMPLE
    .\scripts\sign.ps1 -Path .\artifacts\service
    .\scripts\sign.ps1 -Path .\artifacts\ui -Thumbprint 0123ABCD...
    .\scripts\sign.ps1 -Path .\artifacts\ui -PfxPath C:\certs\fragguard.pfx
#>
param(
    [Parameter(Mandatory)] [string]$Path,
    [string]$Thumbprint,
    [string]$PfxPath,
    [securestring]$PfxPassword,
    [string]$TimestampServer = 'http://timestamp.digicert.com',
    [switch]$NoTimestamp
)

$ErrorActionPreference = 'Stop'
$DevSubject = 'CN=FragGuard Dev Code Signing, O=FragGuard (desarrollo)'

function Get-SigningCertificate {
    if ($PfxPath) {
        $flags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet
        $plain = if ($PfxPassword) { [System.Net.NetworkCredential]::new('', $PfxPassword).Password } else { $null }
        return [System.Security.Cryptography.X509Certificates.X509Certificate2]::new((Resolve-Path $PfxPath), $plain, $flags)
    }
    $stores = 'Cert:\CurrentUser\My', 'Cert:\LocalMachine\My'
    if ($Thumbprint) {
        $c = Get-ChildItem $stores -CodeSigningCert | Where-Object Thumbprint -eq ($Thumbprint -replace '\s', '') | Select-Object -First 1
        if (-not $c) { throw "No se encontró un certificado de firma de código con la huella $Thumbprint." }
        return $c
    }
    return Get-ChildItem $stores -CodeSigningCert |
        Where-Object { $_.Subject -eq $DevSubject -and $_.NotAfter -gt (Get-Date) -and $_.HasPrivateKey } |
        Sort-Object NotAfter -Descending | Select-Object -First 1
}

$cert = Get-SigningCertificate
if (-not $cert) {
    throw 'No hay certificado de firma. Crea uno de desarrollo con .\scripts\new-dev-certificate.ps1 o indica -Thumbprint / -PfxPath.'
}

$files = Get-ChildItem -Path $Path -File | Where-Object { $_.Name -like 'FragGuard*.exe' -or $_.Name -like 'FragGuard*.dll' }
if (-not $files) { throw "No hay binarios de FragGuard en $Path" }

Write-Host "==> Firmando $($files.Count) archivo(s) con: $($cert.Subject) [$($cert.Thumbprint)]" -ForegroundColor Cyan
$failed = @()
foreach ($f in $files) {
    $params = @{ FilePath = $f.FullName; Certificate = $cert; HashAlgorithm = 'SHA256' }
    if (-not $NoTimestamp) { $params.TimestampServer = $TimestampServer }

    $sig = Set-AuthenticodeSignature @params
    if ($sig.Status -ne 'Valid') {
        # El sellado de tiempo necesita Internet: si falla, reintentamos sin él en lugar de dejar el archivo sin firmar.
        if (-not $NoTimestamp) {
            Write-Host "    $($f.Name): sin sello de tiempo ($($sig.StatusMessage)); reintentando sin él" -ForegroundColor Yellow
            $params.Remove('TimestampServer')
            $sig = Set-AuthenticodeSignature @params
        }
    }
    $status = (Get-AuthenticodeSignature $f.FullName).Status
    $color = if ($status -eq 'Valid') { 'Green' } else { 'Red' }
    Write-Host ("    {0,-32} {1}" -f $f.Name, $status) -ForegroundColor $color
    if ($status -ne 'Valid') { $failed += $f.Name }
}

if ($failed) { throw "No se pudieron firmar: $($failed -join ', ')" }
Write-Host '==> Firma completada.' -ForegroundColor Green
