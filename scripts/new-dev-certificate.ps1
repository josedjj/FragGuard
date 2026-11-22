#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Crea (o elimina) un certificado de firma de código AUTOFIRMADO para firmar FragGuard en ESTE equipo.

.DESCRIPTION
    Sirve para desarrollo y uso personal: Windows confiará en las firmas solo en este PC,
    porque el certificado se añade como raíz de confianza y editor de confianza del equipo.
    Para distribuir FragGuard a otras personas hace falta un certificado de firma de código comercial
    (OV/EV); el script sign.ps1 funciona igual con él.

    Seguridad:
      - La clave privada se crea NO EXPORTABLE y se guarda en el almacén del usuario actual.
      - El certificado solo sirve para firmar código (no para TLS ni otros usos).
      - Usa -Remove para quitarlo de todos los almacenes cuando ya no lo necesites.

.EXAMPLE
    .\scripts\new-dev-certificate.ps1
    .\scripts\new-dev-certificate.ps1 -Remove
#>
param(
    [switch]$Remove,
    [int]$ValidYears = 3
)

$ErrorActionPreference = 'Stop'
$Subject = 'CN=FragGuard Dev Code Signing, O=FragGuard (desarrollo)'

function Find-DevCerts {
    Get-ChildItem Cert:\CurrentUser\My, Cert:\LocalMachine\Root, Cert:\LocalMachine\TrustedPublisher -ErrorAction SilentlyContinue |
        Where-Object { $_.Subject -eq $Subject }
}

if ($Remove) {
    $certs = Find-DevCerts
    if (-not $certs) { Write-Host 'No hay certificados de desarrollo de FragGuard.' -ForegroundColor Yellow; return }
    foreach ($c in $certs) {
        Write-Host "==> Eliminando $($c.Thumbprint) de $($c.PSParentPath -replace '^.*::','')" -ForegroundColor Cyan
        Remove-Item $c.PSPath -DeleteKey -ErrorAction SilentlyContinue
        if (Test-Path $c.PSPath) { Remove-Item $c.PSPath }
    }
    Write-Host 'Certificado de desarrollo eliminado. Las firmas existentes dejarán de ser de confianza en este equipo.' -ForegroundColor Green
    return
}

$existing = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Subject -eq $Subject -and $_.NotAfter -gt (Get-Date) -and $_.HasPrivateKey }
if ($existing) {
    $cert = $existing | Sort-Object NotAfter -Descending | Select-Object -First 1
    Write-Host "Ya existe un certificado de desarrollo válido: $($cert.Thumbprint) (caduca $($cert.NotAfter.ToString('dd/MM/yyyy')))" -ForegroundColor Yellow
}
else {
    Write-Host '==> Creando certificado de firma de código autofirmado...' -ForegroundColor Cyan
    $cert = New-SelfSignedCertificate `
        -Type CodeSigningCert `
        -Subject $Subject `
        -CertStoreLocation Cert:\CurrentUser\My `
        -KeyAlgorithm RSA -KeyLength 3072 `
        -HashAlgorithm SHA256 `
        -KeyExportPolicy NonExportable `
        -NotAfter (Get-Date).AddYears($ValidYears)
}

# Confianza en este equipo: raíz de confianza (para que la cadena sea válida)
# y editores de confianza (para que Windows no pregunte por el editor).
$tmp = Join-Path $env:TEMP "fragguard-dev-cert-$([guid]::NewGuid().ToString('N')).cer"
try {
    Export-Certificate -Cert $cert -FilePath $tmp | Out-Null   # solo la parte PÚBLICA
    foreach ($store in 'Cert:\LocalMachine\Root', 'Cert:\LocalMachine\TrustedPublisher') {
        if (-not (Get-ChildItem $store | Where-Object Thumbprint -eq $cert.Thumbprint)) {
            Import-Certificate -FilePath $tmp -CertStoreLocation $store | Out-Null
            Write-Host "==> Añadido a $store" -ForegroundColor Cyan
        }
    }
}
finally {
    Remove-Item $tmp -ErrorAction SilentlyContinue
}

Write-Host ''
Write-Host 'Certificado de desarrollo listo.' -ForegroundColor Green
Write-Host "  Huella   : $($cert.Thumbprint)"
Write-Host "  Caduca   : $($cert.NotAfter.ToString('dd/MM/yyyy'))"
Write-Host '  Ahora: .\scripts\install.ps1   (firma los binarios automáticamente)'
