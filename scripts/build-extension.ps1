<#
.SYNOPSIS
    Genera las reglas de la extensión FragGuard Anti-Phishing a partir de una lista pública de dominios de estafas.

.DESCRIPTION
    Fuente: nikolaischunk/discord-phishing-links (licencia MIT), ~22.000 dominios de Discord Nitro falso,
    phishing de Steam y similares. Se valida cada dominio, se excluyen los dominios legítimos por seguridad y
    se agrupan en reglas declarativeNetRequest de 1.000 dominios (bloqueo en el propio navegador).

    También copia los iconos de FragGuard al tamaño que exige la extensión.

.EXAMPLE
    .\scripts\build-extension.ps1
#>
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path $PSScriptRoot -Parent
$ext = Join-Path $repoRoot 'browser-extension'
$source = 'https://raw.githubusercontent.com/nikolaischunk/discord-phishing-links/main/domain-list.json'

# Dominios que NUNCA deben bloquearse aunque aparezcan por error en una lista externa.
$neverBlock = @(
    'discord.com','discord.gg','discordapp.com','discordapp.net','discord.media','discord.new','discord.gift','discordstatus.com',
    'steampowered.com','steamcommunity.com','steamstatic.com','steamcontent.com','valvesoftware.com','steam-chat.com',
    'epicgames.com','riotgames.com','leagueoflegends.com','playvalorant.com','battle.net','blizzard.com','ea.com',
    'ubisoft.com','rockstargames.com','twitch.tv','youtube.com','google.com','github.com','microsoft.com','xbox.com',
    'roblox.com','minecraft.net','faceit.com','csgo.com','counter-strike.net','dota2.com'
)

Write-Host "==> Descargando lista de dominios (MIT): $source" -ForegroundColor Cyan
$json = Invoke-RestMethod -Uri $source -TimeoutSec 60
$raw = @($json.domains)
$valid = $raw |
    ForEach-Object { $_.ToString().Trim().ToLowerInvariant().TrimEnd('.') } |
    Where-Object { $_ -match '^(?=.{4,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$' } |
    Where-Object { $d = $_; -not ($neverBlock | Where-Object { $d -eq $_ -or $d.EndsWith('.' + $_) }) } |
    Sort-Object -Unique
Write-Host "    $($raw.Count) dominios en la lista, $($valid.Count) válidos tras filtrar." -ForegroundColor Gray

# Reglas declarativeNetRequest: una regla por cada bloque de 1.000 dominios.
$rules = New-Object System.Collections.Generic.List[object]
$id = 1
for ($i = 0; $i -lt $valid.Count; $i += 1000) {
    $chunk = $valid[$i..([Math]::Min($i + 999, $valid.Count - 1))]
    $rules.Add([ordered]@{
        id = $id++
        priority = 1
        action = @{ type = 'block' }
        condition = [ordered]@{
            requestDomains = @($chunk)
            resourceTypes = @('main_frame','sub_frame','xmlhttprequest','script','image','media','websocket','other')
        }
    })
}

$rulesDir = Join-Path $ext 'rules'
New-Item -ItemType Directory -Force $rulesDir | Out-Null
$utf8 = New-Object System.Text.UTF8Encoding($false)
[IO.File]::WriteAllText((Join-Path $rulesDir 'gamer_scams.json'), ($rules | ConvertTo-Json -Depth 6 -Compress), $utf8)
[IO.File]::WriteAllText((Join-Path $rulesDir 'stats.json'), (@{ domains = $valid.Count; source = $source; generatedUtc = (Get-Date).ToUniversalTime().ToString('o') } | ConvertTo-Json -Compress), $utf8)
Write-Host "==> $($rules.Count) reglas generadas en browser-extension\rules\gamer_scams.json" -ForegroundColor Green

# Iconos
Add-Type -AssemblyName System.Drawing
$iconsDir = Join-Path $ext 'icons'
New-Item -ItemType Directory -Force $iconsDir | Out-Null
$src = [System.Drawing.Image]::FromFile((Join-Path $repoRoot 'src\FragGuard.UI\Assets\fragguard.png'))
foreach ($size in 16, 48, 128) {
    $bmp = New-Object System.Drawing.Bitmap($size, $size)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.InterpolationMode = 'HighQualityBicubic'; $g.SmoothingMode = 'AntiAlias'
    $g.DrawImage($src, 0, 0, $size, $size); $g.Dispose()
    $bmp.Save((Join-Path $iconsDir "icon$size.png"), [System.Drawing.Imaging.ImageFormat]::Png); $bmp.Dispose()
}
$src.Dispose()
Write-Host "==> Iconos generados." -ForegroundColor Green
Write-Host ""
Write-Host "Para instalarla: chrome://extensions (o edge://extensions) → Modo desarrollador → Cargar descomprimida → carpeta browser-extension"
