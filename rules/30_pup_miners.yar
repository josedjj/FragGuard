/*
    FragGuard - Programas potencialmente no deseados (PUP) y criptomineros
    ---------------------------------------------------------------------
    Categorías:
      "PUP"   : bundlers y adware. Solo se AVISA (severity low); el usuario puede desactivar esta categoría.
      "Miner" : criptomineros. Muy habituales en juegos crackeados, "cheats" y "optimizadores de FPS" falsos:
                usan tu GPU para minar y te bajan los FPS. Se avisa (medium); si además se oculta, es malicioso (high).

    Todas exigen un ejecutable PE (uint16(0) == 0x5A4D) para no saltar con documentos o páginas web.
    Los archivos firmados por editores de confianza nunca se marcan como PUP/Miner (lo hace el motor).
*/

rule FG_PUP_Bundler_InstallCore
{
    meta:
        description = "Instalador con bundler InstallCore/ironSource: instala programas extra no pedidos"
        severity    = "low"
        category    = "PUP"
        author      = "FragGuard"
    strings:
        $a = "InstallCore" ascii wide nocase
        $b = "ironSource" ascii wide nocase
        $c = "ICLoader" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and filesize < 30MB and 2 of them
}

rule FG_PUP_Bundler_OpenCandy
{
    meta:
        description = "Instalador con OpenCandy: ofrece software adicional durante la instalación"
        severity    = "low"
        category    = "PUP"
        author      = "FragGuard"
    strings:
        $a = "OpenCandy" ascii wide nocase
        $b = "OCSetupHlp" ascii wide nocase
        $c = "api.opencandy.com" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and filesize < 30MB and any of them
}

rule FG_PUP_BrowserHijacker
{
    meta:
        description = "Modifica la página de inicio o el buscador de los navegadores sin pedir permiso"
        severity    = "low"
        category    = "PUP"
        author      = "FragGuard"
    strings:
        $chrome_prefs = "\\Google\\Chrome\\User Data\\Default\\Secure Preferences" ascii wide nocase
        $edge_prefs   = "\\Microsoft\\Edge\\User Data\\Default\\Secure Preferences" ascii wide nocase
        $k1 = "default_search_provider" ascii wide
        $k2 = "homepage_is_newtabpage" ascii wide
        $k3 = "startup_urls" ascii wide
        $silent = /\/(S|silent|verysilent)\b/ ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and filesize < 20MB and
        1 of ($chrome_prefs, $edge_prefs) and 2 of ($k*) and $silent
}

rule FG_Miner_XMRig
{
    meta:
        description = "Criptominero XMRig: usa tu CPU/GPU para minar Monero (te baja los FPS)"
        severity    = "medium"
        category    = "Miner"
        author      = "FragGuard"
    strings:
        $x1 = "xmrig" ascii wide nocase
        $x2 = "donate-level" ascii wide
        $x3 = "stratum+tcp://" ascii wide nocase
        $x4 = "stratum+ssl://" ascii wide nocase
        $x5 = "randomx" ascii wide nocase
        $x6 = "\"algo\":" ascii
    condition:
        uint16(0) == 0x5A4D and 3 of them
}

rule FG_Miner_Hidden
{
    meta:
        description = "Criptominero oculto: se esconde del Administrador de tareas y se lanza en silencio"
        severity    = "high"
        category    = "Miner"
        author      = "FragGuard"
    strings:
        $m1 = "stratum+tcp://" ascii wide nocase
        $m2 = "stratum+ssl://" ascii wide nocase
        $m3 = "pool.minexmr" ascii wide nocase
        $m4 = "nanopool.org" ascii wide nocase
        $m5 = "2miners.com" ascii wide nocase
        $m6 = "unmineable.com" ascii wide nocase
        // Técnicas de ocultación típicas de los mineros "silenciosos"
        $h1 = "Taskmgr.exe" ascii wide nocase
        $h2 = "ProcessHacker" ascii wide nocase
        $h3 = "procexp" ascii wide nocase
        $h4 = "--background" ascii wide
        $h5 = "schtasks /create" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and 1 of ($m*) and 2 of ($h*)
}
