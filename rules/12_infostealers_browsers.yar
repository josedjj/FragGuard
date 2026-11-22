/*
    FragGuard - Robo de contraseñas y cookies de navegadores
    ---------------------------------------------------------
    Los stealers copian las bases de datos SQLite "Login Data" y "Cookies" de los navegadores Chromium,
    descifran la clave de "Local State" (encrypted_key) y roban sesiones (incluidas las de Steam, Epic,
    Riot o Discord abiertas en el navegador).

    Un navegador legítimo contiene la ruta de SU perfil, pero no las de muchos navegadores distintos a la vez.
*/

rule FG_Stealer_Browser_Credentials
{
    meta:
        description = "Infostealer que roba contraseñas y cookies de varios navegadores"
        severity    = "high"
        category    = "Infostealer"
        author      = "FragGuard"

    strings:
        // Perfiles de navegador (Opera GX es muy popular entre gamers)
        $b_chrome  = "\\Google\\Chrome\\User Data" ascii wide nocase
        $b_edge    = "\\Microsoft\\Edge\\User Data" ascii wide nocase
        $b_brave   = "\\BraveSoftware\\Brave-Browser\\User Data" ascii wide nocase
        $b_operagx = "\\Opera Software\\Opera GX Stable" ascii wide nocase
        $b_opera   = "\\Opera Software\\Opera Stable" ascii wide nocase
        $b_firefox = "\\Mozilla\\Firefox\\Profiles" ascii wide nocase
        $b_yandex  = "\\Yandex\\YandexBrowser\\User Data" ascii wide nocase

        // Archivos sensibles dentro del perfil
        $f_logins  = "Login Data" ascii wide
        $f_cookies = "Network\\Cookies" ascii wide nocase
        $f_state   = "Local State" ascii wide
        $f_key     = "encrypted_key" ascii wide
        $f_ff      = "logins.json" ascii wide

        // Consultas SQL típicas para volcar credenciales y cookies
        $sql_logins  = "SELECT origin_url, username_value, password_value FROM logins" ascii wide nocase
        $sql_cookies = "SELECT host_key, name, encrypted_value" ascii wide nocase

        $exfil_webhook  = /discord(app)?\.com\/api\/webhooks\// ascii wide nocase
        $exfil_telegram = "api.telegram.org/bot" ascii wide nocase

    condition:
        filesize < 50MB and
        3 of ($b_*) and
        3 of ($f_*) and
        (1 of ($sql_*) or 1 of ($exfil_*))
}

rule FG_Stealer_Gamer_MultiTarget
{
    meta:
        description = "Stealer orientado a gamers: Discord + Steam + navegadores + exfiltración en el mismo binario"
        severity    = "critical"
        category    = "Infostealer"
        author      = "FragGuard"

    strings:
        $discord = "Local Storage\\leveldb" ascii wide nocase
        $steam   = "loginusers.vdf" ascii wide nocase
        $browser = "Login Data" ascii wide
        $epic    = "\\EpicGamesLauncher\\Saved\\Config" ascii wide nocase
        $riot    = "\\Riot Games\\Riot Client\\Data" ascii wide nocase
        $mc      = "\\.minecraft\\launcher_accounts.json" ascii wide nocase
        $exfil1  = /discord(app)?\.com\/api\/webhooks\// ascii wide nocase
        $exfil2  = "api.telegram.org/bot" ascii wide nocase

    condition:
        filesize < 50MB and
        4 of ($discord, $steam, $browser, $epic, $riot, $mc) and
        1 of ($exfil*)
}
