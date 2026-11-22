/*
    FragGuard - Infostealers que roban tokens de Discord
    -----------------------------------------------------
    Los "token grabbers" leen la base de datos LevelDB de Discord (Local Storage\leveldb),
    extraen el token de sesión (en claro o cifrado con el prefijo "dQw4w9WgXcQ:") y lo envían
    a un webhook de Discord o a un bot de Telegram. Con ese token el atacante entra en la cuenta sin contraseña ni 2FA.

    Limitación: muchos stealers van empaquetados (PyInstaller, ofuscadores .NET). En ese caso las cadenas
    no son visibles en el binario y estas reglas no los detectarán; para eso está la consulta a VirusTotal.
*/

rule FG_Stealer_Discord_TokenGrabber
{
    meta:
        description = "Infostealer que roba tokens de sesión de Discord"
        severity    = "high"
        category    = "Infostealer"
        author      = "FragGuard"

    strings:
        // Rutas de las distintas versiones del cliente de Discord
        $path1 = "\\discord\\Local Storage\\leveldb" ascii wide nocase
        $path2 = "\\discordcanary\\Local Storage\\leveldb" ascii wide nocase
        $path3 = "\\discordptb\\Local Storage\\leveldb" ascii wide nocase
        $path4 = "\\Lightcord\\Local Storage\\leveldb" ascii wide nocase

        // Indicadores de extracción del token
        $tok_enc   = "dQw4w9WgXcQ:" ascii wide                                // prefijo de los tokens cifrados
        $tok_regex = /[MNO][A-Za-z0-9_-]{23,25}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,38}/ ascii wide
        $api_me    = "discord.com/api/v9/users/@me" ascii wide nocase           // validación del token robado

        // Canales de exfiltración típicos
        $exfil_webhook  = /discord(app)?\.com\/api\/webhooks\/[0-9]{5,}/ ascii wide nocase
        $exfil_telegram = "api.telegram.org/bot" ascii wide nocase

    condition:
        filesize < 50MB and
        1 of ($path*) and
        1 of ($tok_*, $api_me) and
        1 of ($exfil_*)
}

rule FG_Stealer_Discord_Injection
{
    meta:
        description = "Modifica el cliente de Discord (index.js) para robar credenciales en cada inicio de sesión"
        severity    = "critical"
        category    = "Infostealer"
        author      = "FragGuard"

    strings:
        $core   = "discord_desktop_core" ascii wide nocase
        $index  = "index.js" ascii wide
        $hook1  = "webContents.debugger" ascii wide
        $hook2  = "onBeforeRequest" ascii wide
        $hook3  = "onCompleted" ascii wide
        $target1 = "/auth/login" ascii wide
        $target2 = "/users/@me" ascii wide
        $target3 = "/billing" ascii wide

    condition:
        filesize < 20MB and $core and $index and 2 of ($hook*) and 2 of ($target*)
}
