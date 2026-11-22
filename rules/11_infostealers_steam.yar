/*
    FragGuard - Infostealers que roban sesiones de Steam
    -----------------------------------------------------
    Robar los archivos "ssfn*" y la carpeta "config" (loginusers.vdf, config.vdf) permite a un atacante
    reutilizar la sesión de Steam y vaciar el inventario (skins de CS2, objetos de Dota 2...).

    IMPORTANTE: el propio cliente de Steam contiene estas cadenas. Por eso exigimos además
    un canal de exfiltración (webhook/Telegram/servicio de subida) que Steam nunca usaría.
*/

rule FG_Stealer_Steam_Session
{
    meta:
        description = "Infostealer que roba la sesión de Steam (ssfn / loginusers.vdf)"
        severity    = "high"
        category    = "Infostealer"
        author      = "FragGuard"

    strings:
        $ssfn       = "ssfn" ascii wide nocase
        $vdf_login  = "loginusers.vdf" ascii wide nocase
        $vdf_config = "config.vdf" ascii wide nocase
        $steam_reg  = "Software\\Valve\\Steam" ascii wide nocase
        $steam_dir  = "\\Steam\\config" ascii wide nocase

        $exfil_webhook  = /discord(app)?\.com\/api\/webhooks\// ascii wide nocase
        $exfil_telegram = "api.telegram.org/bot" ascii wide nocase
        $exfil_upload1  = "gofile.io" ascii wide nocase
        $exfil_upload2  = "anonfiles" ascii wide nocase
        $exfil_upload3  = "transfer.sh" ascii wide nocase

    condition:
        $ssfn and 1 of ($vdf_*) and 1 of ($steam_*) and
        1 of ($exfil_*)
}
