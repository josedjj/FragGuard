/*
    FragGuard - "Cheats" falsos y droppers
    ---------------------------------------
    Un patrón muy común: un .bat/.ps1/.exe que se presenta como cheat o "free skins" y que:
      1) Añade una exclusión a Windows Defender ("para que el cheat no dé falso positivo").
      2) Descarga y ejecuta el malware real (normalmente un infostealer).
*/

rule FG_Dropper_DefenderExclusion_Download
{
    meta:
        description = "Script que desactiva/excluye Windows Defender y descarga otro ejecutable"
        severity    = "high"
        category    = "Dropper"
        author      = "FragGuard"

    strings:
        $excl1 = "Add-MpPreference" ascii wide nocase
        $excl2 = "-ExclusionPath" ascii wide nocase
        $excl3 = "Set-MpPreference -DisableRealtimeMonitoring" ascii wide nocase

        $dl1 = "Invoke-WebRequest" ascii wide nocase
        $dl2 = "DownloadFile" ascii wide nocase
        $dl3 = "DownloadString" ascii wide nocase
        $dl4 = "Start-BitsTransfer" ascii wide nocase
        $dl5 = "curl.exe" ascii wide nocase
        $dl6 = "iwr " ascii wide nocase

        $run1 = "Start-Process" ascii wide nocase
        $run2 = "Invoke-Expression" ascii wide nocase
        $run3 = "iex" fullword ascii wide nocase

    condition:
        (($excl1 and $excl2) or $excl3) and
        1 of ($dl*) and
        1 of ($run*)
}

rule FG_Suspicious_HiddenPowerShell_Cradle
{
    meta:
        description = "PowerShell oculto que descarga y ejecuta código en memoria (técnica típica de droppers)"
        severity    = "medium"
        category    = "Dropper"
        author      = "FragGuard"

    strings:
        $ps     = "powershell" ascii wide nocase
        $hidden = /-w(indowstyle)?\s+hidden/ ascii wide nocase
        $bypass = /-ep\s+bypass|-executionpolicy\s+bypass/ ascii wide nocase
        $enc    = /-e(nc|ncodedcommand)?\s+[A-Za-z0-9+\/=]{40,}/ ascii wide nocase
        $net    = "Net.WebClient" ascii wide nocase

    condition:
        $ps and $hidden and ($bypass or $enc) and ($net or $enc)
}
