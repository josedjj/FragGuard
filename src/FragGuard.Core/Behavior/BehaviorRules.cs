using System.Text.RegularExpressions;
using FragGuard.Shared.Models;

namespace FragGuard.Core.Behavior;

/// <summary>Lo que el servicio sabe de un proceso recién iniciado (todo obtenido en modo usuario, sin inyección).</summary>
public sealed record ProcessFacts(
    uint Pid,
    string Name,
    string? ImagePath,
    string? CommandLine,
    uint ParentPid,
    string? ParentName,
    string? ParentPath,
    bool ParentTrusted);

public enum BehaviorResponse
{
    /// <summary>Solo avisar.</summary>
    Alert,
    /// <summary>Detener el proceso.</summary>
    KillProcess,
    /// <summary>Detener el proceso Y a su padre (quien lo lanzó: típicamente el ransomware o el dropper).</summary>
    KillProcessAndParent
}

public sealed record BehaviorMatch(string RuleId, string Title, string Description, ThreatSeverity Severity, BehaviorResponse Response)
{
    public ThreatInfo ToThreat() => new()
    {
        Name = RuleId,
        Category = "Comportamiento",
        Severity = Severity,
        Source = DetectionSource.Behavior,
        Description = Description
    };
}

/// <summary>
/// Reglas de comportamiento sobre la línea de comandos de cada proceso nuevo.
/// Detectan lo que hace el malware AL EJECUTARSE, aunque el archivo no esté en ninguna base de firmas:
///  - Ransomware: borrar instantáneas de volumen, catálogos de copia y la recuperación de arranque.
///  - Desactivar defensas: exclusiones o apagado de Windows Defender (lo hacen muchos "cheats" falsos).
///  - Descargas con herramientas del sistema (LOLBins): certutil, bitsadmin, mshta, regsvr32...
///  - PowerShell oculto y codificado.
///  - Persistencia sospechosa: tareas programadas que lanzan algo desde carpetas temporales.
///
/// Política de respuesta: si quien lanza el comando es un programa de confianza (firmado por Microsoft,
/// un fabricante de backup reconocido...), solo se avisa; si es un desconocido, se detiene.
/// </summary>
public static class BehaviorRules
{
    private const RegexOptions Opt = RegexOptions.IgnoreCase | RegexOptions.CultureInvariant;

    private static readonly Regex ShadowDelete = new(@"\b(delete\s+shadows|resize\s+shadowstorage)\b", Opt);
    private static readonly Regex WmicShadow = new(@"shadowcopy\s+delete|win32_shadowcopy.*\.delete\(|win32_shadowcopy.*delete", Opt);
    private static readonly Regex WbadminDelete = new(@"\bdelete\s+(catalog|systemstatebackup|backup)\b", Opt);
    private static readonly Regex BcdeditRecovery = new(@"recoveryenabled\s+(no|off|false)|bootstatuspolicy\s+ignoreallfailures", Opt);

    private static readonly Regex DefenderExclusion = new(@"(Add|Set)-MpPreference.*-Exclusion(Path|Process|Extension|IpAddress)", Opt);
    private static readonly Regex DefenderDisable = new(@"Set-MpPreference.*-(DisableRealtimeMonitoring|DisableBehaviorMonitoring|DisableIOAVProtection|DisableScriptScanning)\s+(\$true|1)", Opt);
    private static readonly Regex DefenderRegistry = new(@"reg(\.exe)?\s+add\s+.*Windows Defender\\(Exclusions|Real-Time Protection)", Opt);

    private static readonly Regex PsEncoded = new(@"\s-e(nc|ncodedcommand|ncodedcomman|ncodedcomma|ncodedcomm|ncodedcom|ncodedco|ncodedc|ncoded|ncode|ncod|nco)?\s+[A-Za-z0-9+/=]{20,}", Opt);
    private static readonly Regex PsHidden = new(@"\s-w(indowstyle|indowstyl|indowsty|indowst|indows|indow|indo|ind|in|i)?\s+(hidden|1)\b", Opt);
    private static readonly Regex PsDownload = new(@"(DownloadString|DownloadFile|DownloadData|Invoke-WebRequest|\biwr\b|Invoke-RestMethod|\birm\b|Net\.WebClient|Start-BitsTransfer)", Opt);
    private static readonly Regex PsExec = new(@"(Invoke-Expression|\biex\b|\|\s*iex|Start-Process)", Opt);

    private static readonly Regex CertutilDownload = new(@"-urlcache.*\b(https?|ftp)://|-decode\b", Opt);
    private static readonly Regex BitsadminDownload = new(@"/transfer\b.*(https?)://", Opt);
    private static readonly Regex MshtaRemote = new(@"(https?://|javascript:|vbscript:)", Opt);
    private static readonly Regex Regsvr32Remote = new(@"/i:\s*(https?)://|scrobj\.dll", Opt);
    private static readonly Regex Rundll32Script = new(@"javascript:|mshtml,RunHTMLApplication", Opt);

    private static readonly Regex SchtasksUserPath = new(@"/create\b.*(\\AppData\\|\\Temp\\|\\Downloads\\|%temp%|%appdata%|\\Users\\Public\\)", Opt);

    public static List<BehaviorMatch> Evaluate(ProcessFacts p)
    {
        var matches = new List<BehaviorMatch>();
        string cmd = p.CommandLine ?? "";
        if (cmd.Length == 0)
            return matches;
        string name = p.Name.ToLowerInvariant();

        // Si el padre es de confianza (Microsoft, fabricante de backup firmado...) solo se avisa.
        BehaviorResponse Strong(BehaviorResponse r) => p.ParentTrusted ? BehaviorResponse.Alert : r;

        // ---------------- Ransomware: destrucción de copias de seguridad ----------------
        if ((name == "vssadmin.exe" && ShadowDelete.IsMatch(cmd)) ||
            (name is "wmic.exe" or "powershell.exe" or "pwsh.exe" && WmicShadow.IsMatch(cmd)))
        {
            matches.Add(new("FG.Behavior.ShadowCopyDelete", "Borrado de copias de seguridad de Windows",
                $"{p.ParentName ?? "Un programa"} intentó borrar las instantáneas de volumen (copias de seguridad de Windows). Es el paso previo típico del ransomware.",
                ThreatSeverity.Critical, Strong(BehaviorResponse.KillProcessAndParent)));
        }
        if (name == "wbadmin.exe" && WbadminDelete.IsMatch(cmd))
        {
            matches.Add(new("FG.Behavior.BackupCatalogDelete", "Borrado del catálogo de copias",
                "Se intentó borrar el catálogo de copias de seguridad de Windows (técnica de ransomware).",
                ThreatSeverity.Critical, Strong(BehaviorResponse.KillProcessAndParent)));
        }
        if (name == "bcdedit.exe" && BcdeditRecovery.IsMatch(cmd))
        {
            matches.Add(new("FG.Behavior.RecoveryDisabled", "Desactivación de la recuperación de Windows",
                "Se intentó desactivar la recuperación de arranque de Windows (técnica de ransomware).",
                ThreatSeverity.Critical, Strong(BehaviorResponse.KillProcessAndParent)));
        }

        // ---------------- Desactivar Windows Defender ----------------
        bool isShell = name is "powershell.exe" or "pwsh.exe" or "cmd.exe" or "reg.exe";
        if (isShell && (DefenderExclusion.IsMatch(cmd) || DefenderRegistry.IsMatch(cmd)))
        {
            matches.Add(new("FG.Behavior.DefenderExclusion", "Exclusión añadida a Windows Defender",
                "Un programa intentó excluir archivos de Windows Defender. Muchos \"cheats\" y \"free skins\" falsos lo hacen para que no se detecte el malware que instalan.",
                ThreatSeverity.High, Strong(BehaviorResponse.KillProcessAndParent)));
        }
        if (isShell && DefenderDisable.IsMatch(cmd))
        {
            matches.Add(new("FG.Behavior.DefenderDisabled", "Intento de desactivar Windows Defender",
                "Un programa intentó apagar la protección en tiempo real de Windows Defender.",
                ThreatSeverity.High, Strong(BehaviorResponse.KillProcessAndParent)));
        }

        // ---------------- PowerShell oculto / codificado ----------------
        if (name is "powershell.exe" or "pwsh.exe")
        {
            bool encoded = PsEncoded.IsMatch(cmd);
            bool hidden = PsHidden.IsMatch(cmd);
            bool downloadExec = PsDownload.IsMatch(cmd) && PsExec.IsMatch(cmd);
            if ((encoded && hidden) || (hidden && downloadExec))
            {
                matches.Add(new("FG.Behavior.HiddenPowerShell", "PowerShell oculto que descarga o ejecuta código",
                    "Se lanzó PowerShell en una ventana oculta con un comando codificado o que descarga y ejecuta código: es la técnica habitual de los droppers.",
                    ThreatSeverity.High, Strong(BehaviorResponse.KillProcess)));
            }
        }

        // ---------------- LOLBins: herramientas del sistema usadas para descargar o ejecutar ----------------
        if ((name == "certutil.exe" && CertutilDownload.IsMatch(cmd)) ||
            (name == "bitsadmin.exe" && BitsadminDownload.IsMatch(cmd)) ||
            (name == "mshta.exe" && MshtaRemote.IsMatch(cmd)) ||
            (name == "regsvr32.exe" && Regsvr32Remote.IsMatch(cmd)) ||
            (name == "rundll32.exe" && Rundll32Script.IsMatch(cmd)))
        {
            matches.Add(new("FG.Behavior.LolbinDownload", "Herramienta del sistema usada para descargar o ejecutar código",
                $"{p.Name} se usó de una forma propia del malware (descarga o ejecución remota de scripts).",
                ThreatSeverity.High, Strong(BehaviorResponse.KillProcess)));
        }

        // ---------------- Persistencia sospechosa ----------------
        if (name == "schtasks.exe" && SchtasksUserPath.IsMatch(cmd))
        {
            matches.Add(new("FG.Behavior.SuspiciousScheduledTask", "Tarea programada desde una carpeta temporal",
                "Se creó una tarea programada que ejecuta un programa desde AppData, Temp o Descargas: técnica habitual de persistencia de malware.",
                ThreatSeverity.Medium, BehaviorResponse.Alert));
        }

        return matches;
    }
}
