using FragGuard.Shared;

namespace FragGuard.Core.Configuration;

/// <summary>
/// Rutas de datos del motor. Por defecto cuelgan de %ProgramData%\FragGuard,
/// pero los tests pueden usar una carpeta temporal.
/// </summary>
public sealed class FragGuardPaths
{
    public FragGuardPaths(string? dataRoot = null, string? rulesDirectory = null)
    {
        DataRoot = Path.GetFullPath(dataRoot ?? AppInfo.DefaultDataRoot);
        // Las reglas viajan junto al ejecutable (carpeta "rules") salvo que se indique otra.
        RulesDirectory = Path.GetFullPath(rulesDirectory ?? Path.Combine(AppContext.BaseDirectory, "rules"));
    }

    public string DataRoot { get; }
    public string RulesDirectory { get; }

    public string DatabasePath => Path.Combine(DataRoot, "fragguard.db");
    public string SettingsPath => Path.Combine(DataRoot, "settings.json");
    public string QuarantineDirectory => Path.Combine(DataRoot, "quarantine");
    public string QuarantineKeyPath => Path.Combine(DataRoot, "quarantine.key");
    public string VirusTotalKeyPath => Path.Combine(DataRoot, "vt.key");
    public string AbuseChKeyPath => Path.Combine(DataRoot, "abusech.key");

    /// <summary>Reglas YARA descargadas del canal firmado (se suman a las que vienen con el programa).</summary>
    public string UpdatedRulesDirectory => Path.Combine(DataRoot, "rules-updates");

    /// <summary>Copias de seguridad de entradas de inicio desactivadas por el usuario (para poder restaurarlas).</summary>
    public string DisabledAutorunsDirectory => Path.Combine(DataRoot, "disabled-autoruns");
    public string LogsDirectory => Path.Combine(DataRoot, "logs");

    public void EnsureCreated()
    {
        Directory.CreateDirectory(DataRoot);
        Directory.CreateDirectory(QuarantineDirectory);
        Directory.CreateDirectory(LogsDirectory);
    }
}
