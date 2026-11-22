namespace FragGuard.Core.Configuration;

/// <summary>
/// Límites técnicos del motor (no editables desde la UI en el MVP).
/// Pensados para mantener bajo el consumo de RAM y evitar zip-bombs.
/// </summary>
public sealed class EngineOptions
{
    /// <summary>
    /// Archivos hasta este tamaño se leen UNA vez a un buffer del pool: se calcula el hash y YARA analiza
    /// la memoria sin volver a tocar el disco. Los mayores se procesan por streaming / mapeo de YARA.
    /// </summary>
    public int InMemoryScanMaxBytes { get; set; } = 16 * 1024 * 1024;

    // ---------- Comprimidos (anti zip-bomb) ----------
    public int ArchiveMaxEntries { get; set; } = 2000;
    public long ArchiveMaxEntryBytes { get; set; } = 32L * 1024 * 1024;
    public long ArchiveMaxTotalBytes { get; set; } = 256L * 1024 * 1024;
    /// <summary>Profundidad máxima de comprimidos anidados (zip dentro de zip...).</summary>
    public int ArchiveMaxDepth { get; set; } = 2;

    // ---------- Caché ----------
    /// <summary>Validez de un veredicto cacheado por hash.</summary>
    public TimeSpan HashCacheTtl { get; set; } = TimeSpan.FromDays(7);

    // ---------- Archivos bloqueados ----------
    public int LockedRetryCount { get; set; } = 3;
    public TimeSpan LockedRetryDelay { get; set; } = TimeSpan.FromMilliseconds(400);

    // ---------- Seguridad ----------
    /// <summary>
    /// Restringir con ACL la carpeta de datos/cuarentena a SYSTEM + Administradores.
    /// El servicio lo activa; los tests lo desactivan (si no, el usuario de test perdería el acceso).
    /// </summary>
    public bool HardenDataDirectoryAcl { get; set; } = true;

    // ---------- Escaneo ----------
    /// <summary>Hilos de análisis en escaneos manuales (fuera del modo juego).</summary>
    public int MaxScanParallelism { get; set; } = Math.Clamp(Environment.ProcessorCount / 2, 1, 4);

    /// <summary>
    /// Extensiones analizadas en escaneos rápido/completo/programado (en el personalizado se analiza todo).
    /// Limitarlo a tipos ejecutables/script/comprimidos reduce muchísimo la E/S sin perder cobertura real.
    /// </summary>
    public HashSet<string> InterestingExtensions { get; } = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".sys", ".scr", ".com", ".cpl", ".ocx", ".msi", ".msp",
        ".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".lnk", ".jar",
        ".zip", ".rar", ".7z",
        ".docm", ".xlsm", ".pptm", ".iso", ".img"
    };

    /// <summary>Comprimidos que se abren para analizar su contenido.</summary>
    public HashSet<string> ArchiveExtensions { get; } = new(StringComparer.OrdinalIgnoreCase)
    {
        ".zip", ".rar", ".7z"
    };

    /// <summary>Tipos para los que merece la pena gastar cuota de VirusTotal.</summary>
    public HashSet<string> VirusTotalExtensions { get; } = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".scr", ".com", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".hta",
        ".zip", ".rar", ".7z"
    };
}
