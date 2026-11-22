namespace FragGuard.Shared.Models;

/// <summary>Gravedad de una amenaza. Las reglas YARA la declaran en su bloque meta (severity = "...").</summary>
public enum ThreatSeverity
{
    Low = 0,
    Medium = 1,
    High = 2,
    Critical = 3
}

/// <summary>Origen de la detección.</summary>
public enum DetectionSource
{
    Yara = 0,
    VirusTotal = 1,
    Heuristic = 2,
    /// <summary>Reputación externa: MalwareBazaar (hash) o URLhaus (URL de descarga).</summary>
    Reputation = 3,
    /// <summary>Regla de comportamiento (proceso en ejecución, línea de comandos, ransomware...).</summary>
    Behavior = 4
}

/// <summary>Veredicto final sobre un archivo.</summary>
public enum FileVerdict
{
    Clean = 0,
    /// <summary>Sospechoso: se avisa al usuario pero NO se pone en cuarentena automáticamente.</summary>
    Suspicious = 1,
    /// <summary>Malicioso: se pone en cuarentena automáticamente (si está activado).</summary>
    Malicious = 2,
    /// <summary>No analizado (bloqueado, demasiado grande, excluido...). Ver <see cref="SkipReason"/>.</summary>
    Skipped = 3,
    Error = 4
}

/// <summary>Motivo por el que un archivo no se analizó.</summary>
public enum SkipReason
{
    None = 0,
    NotFound = 1,
    TooLarge = 2,
    Locked = 3,
    AccessDenied = 4,
    Excluded = 5,
    Encrypted = 6,
    Unsupported = 7
}

/// <summary>Tipo de escaneo.</summary>
public enum ScanKind
{
    Quick = 0,
    Full = 1,
    Custom = 2,
    Realtime = 3,
    Scheduled = 4
}

/// <summary>Estado de un escaneo.</summary>
public enum ScanState
{
    Idle = 0,
    Running = 1,
    Paused = 2,
    Completed = 3,
    Cancelled = 4,
    Failed = 5
}

/// <summary>Acción tomada ante una detección.</summary>
public enum ThreatAction
{
    None = 0,
    Quarantined = 1,
    QuarantineFailed = 2,
    /// <summary>El original estaba en uso: se cifró una copia y se programó su borrado al reiniciar.</summary>
    QuarantinePendingReboot = 3,
    Warned = 4
}
