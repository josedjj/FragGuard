namespace FragGuard.Shared.Models;

// DTOs que viajan por el named pipe entre el servicio y la UI.
// Son clases simples (propiedades con set) para que System.Text.Json con source generators las serialice sin reflexión.

/// <summary>Una amenaza concreta encontrada en un archivo.</summary>
public sealed class ThreatInfo
{
    public string Name { get; set; } = "";
    public string Description { get; set; } = "";
    /// <summary>Categoría libre: "Infostealer", "CheatLure", "Dropper", "Test"...</summary>
    public string Category { get; set; } = "";
    public ThreatSeverity Severity { get; set; }
    public DetectionSource Source { get; set; }
}

/// <summary>Detección registrada (evento en tiempo real o entrada del historial).</summary>
public sealed class DetectionDto
{
    public long Id { get; set; }
    public string? ScanId { get; set; }
    public ScanKind ScanKind { get; set; }
    public string FilePath { get; set; } = "";
    public string? Sha256 { get; set; }
    public FileVerdict Verdict { get; set; }
    public ThreatAction Action { get; set; }
    public List<ThreatInfo> Threats { get; set; } = new();
    public string? QuarantineId { get; set; }
    public DateTime DetectedUtc { get; set; }

    /// <summary>Origen de la descarga según Mark-of-the-Web (Zone.Identifier), si existe.</summary>
    public string? SourceUrl { get; set; }

    /// <summary>Editor que firmó el archivo (Authenticode), si está firmado y la firma es válida.</summary>
    public string? Signer { get; set; }

    /// <summary>Nombre de la amenaza principal (la de mayor gravedad).</summary>
    public string PrimaryThreatName =>
        Threats.OrderByDescending(t => t.Severity).FirstOrDefault()?.Name ?? "Desconocida";
}

/// <summary>Petición de escaneo manual.</summary>
public sealed class ScanRequest
{
    public ScanKind Kind { get; set; }
    /// <summary>Solo para <see cref="ScanKind.Custom"/>: carpeta o archivo elegido por el usuario.</summary>
    public string? CustomPath { get; set; }
}

/// <summary>Progreso de un escaneo en curso.</summary>
public sealed class ScanProgressDto
{
    public string ScanId { get; set; } = "";
    public ScanKind Kind { get; set; }
    public ScanState State { get; set; }
    public long FilesScanned { get; set; }
    public long FilesSkipped { get; set; }
    public long ThreatsFound { get; set; }
    public string? CurrentFile { get; set; }
    public DateTime StartedUtc { get; set; }
    public long ElapsedMs { get; set; }
}

/// <summary>Resumen de un escaneo terminado.</summary>
public sealed class ScanSummaryDto
{
    public string ScanId { get; set; } = "";
    public ScanKind Kind { get; set; }
    public ScanState State { get; set; }
    public DateTime StartedUtc { get; set; }
    public DateTime? FinishedUtc { get; set; }
    public long FilesScanned { get; set; }
    public long FilesSkipped { get; set; }
    public long ThreatsFound { get; set; }
    public long Errors { get; set; }
}

/// <summary>Elemento en cuarentena.</summary>
public sealed class QuarantineItemDto
{
    public string Id { get; set; } = "";
    public string OriginalPath { get; set; } = "";
    public string Sha256 { get; set; } = "";
    public string ThreatName { get; set; } = "";
    public long SizeBytes { get; set; }
    public DateTime QuarantinedUtc { get; set; }
    /// <summary>True si el original no se pudo borrar y se eliminará al reiniciar.</summary>
    public bool PendingReboot { get; set; }
}

/// <summary>Estado general mostrado en el panel principal.</summary>
public sealed class StatusDto
{
    public string ServiceVersion { get; set; } = AppInfo.Version;
    public bool RealtimeEnabled { get; set; }
    public bool RealtimeHealthy { get; set; }
    public int WatchedFolderCount { get; set; }
    public bool GameModeActive { get; set; }
    public string? GameModeReason { get; set; }
    public bool VirusTotalConfigured { get; set; }
    public bool AbuseChConfigured { get; set; }
    public int YaraRuleCount { get; set; }
    /// <summary>Versión de las reglas descargadas del canal firmado (0 = solo las de serie).</summary>
    public long RulesUpdateVersion { get; set; }
    public string? RulesUpdateStatus { get; set; }
    public ScanSummaryDto? LastScan { get; set; }
    public ScanProgressDto? ActiveScan { get; set; }
    public long ThreatsBlockedTotal { get; set; }
    public int QuarantineCount { get; set; }
    /// <summary>Memoria privada del servicio en MB.</summary>
    public double ServiceRamMb { get; set; }
    /// <summary>CPU del servicio (% del total de la máquina, promedio de los últimos segundos).</summary>
    public double ServiceCpuPercent { get; set; }
    public DateTime ServiceStartedUtc { get; set; }
}

/// <summary>Aviso de archivo/proceso con nombre típico de cheat, trainer o "free skins".</summary>
public sealed class CheatWarningDto
{
    public string Path { get; set; } = "";
    public string Reason { get; set; } = "";
    /// <summary>"File" si apareció en disco, "Process" si se está ejecutando.</summary>
    public string Origin { get; set; } = "File";
    public int? ProcessId { get; set; }
    public DateTime DetectedUtc { get; set; }
}

/// <summary>Cambio en el estado del modo juego.</summary>
public sealed class GameModeDto
{
    public bool Active { get; set; }
    public string? Reason { get; set; }
}
