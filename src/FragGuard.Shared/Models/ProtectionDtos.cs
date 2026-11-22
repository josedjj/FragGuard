namespace FragGuard.Shared.Models;

/// <summary>Un programa que se inicia automáticamente con Windows.</summary>
public sealed class AutorunEntryDto
{
    /// <summary>Identificador estable (hash de tipo + ubicación + nombre).</summary>
    public string Id { get; set; } = "";
    /// <summary>"Registro", "Carpeta Inicio", "Tarea programada" o "Servicio".</summary>
    public string Kind { get; set; } = "";
    /// <summary>Dónde está registrado (clave del registro, carpeta o ruta de la tarea).</summary>
    public string Location { get; set; } = "";
    public string Name { get; set; } = "";
    public string Command { get; set; } = "";
    public string? ImagePath { get; set; }
    public string? Publisher { get; set; }
    public bool IsSigned { get; set; }
    /// <summary>De confianza: binario de Windows o firmado por un editor de confianza.</summary>
    public bool IsTrusted { get; set; }
    public bool IsMicrosoft { get; set; }
    public bool FileExists { get; set; }
    public bool Enabled { get; set; } = true;
    /// <summary>Desactivado por FragGuard (se puede restaurar).</summary>
    public bool DisabledByFragGuard { get; set; }
    public bool CanDisable { get; set; }
    /// <summary>Sin firma y en una carpeta de usuario (AppData, Temp...): merece revisión.</summary>
    public bool IsSuspicious { get; set; }
}

/// <summary>Uso de cámara o micrófono registrado por Windows (CapabilityAccessManager).</summary>
public sealed class DeviceUsageDto
{
    /// <summary>"Cámara" o "Micrófono".</summary>
    public string Device { get; set; } = "";
    public string App { get; set; } = "";
    public string? Path { get; set; }
    public bool IsStoreApp { get; set; }
    public DateTime? LastStartUtc { get; set; }
    public DateTime? LastStopUtc { get; set; }
    public bool InUse { get; set; }
    public string? Publisher { get; set; }
    public bool IsTrusted { get; set; }
}

/// <summary>Estado de los módulos de protección en ejecución (para la página "Protección").</summary>
public sealed class ProtectionStatusDto
{
    public bool ProcessMonitorActive { get; set; }
    public bool RansomwareShieldActive { get; set; }
    public int RansomwareCanaries { get; set; }
    public bool AccountProtectionActive { get; set; }
    /// <summary>Qué se protege: "Discord", "Discord PTB", "Steam"...</summary>
    public List<string> AccountProtectionTargets { get; set; } = new();
    public string? AccountProtectionError { get; set; }
    public bool PrivacyMonitorActive { get; set; }
    public bool PersistenceMonitorActive { get; set; }
    public int AutorunCount { get; set; }
    public int DefenderExclusionCount { get; set; }
    public bool RemovableDrivesActive { get; set; }
    public List<string> RemovableDrives { get; set; } = new();
    /// <summary>Resultado de la comprobación de integridad de los propios binarios de FragGuard.</summary>
    public string SelfIntegrity { get; set; } = "";
    public bool SelfIntegrityOk { get; set; } = true;
}
