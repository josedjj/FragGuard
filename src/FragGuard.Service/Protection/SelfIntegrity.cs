using FragGuard.Core.Security;

namespace FragGuard.Service.Protection;

/// <summary>
/// Autoprotección básica (sin drivers): al arrancar comprueba la firma Authenticode de los binarios de FragGuard.
///  - Firma válida → íntegros.
///  - Firma presente pero INVÁLIDA → alguien ha modificado FragGuard después de firmarlo (alerta crítica).
///  - Sin firma → versión de desarrollo (aviso informativo).
/// Los binarios viven en Program Files y los datos en ProgramData con ACL de administradores: un usuario
/// normal (o malware sin privilegios) no puede tocarlos; esta comprobación cubre el resto de casos.
/// </summary>
public sealed class SelfIntegrity
{
    private readonly ILogger<SelfIntegrity> _logger;

    public SelfIntegrity(ILogger<SelfIntegrity> logger) => _logger = logger;

    public bool Ok { get; private set; } = true;
    public string Summary { get; private set; } = "Sin comprobar";

    public void Check()
    {
        var files = Directory.EnumerateFiles(AppContext.BaseDirectory, "FragGuard*.*")
            .Where(f => f.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) || f.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
            .ToList();

        var results = files.Select(f => (File: Path.GetFileName(f), Sig: Authenticode.Verify(f))).ToList();
        var tampered = results.Where(r => r.Sig.IsSigned && !r.Sig.IsValid).Select(r => r.File).ToList();

        if (tampered.Count > 0)
        {
            Ok = false;
            Summary = "¡Binarios modificados después de firmarse!: " + string.Join(", ", tampered);
            _logger.LogCritical("INTEGRIDAD: {Summary}", Summary);
        }
        else if (results.Count > 0 && results.All(r => r.Sig.IsValid))
        {
            Ok = true;
            Summary = $"Binarios firmados e íntegros ({results[0].Sig.Publisher})";
            _logger.LogInformation("Integridad: {Summary}", Summary);
        }
        else
        {
            Ok = true;
            Summary = "Binarios sin firma digital (versión de desarrollo)";
            _logger.LogInformation("Integridad: {Summary}", Summary);
        }
    }
}

/// <summary>Estado agregado de los módulos de protección para la UI.</summary>
public sealed class ProtectionStatusProvider
{
    private readonly ProcessMonitorService _processes;
    private readonly RansomwareShield _ransomware;
    private readonly AccountProtectionService _accounts;
    private readonly PrivacyMonitorService _privacy;
    private readonly PersistenceMonitorService _persistence;
    private readonly RemovableDriveService _removable;
    private readonly SelfIntegrity _integrity;
    private readonly Core.Configuration.SettingsStore _settings;

    public ProtectionStatusProvider(ProcessMonitorService processes, RansomwareShield ransomware, AccountProtectionService accounts,
        PrivacyMonitorService privacy, PersistenceMonitorService persistence, RemovableDriveService removable, SelfIntegrity integrity,
        Core.Configuration.SettingsStore settings)
    {
        _processes = processes;
        _ransomware = ransomware;
        _accounts = accounts;
        _privacy = privacy;
        _persistence = persistence;
        _removable = removable;
        _integrity = integrity;
        _settings = settings;
    }

    public Shared.Models.ProtectionStatusDto Get() => new()
    {
        ProcessMonitorActive = _settings.Current.ProcessMonitorEnabled,
        RansomwareShieldActive = _ransomware.IsArmed,
        RansomwareCanaries = _ransomware.CanaryCount,
        AccountProtectionActive = _accounts.IsActive,
        AccountProtectionTargets = _accounts.TargetLabels,
        AccountProtectionError = _accounts.LastError,
        PrivacyMonitorActive = _privacy.IsActive,
        PersistenceMonitorActive = _persistence.IsActive,
        AutorunCount = _persistence.AutorunCount,
        DefenderExclusionCount = _persistence.DefenderExclusionCount,
        RemovableDrivesActive = _removable.IsActive,
        RemovableDrives = _removable.CurrentDrives.ToList(),
        SelfIntegrity = _integrity.Summary,
        SelfIntegrityOk = _integrity.Ok
    };
}
