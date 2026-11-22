using System.Diagnostics;
using System.Text.Json;
using FragGuard.Core.Configuration;
using FragGuard.Core.Persistence;
using FragGuard.Core.Scanning;
using FragGuard.Service.GameMode;
using FragGuard.Shared.Ipc;
using FragGuard.Shared.Models;
using Microsoft.Win32;

namespace FragGuard.Service.Protection;

/// <summary>
/// Vigilancia de persistencia:
///  - Cada minuto (5 en modo juego) compara el inventario de programas de inicio con el anterior. Lo NUEVO
///    que no es de confianza se analiza y se avisa (y si es malware, va a cuarentena).
///  - Vigila las exclusiones de Windows Defender: añadir una exclusión es lo primero que hacen muchos
///    "cheats" y "free skins" falsos para que Defender no vea lo que instalan.
/// El primer recorrido solo toma la "foto" inicial (no avisa de lo que ya existía).
/// </summary>
public sealed class PersistenceMonitorService : BackgroundService
{
    private const string DefenderExclusionsKey = @"SOFTWARE\Microsoft\Windows Defender\Exclusions";

    private readonly SettingsStore _settings;
    private readonly FileScanner _scanner;
    private readonly ThreatResponder _responder;
    private readonly GameModeService _gameMode;
    private readonly ILogger<PersistenceMonitorService> _logger;

    private HashSet<string>? _knownAutoruns;
    private HashSet<string>? _knownExclusions;

    public PersistenceMonitorService(SettingsStore settings, FileScanner scanner, ThreatResponder responder,
        GameModeService gameMode, ILogger<PersistenceMonitorService> logger)
    {
        _settings = settings;
        _scanner = scanner;
        _responder = responder;
        _gameMode = gameMode;
        _logger = logger;
    }

    public int AutorunCount { get; private set; }
    public int DefenderExclusionCount { get; private set; }
    public bool IsActive { get; private set; }

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        try { await Task.Delay(TimeSpan.FromSeconds(20), ct).ConfigureAwait(false); }
        catch (OperationCanceledException) { return; }

        while (!ct.IsCancellationRequested)
        {
            IsActive = _settings.Current.PersistenceMonitorEnabled;
            if (IsActive)
            {
                try
                {
                    await CheckAutorunsAsync(ct).ConfigureAwait(false);
                    CheckDefenderExclusions();
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
                catch (Exception ex) { _logger.LogWarning(ex, "Error vigilando la persistencia"); }
            }

            try { await Task.Delay(_gameMode.IsActive ? TimeSpan.FromMinutes(5) : TimeSpan.FromMinutes(1), ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { break; }
        }
    }

    private async Task CheckAutorunsAsync(CancellationToken ct)
    {
        // Sin servicios: cambian poco y son caros de recorrer cada minuto.
        var entries = AutorunInventory.Collect(includeServices: false);
        AutorunCount = entries.Count;
        var ids = entries.Select(e => e.Id).ToHashSet();

        if (_knownAutoruns is null)
        {
            _knownAutoruns = ids;
            return;
        }

        foreach (var e in entries.Where(e => !_knownAutoruns.Contains(e.Id) && !e.IsTrusted))
        {
            _logger.LogWarning("Nuevo programa de inicio no confiable: {Name} ({Kind}) → {Command}", e.Name, e.Kind, e.Command);

            // Si el ejecutable es malware, el escáner lo pone en cuarentena.
            if (e.FileExists && e.ImagePath is not null)
            {
                var result = await _scanner.ScanAsync(e.ImagePath, FileScanContext.Realtime, ct).ConfigureAwait(false);
                if (result.IsThreat)
                {
                    await _responder.HandleAsync(result, null, ScanKind.Realtime, ct).ConfigureAwait(false);
                    continue;
                }
            }

            _responder.Report(new DetectionDto
            {
                ScanKind = ScanKind.Realtime,
                FilePath = e.ImagePath ?? e.Command,
                Verdict = FileVerdict.Suspicious,
                Action = ThreatAction.Warned,
                DetectedUtc = DateTime.UtcNow,
                Threats = new List<ThreatInfo>
                {
                    new()
                    {
                        Name = "FG.Persistence.NewStartupEntry",
                        Category = "Persistencia",
                        Severity = e.IsSuspicious ? ThreatSeverity.Medium : ThreatSeverity.Low,
                        Source = DetectionSource.Behavior,
                        Description = $"Nuevo programa de inicio ({e.Kind}): \"{e.Name}\"{(e.IsSigned ? "" : ", sin firma digital")}. Si no lo has instalado tú, desactívalo en «Programas de inicio»."
                    }
                }
            });
        }
        _knownAutoruns = ids;
    }

    private void CheckDefenderExclusions()
    {
        var current = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            foreach (var kind in new[] { "Paths", "Processes", "Extensions", "IpAddresses" })
            {
                using var key = Registry.LocalMachine.OpenSubKey($@"{DefenderExclusionsKey}\{kind}");
                if (key is null) continue;
                foreach (var v in key.GetValueNames())
                    current.Add($"{kind}: {v}");
            }
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException)
        {
            return; // sin permiso (ejecución sin SYSTEM)
        }

        DefenderExclusionCount = current.Count;
        if (_knownExclusions is null)
        {
            _knownExclusions = current;
            return;
        }

        foreach (var added in current.Where(c => !_knownExclusions.Contains(c)))
        {
            _logger.LogWarning("Nueva exclusión de Windows Defender: {Exclusion}", added);
            _responder.Report(new DetectionDto
            {
                ScanKind = ScanKind.Realtime,
                FilePath = added,
                Verdict = FileVerdict.Suspicious,
                Action = ThreatAction.Warned,
                DetectedUtc = DateTime.UtcNow,
                Threats = new List<ThreatInfo>
                {
                    new()
                    {
                        Name = "FG.Tamper.DefenderExclusion",
                        Category = "Manipulación",
                        Severity = ThreatSeverity.High,
                        Source = DetectionSource.Behavior,
                        Description = $"Se añadió una exclusión a Windows Defender ({added}). Si no la has puesto tú, quítala en Seguridad de Windows → Exclusiones: el malware lo hace para esconderse."
                    }
                }
            });
        }
        _knownExclusions = current;
    }
}

/// <summary>
/// Desactiva y restaura programas de inicio SIN perder información: antes de quitar nada guarda una copia
/// en %ProgramData%\FragGuard\disabled-autoruns. Los servicios no se tocan (podría romper Windows).
/// Lo invoca el pipe solo para administradores elevados.
/// </summary>
public sealed class AutorunManager
{
    private readonly FragGuardPaths _paths;
    private readonly ILogger<AutorunManager> _logger;

    public AutorunManager(FragGuardPaths paths, ILogger<AutorunManager> logger)
    {
        _paths = paths;
        _logger = logger;
    }

    private sealed class Backup
    {
        public string Kind { get; set; } = "";
        public string Name { get; set; } = "";
        public string Location { get; set; } = "";
        public string Command { get; set; } = "";
        public string? RegistryRoot { get; set; }
        public string? RegistrySubKey { get; set; }
        public string? OriginalFile { get; set; }
        public string? TaskName { get; set; }
    }

    private string BackupPath(string id) => Path.Combine(_paths.DisabledAutorunsDirectory, id + ".json");

    /// <summary>Inventario + entradas desactivadas por FragGuard (para poder restaurarlas).</summary>
    public List<AutorunEntryDto> List()
    {
        var entries = AutorunInventory.Collect(includeServices: true);
        var ids = entries.Select(e => e.Id).ToHashSet();
        if (Directory.Exists(_paths.DisabledAutorunsDirectory))
        {
            foreach (var file in Directory.EnumerateFiles(_paths.DisabledAutorunsDirectory, "*.json"))
            {
                try
                {
                    var b = JsonSerializer.Deserialize<Backup>(File.ReadAllText(file))!;
                    string id = Path.GetFileNameWithoutExtension(file);
                    var existing = entries.FirstOrDefault(e => e.Id == id);
                    if (existing is not null) { existing.DisabledByFragGuard = true; existing.Enabled = false; continue; }
                    entries.Add(new AutorunEntryDto
                    {
                        Id = id, Kind = b.Kind, Name = b.Name, Location = b.Location, Command = b.Command,
                        ImagePath = AutorunInventory.ResolveImage(b.Command), Enabled = false, DisabledByFragGuard = true, CanDisable = false
                    });
                }
                catch (Exception ex) when (ex is IOException or JsonException) { }
            }
        }
        return entries;
    }

    public OperationResult Disable(string id)
    {
        var entry = AutorunInventory.Collect(includeServices: false).FirstOrDefault(e => e.Id == id);
        if (entry is null)
            return OperationResult.Fail("No se encontró esa entrada de inicio.");
        if (!entry.CanDisable)
            return OperationResult.Fail("Este tipo de entrada no se puede desactivar desde FragGuard.");

        Directory.CreateDirectory(_paths.DisabledAutorunsDirectory);
        var backup = new Backup { Kind = entry.Kind, Name = entry.Name, Location = entry.Location, Command = entry.Command };

        try
        {
            switch (entry.Kind)
            {
                case AutorunInventory.KindRegistry:
                {
                    var loc = AutorunInventory.RunKeys().FirstOrDefault(l =>
                        AutorunInventory.DisplayLocation(l).Equals(entry.Location, StringComparison.OrdinalIgnoreCase));
                    if (loc is null)
                        return OperationResult.Fail("No se pudo localizar la clave del registro.");
                    backup.RegistryRoot = loc.Root == Registry.LocalMachine ? "HKLM" : "HKU";
                    backup.RegistrySubKey = loc.SubKey;
                    File.WriteAllText(BackupPath(id), JsonSerializer.Serialize(backup));
                    using var key = loc.Root.OpenSubKey(loc.SubKey, writable: true);
                    key?.DeleteValue(entry.Name, throwOnMissingValue: false);
                    break;
                }
                case AutorunInventory.KindStartupFolder:
                {
                    string original = Path.Combine(entry.Location, entry.Name);
                    backup.OriginalFile = original;
                    File.WriteAllText(BackupPath(id), JsonSerializer.Serialize(backup));
                    File.Move(original, Path.Combine(_paths.DisabledAutorunsDirectory, id + ".bin"), overwrite: true);
                    break;
                }
                case AutorunInventory.KindTask:
                {
                    backup.TaskName = entry.Location;
                    File.WriteAllText(BackupPath(id), JsonSerializer.Serialize(backup));
                    if (!RunSchtasks($"/Change /TN \"{entry.Location}\" /Disable"))
                    {
                        File.Delete(BackupPath(id));
                        return OperationResult.Fail("schtasks no pudo desactivar la tarea.");
                    }
                    break;
                }
                default:
                    return OperationResult.Fail("Tipo de entrada no soportado.");
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            return OperationResult.Fail("No se pudo desactivar: " + ex.Message);
        }

        _logger.LogWarning("Programa de inicio desactivado: {Name} ({Kind})", entry.Name, entry.Kind);
        return OperationResult.Ok("Desactivado. Puedes restaurarlo cuando quieras.");
    }

    public OperationResult Restore(string id)
    {
        string path = BackupPath(id);
        if (!File.Exists(path))
            return OperationResult.Fail("No hay copia de esa entrada.");
        try
        {
            var b = JsonSerializer.Deserialize<Backup>(File.ReadAllText(path))!;
            switch (b.Kind)
            {
                case AutorunInventory.KindRegistry:
                {
                    var root = b.RegistryRoot == "HKLM" ? Registry.LocalMachine : Registry.Users;
                    using var key = root.CreateSubKey(b.RegistrySubKey!, writable: true);
                    key.SetValue(b.Name, b.Command, RegistryValueKind.String);
                    break;
                }
                case AutorunInventory.KindStartupFolder:
                    File.Move(Path.Combine(_paths.DisabledAutorunsDirectory, id + ".bin"), b.OriginalFile!, overwrite: false);
                    break;
                case AutorunInventory.KindTask:
                    if (!RunSchtasks($"/Change /TN \"{b.TaskName}\" /Enable"))
                        return OperationResult.Fail("schtasks no pudo reactivar la tarea.");
                    break;
            }
            File.Delete(path);
            _logger.LogInformation("Programa de inicio restaurado: {Name}", b.Name);
            return OperationResult.Ok("Restaurado.");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or System.Security.SecurityException)
        {
            return OperationResult.Fail("No se pudo restaurar: " + ex.Message);
        }
    }

    private static bool RunSchtasks(string args)
    {
        using var p = Process.Start(new ProcessStartInfo("schtasks.exe", args) { CreateNoWindow = true, UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true });
        if (p is null) return false;
        p.WaitForExit(15000);
        return p.HasExited && p.ExitCode == 0;
    }
}
