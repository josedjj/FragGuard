using System.Collections.Concurrent;
using System.Security.Cryptography;
using FragGuard.Core.Configuration;
using FragGuard.Core.Hashing;
using FragGuard.Core.Quarantine;
using FragGuard.Core.Scanning;
using FragGuard.Service.Infrastructure;
using FragGuard.Shared.Models;

namespace FragGuard.Service.Protection;

/// <summary>
/// Escudo anti-ransomware en modo usuario.
///
/// Detección (dos señales independientes):
///  1. ARCHIVOS SEÑUELO ocultos en Documentos, Imágenes y Escritorio de cada usuario. Ningún programa
///     legítimo tiene motivo para modificarlos o renombrarlos: si ocurre, casi seguro es ransomware.
///  2. CAMBIOS MASIVOS: muchos archivos renombrados a una extensión distinta (fotos.jpg → fotos.jpg.locked)
///     en pocos segundos dentro de las carpetas personales.
///
/// Respuesta: FileSystemWatcher no dice QUÉ proceso escribe, así que se comparan los contadores de E/S de
/// todos los procesos (GetProcessIoCounters, solo lectura) con la muestra anterior: el proceso no confiable
/// que más ha escrito en los últimos segundos es el culpable → se detiene y su ejecutable va a cuarentena.
/// (El borrado de copias de seguridad que suele preceder al cifrado lo detectan las reglas de comportamiento.)
/// </summary>
public sealed class RansomwareShield : BackgroundService
{
    private const string CanaryMarker = "fg_canary";
    private static readonly string[] CanaryNames = { "!" + CanaryMarker + "_0001.docx", "~~" + CanaryMarker + "_zz.jpg" };
    private static readonly TimeSpan Window = TimeSpan.FromSeconds(10);
    private const int RenameThreshold = 25;

    private readonly SettingsStore _settings;
    private readonly ThreatResponder _responder;
    private readonly QuarantineManager _quarantine;
    private readonly ILogger<RansomwareShield> _logger;

    private readonly List<FileSystemWatcher> _watchers = new();
    private readonly ConcurrentQueue<DateTime> _suspiciousRenames = new();
    private Dictionary<uint, (string Name, ulong Writes)> _ioBaseline = new();
    private DateTime _lastTriggerUtc = DateTime.MinValue;
    private volatile bool _triggerPending;
    private volatile string? _triggerReason;

    public RansomwareShield(SettingsStore settings, ThreatResponder responder, QuarantineManager quarantine, ILogger<RansomwareShield> logger)
    {
        _settings = settings;
        _responder = responder;
        _quarantine = quarantine;
        _logger = logger;
    }

    public bool IsArmed { get; private set; }
    public int CanaryCount { get; private set; }

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        bool armed = false;
        while (!ct.IsCancellationRequested)
        {
            try
            {
                bool enabled = _settings.Current.RansomwareShieldEnabled;
                if (enabled && !armed) { Arm(); armed = true; }
                else if (!enabled && armed) { Disarm(); armed = false; }

                if (armed)
                {
                    if (_triggerPending)
                    {
                        _triggerPending = false;
                        Respond(_triggerReason ?? "Actividad de ransomware");
                    }
                    // Muestra de contadores de E/S cada ~2 s para tener con qué comparar en caso de alarma.
                    _ioBaseline = SampleIo();
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error en el escudo anti-ransomware");
            }

            try { await Task.Delay(TimeSpan.FromSeconds(2), ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { break; }
        }
        Disarm();
    }

    // ---------------- Armado: señuelos + vigilancia ----------------

    private void Arm()
    {
        int canaries = 0;
        foreach (var profile in ScanTargets.GetUserProfiles())
        {
            // Rutas REALES (OneDrive puede redirigir Documentos y Escritorio).
            foreach (var (value, sub) in new[] { ("Personal", "Documents"), ("My Pictures", "Pictures"), ("Desktop", "Desktop") })
            {
                string dir = ScanTargets.GetShellFolder(profile, value, sub);
                if (!Directory.Exists(dir))
                    continue;
                canaries += EnsureCanaries(dir);
                Watch(dir);
            }
        }
        CanaryCount = canaries;
        IsArmed = true;
        _logger.LogInformation("Escudo anti-ransomware activo: {Count} señuelos, {Folders} carpetas vigiladas", canaries, _watchers.Count);
    }

    private void Disarm()
    {
        foreach (var w in _watchers) w.Dispose();
        _watchers.Clear();
        IsArmed = false;
    }

    /// <summary>Crea los archivos señuelo (ocultos) si no existen. Contenido aleatorio con cabecera realista.</summary>
    private int EnsureCanaries(string dir)
    {
        int n = 0;
        foreach (string name in CanaryNames)
        {
            string path = Path.Combine(dir, name);
            try
            {
                if (!File.Exists(path))
                {
                    byte[] content = RandomNumberGenerator.GetBytes(24 * 1024);
                    // Cabeceras de un .docx (ZIP) y de un .jpg: el ransomware filtra por tipo de archivo.
                    if (name.EndsWith(".docx")) { content[0] = 0x50; content[1] = 0x4B; content[2] = 0x03; content[3] = 0x04; }
                    else { content[0] = 0xFF; content[1] = 0xD8; content[2] = 0xFF; content[3] = 0xE0; }
                    File.WriteAllBytes(path, content);
                    File.SetAttributes(path, FileAttributes.Hidden);
                }
                n++;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                _logger.LogDebug("No se pudo crear el señuelo {Path}: {Error}", path, ex.Message);
            }
        }
        return n;
    }

    private void Watch(string dir)
    {
        try
        {
            var w = new FileSystemWatcher(dir)
            {
                IncludeSubdirectories = true,
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size,
                InternalBufferSize = 64 * 1024
            };
            w.Changed += (_, e) => { if (IsCanary(e.FullPath)) Trigger($"Se modificó un archivo señuelo ({e.Name})"); };
            w.Renamed += (_, e) => OnRenamed(e);
            w.Deleted += (_, e) => { if (IsCanary(e.FullPath)) _logger.LogInformation("Señuelo eliminado: {Path} (se recreará)", e.FullPath); };
            w.Error += (_, e) => _logger.LogDebug(e.GetException(), "Watcher del escudo con error en {Dir}", dir);
            w.EnableRaisingEvents = true;
            _watchers.Add(w);
        }
        catch (Exception ex) when (ex is ArgumentException or IOException or UnauthorizedAccessException)
        {
            _logger.LogDebug("No se pudo vigilar {Dir}: {Error}", dir, ex.Message);
        }
    }

    private static bool IsCanary(string path) => Path.GetFileName(path).Contains(CanaryMarker, StringComparison.OrdinalIgnoreCase);

    private void OnRenamed(RenamedEventArgs e)
    {
        if (IsCanary(e.OldFullPath))
        {
            Trigger($"Se renombró un archivo señuelo ({e.OldName} → {e.Name})");
            return;
        }
        if (IsExtensionChange(e.OldFullPath, e.FullPath))
        {
            var now = DateTime.UtcNow;
            _suspiciousRenames.Enqueue(now);
            while (_suspiciousRenames.TryPeek(out var t) && now - t > Window)
                _suspiciousRenames.TryDequeue(out _);
            if (_suspiciousRenames.Count >= RenameThreshold)
                Trigger($"{_suspiciousRenames.Count} archivos renombrados a extensiones nuevas en {Window.TotalSeconds:0} s");
        }
    }

    /// <summary>
    /// fotos.jpg → fotos.jpg.locked, o informe.docx → informe.x7k9q. Se ignoran los temporales de los
    /// programas de ofimática (~$archivo, .tmp) y los cambios a extensiones conocidas.
    /// </summary>
    internal static bool IsExtensionChange(string oldPath, string newPath)
    {
        string oldExt = Path.GetExtension(oldPath);
        string newExt = Path.GetExtension(newPath);
        if (oldExt.Length == 0 || oldExt.Equals(newExt, StringComparison.OrdinalIgnoreCase))
            return false;
        if (newExt is ".tmp" or ".bak" or ".crdownload" or ".part" || oldExt is ".tmp" or ".crdownload" or ".part")
            return false;
        return !Path.GetFileName(oldPath).StartsWith("~$");
    }

    private void Trigger(string reason)
    {
        // Una sola respuesta cada 30 s: un ransomware genera miles de eventos.
        if (DateTime.UtcNow - _lastTriggerUtc < TimeSpan.FromSeconds(30))
            return;
        _lastTriggerUtc = DateTime.UtcNow;
        _triggerReason = reason;
        _triggerPending = true;
        _logger.LogCritical("ALERTA RANSOMWARE: {Reason}", reason);
    }

    // ---------------- Respuesta ----------------

    private void Respond(string reason)
    {
        var before = _ioBaseline;
        var now = SampleIo();

        // El proceso NO confiable que más operaciones de escritura ha hecho desde la última muestra.
        var culprit = now
            .Where(kv => before.TryGetValue(kv.Key, out var b) && kv.Value.Writes > b.Writes)
            .Select(kv => (Pid: kv.Key, kv.Value.Name, Delta: kv.Value.Writes - before[kv.Key].Writes, Path: NativeMethods.TryGetProcessPath(kv.Key)))
            .Where(c => c.Delta > 50 && c.Path is not null && !ProcessGuard.IsTrustedImage(c.Path) && !c.Path.Contains("FragGuard", StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(c => c.Delta)
            .FirstOrDefault();

        ThreatAction action = ThreatAction.Warned;
        string? quarantineId = null;
        string description = reason + ".";

        if (culprit.Path is not null)
        {
            bool killed = ProcessGuard.TryKill(culprit.Pid, culprit.Name, _logger);
            if (killed)
            {
                action = ThreatAction.ProcessTerminated;
                Thread.Sleep(300);
                quarantineId = TryQuarantine(culprit.Path);
                if (quarantineId is not null)
                    action = ThreatAction.Quarantined;
            }
            description += $" Proceso responsable: {culprit.Name} ({culprit.Delta:N0} escrituras en segundos).";
        }
        else
        {
            description += " No se pudo identificar un proceso responsable no confiable: revisa los programas abiertos.";
        }

        _responder.Report(new DetectionDto
        {
            ScanKind = ScanKind.Realtime,
            FilePath = culprit.Path ?? "Carpetas personales",
            Verdict = FileVerdict.Malicious,
            Action = action,
            QuarantineId = quarantineId,
            DetectedUtc = DateTime.UtcNow,
            Threats = new List<ThreatInfo>
            {
                new()
                {
                    Name = "FG.Behavior.Ransomware",
                    Category = "Ransomware",
                    Severity = ThreatSeverity.Critical,
                    Source = DetectionSource.Behavior,
                    Description = description
                }
            }
        });
    }

    private string? TryQuarantine(string path)
    {
        try
        {
            string sha;
            using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                sha = FileHasher.HashStreamAsync(fs, CancellationToken.None).GetAwaiter().GetResult();
            return _quarantine.QuarantineAsync(path, sha, "FG.Behavior.Ransomware", CancellationToken.None).GetAwaiter().GetResult().QuarantineId;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "No se pudo aislar {Path}", path);
            return null;
        }
    }

    private static Dictionary<uint, (string Name, ulong Writes)> SampleIo()
    {
        var result = new Dictionary<uint, (string, ulong)>();
        foreach (var p in ProcessSnapshot.Take())
        {
            if (p.Pid <= 4)
                continue;
            if (NativeMethods.TryGetIoCounters(p.Pid) is { } io)
                result[p.Pid] = (p.Name, io.WriteOperationCount);
        }
        return result;
    }
}
