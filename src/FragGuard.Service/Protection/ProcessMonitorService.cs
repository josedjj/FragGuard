using System.Threading.Channels;
using FragGuard.Core.Behavior;
using FragGuard.Core.Configuration;
using FragGuard.Core.Hashing;
using FragGuard.Core.Quarantine;
using FragGuard.Core.Scanning;
using FragGuard.Service.GameMode;
using FragGuard.Service.Infrastructure;
using FragGuard.Shared.Models;

namespace FragGuard.Service.Protection;

/// <summary>
/// Protección de procesos en modo usuario (sin drivers ni inyección):
///  1. Cada 1,5 s (3 s en modo juego) toma una instantánea de procesos (Toolhelp, ~1 ms).
///  2. A cada proceso NUEVO le aplica las reglas de comportamiento sobre su línea de comandos
///     (borrado de copias de seguridad, exclusiones de Defender, PowerShell oculto, LOLBins...) y responde
///     al momento: avisar, detener el proceso o detener también a su origen.
///  3. Encola su ejecutable para analizarlo (hash → caché → YARA → nube). Si es malicioso, detiene el
///     proceso y lo pone en cuarentena.
///
/// Límites honestos: al no haber driver, la detección llega DESPUÉS de que el proceso arranque (hasta 1,5 s).
/// No se analizan ejecutables de C:\Windows (sistema) ni de más de 50 MB (los juegos), y cada ejecutable
/// solo se analiza una vez mientras no cambie.
/// </summary>
public sealed class ProcessMonitorService : BackgroundService
{
    private const long MaxImageBytes = 50L * 1024 * 1024;

    private readonly SettingsStore _settings;
    private readonly FileScanner _scanner;
    private readonly ThreatResponder _responder;
    private readonly QuarantineManager _quarantine;
    private readonly GameModeService _gameMode;
    private readonly ILogger<ProcessMonitorService> _logger;

    private readonly HashSet<uint> _known = new();
    private readonly Dictionary<string, (long Size, DateTime Written)> _scannedImages = new(StringComparer.OrdinalIgnoreCase);
    private readonly Channel<(uint Pid, string Name, string Path)> _scanQueue =
        Channel.CreateBounded<(uint, string, string)>(new BoundedChannelOptions(256) { FullMode = BoundedChannelFullMode.DropOldest });

    public ProcessMonitorService(SettingsStore settings, FileScanner scanner, ThreatResponder responder, QuarantineManager quarantine,
        GameModeService gameMode, ILogger<ProcessMonitorService> logger)
    {
        _settings = settings;
        _scanner = scanner;
        _responder = responder;
        _quarantine = quarantine;
        _gameMode = gameMode;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        var worker = Task.Run(() => ScanWorkerAsync(ct), ct);
        bool first = true;

        while (!ct.IsCancellationRequested)
        {
            try
            {
                if (_settings.Current.ProcessMonitorEnabled)
                {
                    Tick(firstRun: first);
                    first = false;
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error en el monitor de procesos");
            }

            try { await Task.Delay(_gameMode.IsActive ? 3000 : 1500, ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { break; }
        }

        _scanQueue.Writer.TryComplete();
        try { await worker.ConfigureAwait(false); } catch (OperationCanceledException) { }
    }

    private void Tick(bool firstRun)
    {
        var list = ProcessSnapshot.Take();
        var byPid = new Dictionary<uint, ProcessEntry>(list.Count);
        foreach (var p in list)
            byPid[p.Pid] = p;

        foreach (var p in list)
        {
            if (!_known.Add(p.Pid) || p.Pid <= 4 || p.Pid == (uint)Environment.ProcessId)
                continue;

            string? image = NativeMethods.TryGetProcessPath(p.Pid);

            // En el primer recorrido (arranque del servicio) no aplicamos reglas a procesos que ya estaban:
            // solo analizamos sus ejecutables.
            if (!firstRun)
                EvaluateBehavior(p, image, byPid);

            if (image is not null && ShouldScanImage(image))
                _scanQueue.Writer.TryWrite((p.Pid, p.Name, image));
        }

        // Olvidamos los PID que ya no existen (se reutilizan).
        _known.RemoveWhere(pid => !byPid.ContainsKey(pid));
    }

    // ---------------- Reglas de comportamiento ----------------

    private void EvaluateBehavior(ProcessEntry p, string? image, Dictionary<uint, ProcessEntry> snapshot)
    {
        // Solo merece la pena leer la línea de comandos de los ejecutables que las reglas vigilan.
        if (!WatchedForBehavior.Contains(p.Name))
            return;

        var facts = ProcessGuard.Describe(p, image, snapshot);
        foreach (var match in BehaviorRules.Evaluate(facts))
            Respond(facts, match);
    }

    private static readonly HashSet<string> WatchedForBehavior = new(StringComparer.OrdinalIgnoreCase)
    {
        "vssadmin.exe", "wmic.exe", "wbadmin.exe", "bcdedit.exe", "powershell.exe", "pwsh.exe", "cmd.exe", "reg.exe",
        "certutil.exe", "bitsadmin.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe", "schtasks.exe"
    };

    private void Respond(ProcessFacts facts, BehaviorMatch match)
    {
        bool killed = false;
        if (match.Response is BehaviorResponse.KillProcess or BehaviorResponse.KillProcessAndParent)
            killed = ProcessGuard.TryKill(facts.Pid, facts.Name, _logger);

        string? originQuarantined = null;
        if (match.Response == BehaviorResponse.KillProcessAndParent && facts.ParentName is not null && !facts.ParentTrusted)
        {
            // El ORIGEN (quien lanzó el comando) es el verdadero culpable: lo detenemos y, si su ejecutable
            // está en una carpeta de usuario, lo aislamos aunque ninguna firma lo detecte.
            killed |= ProcessGuard.TryKill(facts.ParentPid, facts.ParentName, _logger);
            if (facts.ParentPath is { } originPath && ProcessGuard.IsUserWritableLocation(originPath) && !ProcessGuard.IsSystemImage(originPath))
                originQuarantined = QuarantineOrigin(originPath, match.RuleId);
        }

        _responder.Report(new DetectionDto
        {
            ScanKind = ScanKind.Realtime,
            FilePath = facts.ParentPath ?? facts.ImagePath ?? facts.Name,
            Verdict = match.Severity >= ThreatSeverity.High ? FileVerdict.Malicious : FileVerdict.Suspicious,
            Action = originQuarantined is not null ? ThreatAction.Quarantined : killed ? ThreatAction.ProcessTerminated : ThreatAction.Warned,
            QuarantineId = originQuarantined,
            Threats = new List<ThreatInfo> { match.ToThreat() },
            DetectedUtc = DateTime.UtcNow
        });
    }

    private string? QuarantineOrigin(string path, string reason)
    {
        try
        {
            string sha;
            using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                sha = FileHasher.HashStreamAsync(fs, CancellationToken.None).GetAwaiter().GetResult();
            var outcome = _quarantine.QuarantineAsync(path, sha, reason, CancellationToken.None).GetAwaiter().GetResult();
            return outcome.QuarantineId;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "No se pudo aislar el origen {Path}", path);
            return null;
        }
    }

    // ---------------- Análisis del ejecutable ----------------

    private bool ShouldScanImage(string image)
    {
        if (ProcessGuard.IsSystemImage(image))
            return false;
        try
        {
            var fi = new FileInfo(image);
            if (!fi.Exists || fi.Length > MaxImageBytes)
                return false;
            var stamp = (fi.Length, fi.LastWriteTimeUtc);
            if (_scannedImages.TryGetValue(image, out var prev) && prev == stamp)
                return false;
            if (_scannedImages.Count > 5000)
                _scannedImages.Clear();
            _scannedImages[image] = stamp;
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    private async Task ScanWorkerAsync(CancellationToken ct)
    {
        await foreach (var (pid, name, path) in _scanQueue.Reader.ReadAllAsync(ct).ConfigureAwait(false))
        {
            try
            {
                var result = await _scanner.ScanAsync(path, FileScanContext.ForScan(ScanKind.Realtime), ct).ConfigureAwait(false);
                if (!result.IsThreat)
                    continue;

                // Malicioso y en ejecución: primero detenerlo (si no, el archivo está bloqueado y no se puede aislar).
                if (result.Verdict == FileVerdict.Malicious)
                {
                    ProcessGuard.TryKill(pid, name, _logger);
                    await Task.Delay(300, ct).ConfigureAwait(false); // que Windows libere el archivo
                }
                await _responder.HandleAsync(result, null, ScanKind.Realtime, ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error analizando el ejecutable de {Name}", name);
            }
        }
    }
}
