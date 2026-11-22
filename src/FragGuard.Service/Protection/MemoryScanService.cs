using FragGuard.Core.Configuration;
using FragGuard.Core.Data;
using FragGuard.Core.Detection;
using FragGuard.Core.Scanning;
using FragGuard.Service.GameMode;
using FragGuard.Service.Infrastructure;
using FragGuard.Service.Ipc;
using FragGuard.Shared.Ipc;
using FragGuard.Shared.Models;

namespace FragGuard.Service.Protection;

/// <summary>
/// Escaneo de MEMORIA bajo demanda: aplica las reglas YARA a la memoria de los procesos del usuario.
/// Encuentra malware empaquetado/ofuscado (en disco está cifrado; en memoria aparece en claro).
///
/// Para no chocar con los anti-cheat y no molestar mientras juegas:
///  - NO se permite durante el modo juego.
///  - Se excluyen los juegos detectados, los lanzadores y los procesos de anti-cheat (Vanguard, EAC, BattlEye...).
///  - Se excluyen los procesos de Windows (C:\Windows) y los procesos protegidos (no se pueden abrir).
/// Solo lee memoria: no inyecta, no escribe y no suspende nada.
/// </summary>
public sealed class MemoryScanService
{
    private static readonly HashSet<string> NeverScan = new(StringComparer.OrdinalIgnoreCase)
    {
        "vgc.exe", "vgtray.exe", "EasyAntiCheat.exe", "EasyAntiCheat_EOS.exe", "BEService.exe", "BEService_x64.exe",
        "FACEIT.exe", "faceitservice.exe", "EAAntiCheat.GameService.exe", "PnkBstrA.exe", "PnkBstrB.exe", "xigncode3.exe",
        "MsMpEng.exe", "NisSrv.exe", "FragGuard.exe", "FragGuard.Service.exe"
    };

    private readonly IYaraEngine _yara;
    private readonly SettingsStore _settings;
    private readonly GameModeService _gameMode;
    private readonly ThreatResponder _responder;
    private readonly ScanHistoryRepository _history;
    private readonly EventBroadcaster _events;
    private readonly ILogger<MemoryScanService> _logger;
    private int _running;

    public MemoryScanService(IYaraEngine yara, SettingsStore settings, GameModeService gameMode, ThreatResponder responder,
        ScanHistoryRepository history, EventBroadcaster events, ILogger<MemoryScanService> logger)
    {
        _yara = yara;
        _settings = settings;
        _gameMode = gameMode;
        _responder = responder;
        _history = history;
        _events = events;
        _logger = logger;
    }

    public OperationResult Start()
    {
        if (_gameMode.IsActive)
            return OperationResult.Fail("El escaneo de memoria no se permite en modo juego (para no interferir con los anti-cheat). Hazlo cuando termines la partida.");
        if (Interlocked.Exchange(ref _running, 1) == 1)
            return OperationResult.Fail("Ya hay un escaneo de memoria en curso.");
        _ = Task.Run(RunAsync);
        return OperationResult.Ok("Escaneo de memoria iniciado.");
    }

    private async Task RunAsync()
    {
        var summary = new ScanSummaryDto { ScanId = Guid.NewGuid().ToString("N"), Kind = ScanKind.Memory, State = ScanState.Running, StartedUtc = DateTime.UtcNow };
        var sw = System.Diagnostics.Stopwatch.StartNew();
        try
        {
            _history.Upsert(summary);
            var settings = _settings.Current;
            var games = new HashSet<string>(settings.GameProcesses.Concat(settings.LauncherProcesses), StringComparer.OrdinalIgnoreCase);
            var processes = ProcessSnapshot.Take()
                .Where(p => p.Pid > 4 && p.Pid != (uint)Environment.ProcessId && !NeverScan.Contains(p.Name) && !games.Contains(p.Name))
                .ToList();

            foreach (var p in processes)
            {
                if (_gameMode.IsActive)
                {
                    _logger.LogInformation("Escaneo de memoria interrumpido: empezó una partida");
                    summary.State = ScanState.Cancelled;
                    break;
                }

                string? path = NativeMethods.TryGetProcessPath(p.Pid);
                if (path is null || ProcessGuard.IsSystemImage(path))
                {
                    summary.FilesSkipped++;
                    continue;
                }

                _events.Publish(MessageTypes.EventScanProgress, new ScanProgressDto
                {
                    ScanId = summary.ScanId, Kind = ScanKind.Memory, State = ScanState.Running, StartedUtc = summary.StartedUtc,
                    FilesScanned = summary.FilesScanned, FilesSkipped = summary.FilesSkipped, ThreatsFound = summary.ThreatsFound,
                    CurrentFile = $"{p.Name} (PID {p.Pid})", ElapsedMs = sw.ElapsedMilliseconds
                }, FragGuardJsonContext.Default.ScanProgressDto);

                IReadOnlyList<ThreatInfo> threats;
                try
                {
                    threats = await Task.Run(() => _yara.ScanProcess((int)p.Pid)).ConfigureAwait(false);
                    summary.FilesScanned++;
                }
                catch (Exception ex)
                {
                    // Protegido, terminado o sin permiso: normal en muchos procesos.
                    _logger.LogDebug("Memoria de {Name} no analizable: {Error}", p.Name, ex.Message);
                    summary.FilesSkipped++;
                    continue;
                }

                if (threats.Count == 0)
                    continue;

                summary.ThreatsFound++;
                // Un programa de confianza (p. ej. un editor de código con reglas YARA abiertas, o un navegador)
                // puede contener esas cadenas en memoria sin ser malware: solo se avisa, nunca se cierra.
                bool trusted = ProcessGuard.IsTrustedImage(path);
                bool malicious = !trusted && threats.Any(t => t.Severity >= ThreatSeverity.High && t.Category != "Test");
                bool killed = malicious && ProcessGuard.TryKill(p.Pid, p.Name, _logger);
                foreach (var t in threats)
                {
                    t.Description = $"[en memoria de {p.Name}] {t.Description}";
                    if (trusted)
                    {
                        t.Severity = ThreatSeverity.Low;
                        t.Description += " (Programa firmado de confianza: probablemente contiene estas cadenas por otro motivo, como un editor con reglas abiertas.)";
                    }
                }

                _responder.Report(new DetectionDto
                {
                    ScanId = summary.ScanId,
                    ScanKind = ScanKind.Memory,
                    FilePath = path,
                    Verdict = malicious ? FileVerdict.Malicious : FileVerdict.Suspicious,
                    Action = killed ? ThreatAction.ProcessTerminated : ThreatAction.Warned,
                    Threats = threats.ToList(),
                    DetectedUtc = DateTime.UtcNow
                });
            }

            if (summary.State == ScanState.Running)
                summary.State = ScanState.Completed;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error en el escaneo de memoria");
            summary.State = ScanState.Failed;
        }
        finally
        {
            summary.FinishedUtc = DateTime.UtcNow;
            try { _history.Upsert(summary); } catch { }
            _events.Publish(MessageTypes.EventScanCompleted, summary, FragGuardJsonContext.Default.ScanSummaryDto);
            Interlocked.Exchange(ref _running, 0);
            ProcessPriority.TrimMemory();
            _logger.LogInformation("Escaneo de memoria: {Scanned} procesos, {Skipped} omitidos, {Threats} con amenazas", summary.FilesScanned, summary.FilesSkipped, summary.ThreatsFound);
        }
    }
}
