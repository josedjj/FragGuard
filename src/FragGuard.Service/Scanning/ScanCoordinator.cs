using FragGuard.Core.Configuration;
using FragGuard.Core.Scanning;
using FragGuard.Service.Infrastructure;
using FragGuard.Service.Ipc;
using FragGuard.Shared.Ipc;
using FragGuard.Shared.Models;
using Microsoft.Extensions.Logging;

namespace FragGuard.Service.Scanning;

/// <summary>
/// Gestiona los escaneos manuales y programados (uno a la vez), su pausa/cancelación
/// y su comportamiento en modo juego:
///  - Escaneos PROGRAMADOS: se pausan mientras dura el modo juego y se reanudan solos al salir.
///  - Escaneos MANUALES (los pidió el usuario): siguen, pero en modo de bajo impacto (1 hilo, con pausas).
/// </summary>
public sealed class ScanCoordinator
{
    private const string GameModeReason = "gamemode";
    private const string UserReason = "user";

    private readonly ScanRunner _runner;
    private readonly ScanThrottle _throttle;
    private readonly SettingsStore _settings;
    private readonly UserFolderRegistry _userFolders;
    private readonly EventBroadcaster _events;
    private readonly ILogger<ScanCoordinator> _logger;
    private readonly object _sync = new();

    private ScanJob? _current;
    private CancellationTokenSource? _cts;
    private bool _gameMode;

    public ScanCoordinator(ScanRunner runner, ScanThrottle throttle, SettingsStore settings, UserFolderRegistry userFolders,
        EventBroadcaster events, ILogger<ScanCoordinator> logger)
    {
        _runner = runner;
        _throttle = throttle;
        _settings = settings;
        _userFolders = userFolders;
        _events = events;
        _logger = logger;
    }

    public bool IsBusy
    {
        get { lock (_sync) return _current is not null; }
    }

    public ScanProgressDto? ActiveProgress
    {
        get { lock (_sync) return _current?.GetProgress(); }
    }

    public OperationResult Start(ScanRequest request)
    {
        List<string> roots;
        bool onlyInteresting;
        switch (request.Kind)
        {
            case ScanKind.Quick:
            case ScanKind.Scheduled:
                roots = ScanTargets.GetQuickScanRoots(_userFolders.AllFolders);
                onlyInteresting = true;
                break;
            case ScanKind.Full:
                roots = ScanTargets.GetFullScanRoots();
                onlyInteresting = true;
                break;
            case ScanKind.Custom:
                if (string.IsNullOrWhiteSpace(request.CustomPath) || !Path.IsPathFullyQualified(request.CustomPath))
                    return OperationResult.Fail("Ruta no válida.");
                if (!Directory.Exists(request.CustomPath) && !File.Exists(request.CustomPath))
                    return OperationResult.Fail("La ruta no existe.");
                roots = [Path.GetFullPath(request.CustomPath)];
                onlyInteresting = false; // en el personalizado se analiza todo
                break;
            default:
                return OperationResult.Fail("Tipo de escaneo no soportado.");
        }

        if (roots.Count == 0)
            return OperationResult.Fail("No hay carpetas que analizar.");

        ScanJob job;
        CancellationTokenSource cts;
        lock (_sync)
        {
            if (_current is not null)
                return OperationResult.Fail("Ya hay un escaneo en curso.");
            job = new ScanJob(request.Kind, roots, onlyInteresting);
            cts = new CancellationTokenSource();
            _current = job;
            _cts = cts;
            // Un programado que arranca durante el modo juego nace pausado.
            if (_gameMode && request.Kind == ScanKind.Scheduled)
                job.Gate.Pause(GameModeReason);
        }

        _ = Task.Run(() => RunJobAsync(job, cts));
        return OperationResult.Ok(job.Id);
    }

    private async Task RunJobAsync(ScanJob job, CancellationTokenSource cts)
    {
        ScanSummaryDto summary;
        try
        {
            summary = await _runner.RunAsync(job,
                p => _events.Publish(MessageTypes.EventScanProgress, p, FragGuardJsonContext.Default.ScanProgressDto),
                cts.Token);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error inesperado en el escaneo {Id}", job.Id);
            job.State = ScanState.Failed;
            summary = job.GetSummary();
        }
        finally
        {
            lock (_sync)
            {
                _current = null;
                _cts = null;
            }
            cts.Dispose();
        }

        _events.Publish(MessageTypes.EventScanCompleted, summary, FragGuardJsonContext.Default.ScanSummaryDto);

        // Devolvemos al sistema la memoria usada durante el escaneo (vuelta al consumo de reposo).
        ProcessPriority.TrimMemory();
    }

    public OperationResult Cancel()
    {
        lock (_sync)
        {
            if (_cts is null)
                return OperationResult.Fail("No hay ningún escaneo en curso.");
            _cts.Cancel();
            _current?.Gate.Resume(UserReason);
            _current?.Gate.Resume(GameModeReason); // para que los hilos pausados vean la cancelación
            return OperationResult.Ok();
        }
    }

    public OperationResult Pause()
    {
        lock (_sync)
        {
            if (_current is null)
                return OperationResult.Fail("No hay ningún escaneo en curso.");
            _current.Gate.Pause(UserReason);
            return OperationResult.Ok();
        }
    }

    public OperationResult Resume()
    {
        lock (_sync)
        {
            if (_current is null)
                return OperationResult.Fail("No hay ningún escaneo en curso.");
            _current.Gate.Resume(UserReason);
            return OperationResult.Ok();
        }
    }

    /// <summary>Lo llama el servicio de modo juego al entrar/salir.</summary>
    public void SetGameMode(bool active)
    {
        lock (_sync)
        {
            _gameMode = active;
            _throttle.LowImpact = active;
            if (_current is { Kind: ScanKind.Scheduled } job)
            {
                if (active) job.Gate.Pause(GameModeReason);
                else job.Gate.Resume(GameModeReason);
                _logger.LogInformation("Escaneo programado {State} por el modo juego", active ? "pausado" : "reanudado");
            }
        }
    }
}
