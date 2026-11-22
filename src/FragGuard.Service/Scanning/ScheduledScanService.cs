using FragGuard.Core.Configuration;
using FragGuard.Core.Data;
using FragGuard.Service.GameMode;
using FragGuard.Shared.Models;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace FragGuard.Service.Scanning;

/// <summary>
/// Escaneo rápido diario a la hora configurada.
/// - Si el PC estaba apagado a esa hora, se recupera más tarde ese mismo día.
/// - No arranca durante el modo juego (queda pendiente hasta que termine la partida).
/// - Espera unos minutos tras el arranque del servicio para no cargar el inicio de Windows.
/// </summary>
public sealed class ScheduledScanService : BackgroundService
{
    private static readonly TimeSpan BootGracePeriod = TimeSpan.FromMinutes(5);

    private readonly SettingsStore _settings;
    private readonly ScanHistoryRepository _history;
    private readonly ScanCoordinator _scans;
    private readonly GameModeService _gameMode;
    private readonly ILogger<ScheduledScanService> _logger;
    private readonly DateTime _startedUtc = DateTime.UtcNow;
    private bool _loggedWaitingForGame;

    public ScheduledScanService(SettingsStore settings, ScanHistoryRepository history, ScanCoordinator scans,
        GameModeService gameMode, ILogger<ScheduledScanService> logger)
    {
        _settings = settings;
        _history = history;
        _scans = scans;
        _gameMode = gameMode;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromMinutes(1));
        while (await timer.WaitForNextTickAsync(ct).ConfigureAwait(false))
        {
            try
            {
                Tick();
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error en el programador de escaneos");
            }
        }
    }

    private void Tick()
    {
        var settings = _settings.Current;
        if (!settings.ScheduledScanEnabled || DateTime.UtcNow - _startedUtc < BootGracePeriod)
            return;
        if (!TimeOnly.TryParseExact(settings.ScheduledScanTime, "HH:mm", out var scheduled))
            return;

        var now = DateTime.Now;
        if (TimeOnly.FromDateTime(now) < scheduled)
            return;

        var last = _history.GetLastStartedUtc(ScanKind.Scheduled);
        if (last is { } l && l.ToLocalTime().Date == now.Date)
            return; // ya se hizo hoy

        if (_gameMode.IsActive)
        {
            if (!_loggedWaitingForGame)
            {
                _logger.LogInformation("Escaneo programado pendiente: se ejecutará al salir del modo juego");
                _loggedWaitingForGame = true;
            }
            return;
        }
        if (_scans.IsBusy)
            return;

        _loggedWaitingForGame = false;
        var result = _scans.Start(new ScanRequest { Kind = ScanKind.Scheduled });
        _logger.LogInformation("Escaneo programado: {Result}", result.Success ? "iniciado" : result.Message);
    }
}
