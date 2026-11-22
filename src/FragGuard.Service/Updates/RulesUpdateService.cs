using FragGuard.Core.Configuration;
using FragGuard.Core.Detection;
using FragGuard.Core.Updates;
using FragGuard.Service.GameMode;
using FragGuard.Service.Infrastructure;

namespace FragGuard.Service.Updates;

/// <summary>
/// Comprueba el canal firmado de reglas cada 12 h (la primera vez, 3 minutos después de arrancar) y,
/// si hay una versión nueva con firma válida, recarga YARA en caliente. Nunca durante el modo juego:
/// recompilar reglas supone un pico de CPU de un segundo.
/// </summary>
public sealed class RulesUpdateService : BackgroundService
{
    private static readonly TimeSpan FirstCheck = TimeSpan.FromMinutes(3);
    private static readonly TimeSpan Interval = TimeSpan.FromHours(12);

    private readonly RulesChannel _channel;
    private readonly IYaraEngine _yara;
    private readonly FragGuardPaths _paths;
    private readonly SettingsStore _settings;
    private readonly GameModeService _gameMode;
    private readonly ILogger<RulesUpdateService> _logger;
    private readonly SemaphoreSlim _gate = new(1, 1);

    public RulesUpdateService(RulesChannel channel, IYaraEngine yara, FragGuardPaths paths, SettingsStore settings,
        GameModeService gameMode, ILogger<RulesUpdateService> logger)
    {
        _channel = channel;
        _yara = yara;
        _paths = paths;
        _settings = settings;
        _gameMode = gameMode;
        _logger = logger;
    }

    public long InstalledVersion => _channel.InstalledVersion;
    public DateTime? LastCheckUtc { get; private set; }
    public string? LastResult { get; private set; }

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        try { await Task.Delay(FirstCheck, ct).ConfigureAwait(false); }
        catch (OperationCanceledException) { return; }

        while (!ct.IsCancellationRequested)
        {
            if (_settings.Current.AutoUpdateRules && !_gameMode.IsActive)
                await CheckNowAsync(ct).ConfigureAwait(false);

            // Si estaba jugando, reintentamos antes (en 30 min) en vez de esperar 12 h.
            var wait = _gameMode.IsActive ? TimeSpan.FromMinutes(30) : Interval;
            try { await Task.Delay(wait, ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { return; }
        }
    }

    /// <summary>Comprueba y aplica ahora (también lo usa el botón "Buscar actualizaciones" de la UI).</summary>
    public async Task<RulesUpdateResult> CheckNowAsync(CancellationToken ct)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var result = await _channel.CheckAndApplyAsync(ct).ConfigureAwait(false);
            LastCheckUtc = DateTime.UtcNow;
            LastResult = result.Outcome switch
            {
                RulesUpdateOutcome.Applied => $"Reglas actualizadas (versión {result.Version}).",
                RulesUpdateOutcome.UpToDate => "Las reglas ya están al día.",
                RulesUpdateOutcome.NotAvailable => "El canal de reglas no está disponible todavía.",
                RulesUpdateOutcome.InvalidSignature => "Actualización RECHAZADA: firma no válida.",
                _ => "No se pudo comprobar: " + result.Message
            };

            if (result.Outcome == RulesUpdateOutcome.Applied)
            {
                _yara.LoadRules(_paths.RulesDirectory, _paths.UpdatedRulesDirectory);
                ProcessPriority.TrimMemory();
            }
            return result;
        }
        finally
        {
            _gate.Release();
        }
    }
}
