using FragGuard.Core.Configuration;
using FragGuard.Core.Detection;
using FragGuard.Service.Infrastructure;
using FragGuard.Service.Ipc;
using FragGuard.Service.Scanning;
using FragGuard.Shared.Ipc;
using FragGuard.Shared.Models;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace FragGuard.Service.GameMode;

/// <summary>
/// Modo juego automático + vigilancia de procesos con nombre de cheat.
///
/// Cada 3 s toma una instantánea de procesos (Toolhelp, muy barata) y activa el modo juego si:
///   a) se ejecuta un juego conocido (lista GameProcesses), o
///   b) un lanzador (Steam, Epic, Battle.net, Riot...) tiene un proceso HIJO que no es uno de sus auxiliares, o
///   c) la UI informa de una aplicación a pantalla completa en la sesión del usuario.
///
/// Mientras está activo: el servicio pasa a prioridad "background" (CPU + E/S bajas), los escaneos
/// programados se pausan y la UI silencia las notificaciones no críticas. Al cerrar el juego, todo vuelve solo.
/// </summary>
public sealed class GameModeService : BackgroundService
{
    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(3);

    private readonly SettingsStore _settings;
    private readonly ScanCoordinator _scans;
    private readonly ProcessPriority _priority;
    private readonly EventBroadcaster _events;
    private readonly ILogger<GameModeService> _logger;
    private readonly object _sync = new();
    private readonly uint _selfPid = (uint)Environment.ProcessId;

    // Estado del modo juego
    private bool _active;
    private string? _reason;

    // Pantalla completa reportada por la UI (por conexión, para poder limpiarlo si la UI se desconecta)
    private Guid? _fullscreenClient;
    private string? _fullscreenProcess;

    // Procesos ya avisados como "cheat" (PID -> nombre). Solo estos se pueden terminar desde la UI.
    private readonly Dictionary<uint, string> _flaggedProcesses = new();

    public GameModeService(SettingsStore settings, ScanCoordinator scans, ProcessPriority priority,
        EventBroadcaster events, ILogger<GameModeService> logger)
    {
        _settings = settings;
        _scans = scans;
        _priority = priority;
        _events = events;
        _logger = logger;
    }

    public bool IsActive
    {
        get { lock (_sync) return _active; }
    }

    public string? Reason
    {
        get { lock (_sync) return _reason; }
    }

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        using var timer = new PeriodicTimer(PollInterval);
        do
        {
            try
            {
                Evaluate(ProcessSnapshot.Take());
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error evaluando el modo juego");
            }
        }
        while (await timer.WaitForNextTickAsync(ct).ConfigureAwait(false));
    }

    // ---------------- Pantalla completa (la reporta la UI) ----------------

    public void ReportFullscreen(Guid clientId, bool isFullscreen, string? processName)
    {
        lock (_sync)
        {
            if (isFullscreen)
            {
                _fullscreenClient = clientId;
                _fullscreenProcess = string.IsNullOrWhiteSpace(processName) ? "aplicación" : processName;
            }
            else if (_fullscreenClient == clientId)
            {
                _fullscreenClient = null;
                _fullscreenProcess = null;
            }
        }
        Reevaluate();
    }

    public void ClientDisconnected(Guid clientId)
    {
        bool changed;
        lock (_sync)
        {
            changed = _fullscreenClient == clientId;
            if (changed)
            {
                _fullscreenClient = null;
                _fullscreenProcess = null;
            }
        }
        if (changed)
            Reevaluate();
    }

    private void Reevaluate()
    {
        try { Evaluate(ProcessSnapshot.Take()); }
        catch (Exception ex) { _logger.LogWarning(ex, "Error reevaluando el modo juego"); }
    }

    // ---------------- Lógica principal ----------------

    private readonly object _evaluateLock = new();

    private void Evaluate(List<ProcessEntry> processes)
    {
        // Se llama desde el temporizador y desde el pipe (pantalla completa): una evaluación a la vez.
        lock (_evaluateLock)
            EvaluateCore(processes);
    }

    private void EvaluateCore(List<ProcessEntry> processes)
    {
        var settings = _settings.Current;
        CheckCheatProcesses(processes);

        string? reason = null;
        if (settings.GameModeAuto)
        {
            reason = DetectGame(processes, settings);
            if (reason is null && settings.GameModeOnFullscreen)
            {
                lock (_sync)
                {
                    if (_fullscreenClient is not null)
                        reason = $"Pantalla completa: {_fullscreenProcess}";
                }
            }
        }

        bool shouldBeActive = reason is not null;
        bool changed;
        lock (_sync)
        {
            changed = shouldBeActive != _active;
            _active = shouldBeActive;
            _reason = reason;
        }

        if (changed)
            Apply(shouldBeActive, reason);
    }

    private void Apply(bool active, string? reason)
    {
        _logger.LogInformation(active ? "Modo juego ACTIVADO ({Reason})" : "Modo juego desactivado", reason);
        _priority.SetBackgroundMode(active);
        _scans.SetGameMode(active);
        _events.Publish(MessageTypes.EventGameModeChanged, new GameModeDto { Active = active, Reason = reason },
            FragGuardJsonContext.Default.GameModeDto);
    }

    /// <summary>Devuelve el motivo si detecta un juego, o null.</summary>
    internal static string? DetectGame(List<ProcessEntry> processes, FragGuardSettings settings)
    {
        var games = new HashSet<string>(settings.GameProcesses, StringComparer.OrdinalIgnoreCase);
        var launchers = new HashSet<string>(settings.LauncherProcesses, StringComparer.OrdinalIgnoreCase);
        var helpers = new HashSet<string>(settings.LauncherHelperProcesses, StringComparer.OrdinalIgnoreCase);

        // a) juego conocido
        foreach (var p in processes)
        {
            if (games.Contains(p.Name))
                return $"Juego detectado: {p.Name}";
        }

        // b) hijo de un lanzador que no es un proceso auxiliar
        var launcherPids = new Dictionary<uint, string>();
        foreach (var p in processes)
        {
            if (launchers.Contains(p.Name))
                launcherPids[p.Pid] = p.Name;
        }
        if (launcherPids.Count == 0)
            return null;

        foreach (var p in processes)
        {
            if (launcherPids.TryGetValue(p.ParentPid, out var launcher) &&
                !helpers.Contains(p.Name) && !launchers.Contains(p.Name))
                return $"Juego lanzado desde {Path.GetFileNameWithoutExtension(launcher)}: {p.Name}";
        }
        return null;
    }

    // ---------------- Procesos con nombre de cheat ----------------

    private void CheckCheatProcesses(List<ProcessEntry> processes)
    {
        var alive = new HashSet<uint>(processes.Count);
        var newWarnings = new List<CheatWarningDto>();

        foreach (var p in processes)
        {
            alive.Add(p.Pid);
            if (p.Pid == _selfPid || p.Pid <= 4)
                continue;

            lock (_sync)
            {
                if (_flaggedProcesses.ContainsKey(p.Pid))
                    continue;
            }

            if (CheatLureAnalyzer.Analyze(p.Name) is not { } lure)
                continue;

            string path = NativeMethods.TryGetProcessPath(p.Pid) ?? p.Name;
            lock (_sync)
                _flaggedProcesses[p.Pid] = p.Name;

            newWarnings.Add(new CheatWarningDto
            {
                Path = path,
                ProcessId = (int)p.Pid,
                Origin = "Process",
                Reason = lure.Description,
                DetectedUtc = DateTime.UtcNow
            });
        }

        // Olvidamos los PIDs que ya no existen (los PIDs se reutilizan).
        lock (_sync)
        {
            foreach (var pid in _flaggedProcesses.Keys.Where(pid => !alive.Contains(pid)).ToList())
                _flaggedProcesses.Remove(pid);
        }

        foreach (var w in newWarnings)
        {
            _logger.LogWarning("Proceso con nombre de cheat en ejecución: {Path} (PID {Pid})", w.Path, w.ProcessId);
            _events.Publish(MessageTypes.EventCheatWarning, w, FragGuardJsonContext.Default.CheatWarningDto);
        }
    }

    /// <summary>
    /// Termina un proceso, pero SOLO si es uno que nosotros marcamos como cheat.
    /// El servicio corre como SYSTEM: sin esta comprobación, cualquier usuario podría usar el pipe
    /// para matar procesos que él mismo no tiene permiso para cerrar.
    /// </summary>
    public OperationResult KillFlaggedProcess(int pid)
    {
        string? name;
        lock (_sync)
        {
            if (!_flaggedProcesses.TryGetValue((uint)pid, out name))
                return OperationResult.Fail("Solo se pueden cerrar procesos marcados por FragGuard.");
        }

        try
        {
            using var process = System.Diagnostics.Process.GetProcessById(pid);
            if (!string.Equals(process.ProcessName + ".exe", name, StringComparison.OrdinalIgnoreCase))
                return OperationResult.Fail("El proceso ya no es el mismo.");
            process.Kill(entireProcessTree: false);
            _logger.LogWarning("Proceso cerrado a petición del usuario: {Name} (PID {Pid})", name, pid);
            return OperationResult.Ok();
        }
        catch (ArgumentException)
        {
            return OperationResult.Fail("El proceso ya no existe.");
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            return OperationResult.Fail("No se pudo cerrar: " + ex.Message);
        }
    }
}
