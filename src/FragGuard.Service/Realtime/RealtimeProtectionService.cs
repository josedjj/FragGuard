using System.Collections.Concurrent;
using System.Threading.Channels;
using FragGuard.Core.Configuration;
using FragGuard.Core.Scanning;
using FragGuard.Service.Infrastructure;
using FragGuard.Shared.Models;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace FragGuard.Service.Realtime;

/// <summary>
/// Protección en tiempo real a nivel de usuario (sin drivers): FileSystemWatcher sobre las Descargas
/// de cada usuario y las carpetas configuradas (mods, etc.).
///
/// Flujo: evento del watcher → filtro por extensión → "debounce" (se espera a que el archivo deje de
/// cambiar ~2 s, p. ej. mientras el navegador termina la descarga) → cola → 2 analizadores en paralelo.
/// Los archivos bloqueados se reintentan unas cuantas veces.
/// </summary>
public sealed class RealtimeProtectionService : BackgroundService
{
    private static readonly TimeSpan SettleDelay = TimeSpan.FromSeconds(2);
    private static readonly TimeSpan LockedRetryDelay = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan PeriodicRefresh = TimeSpan.FromMinutes(10);
    private const int MaxLockedAttempts = 6;
    private const int MaxPending = 5000;
    private const int Workers = 2;

    private readonly FileScanner _scanner;
    private readonly ThreatResponder _responder;
    private readonly SettingsStore _settings;
    private readonly UserFolderRegistry _userFolders;
    private readonly ILogger<RealtimeProtectionService> _logger;

    private readonly Dictionary<string, FileSystemWatcher> _watchers = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, Pending> _pending = new(StringComparer.OrdinalIgnoreCase);
    private readonly Channel<(string Path, int Attempt)> _queue = Channel.CreateBounded<(string, int)>(
        new BoundedChannelOptions(1000) { FullMode = BoundedChannelFullMode.DropOldest });

    private volatile bool _refreshRequested = true;
    private volatile bool _hadWatcherError;
    private HashSet<string> _extensions = new(StringComparer.OrdinalIgnoreCase);

    private sealed record Pending(DateTime LastEventUtc, DateTime NotBeforeUtc, int Attempt);

    public RealtimeProtectionService(FileScanner scanner, ThreatResponder responder, SettingsStore settings,
        UserFolderRegistry userFolders, ILogger<RealtimeProtectionService> logger)
    {
        _scanner = scanner;
        _responder = responder;
        _settings = settings;
        _userFolders = userFolders;
        _logger = logger;
    }

    public int WatchedFolderCount
    {
        get { lock (_watchers) return _watchers.Count; }
    }

    public bool IsHealthy => !_settings.Current.RealtimeEnabled || (WatchedFolderCount > 0 && !_hadWatcherError);

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        _settings.Changed += _ => _refreshRequested = true;
        _userFolders.Changed += () => _refreshRequested = true;

        var workers = Enumerable.Range(0, Workers).Select(_ => Task.Run(() => WorkerAsync(ct), ct)).ToArray();

        DateTime lastRefresh = DateTime.MinValue;
        using var timer = new PeriodicTimer(TimeSpan.FromMilliseconds(500));
        try
        {
            while (await timer.WaitForNextTickAsync(ct).ConfigureAwait(false))
            {
                if (_refreshRequested || DateTime.UtcNow - lastRefresh > PeriodicRefresh)
                {
                    _refreshRequested = false;
                    lastRefresh = DateTime.UtcNow;
                    RefreshWatchers();
                }
                DispatchDueFiles();
            }
        }
        catch (OperationCanceledException) { }
        finally
        {
            _queue.Writer.TryComplete();
            DisposeAllWatchers();
        }
        await Task.WhenAll(workers).ConfigureAwait(false);
    }

    // ---------------- Gestión de watchers ----------------

    private void RefreshWatchers()
    {
        var settings = _settings.Current;
        _extensions = new HashSet<string>(settings.RealtimeExtensions, StringComparer.OrdinalIgnoreCase);

        if (!settings.RealtimeEnabled)
        {
            if (WatchedFolderCount > 0)
                _logger.LogWarning("Protección en tiempo real DESACTIVADA por configuración");
            DisposeAllWatchers();
            return;
        }

        // Descargas de todos los perfiles (registro) + las que reporta la UI + carpetas configuradas (mods...)
        var desired = ScanTargets.GetUserProfiles().Select(ScanTargets.GetDownloadsFolder)
            .Concat(_userFolders.Downloads)
            .Concat(settings.WatchedFolders)
            .Where(Directory.Exists);
        var normalized = ScanTargets.Normalize(desired).ToHashSet(StringComparer.OrdinalIgnoreCase);

        lock (_watchers)
        {
            foreach (var folder in _watchers.Keys.Where(k => !normalized.Contains(k)).ToList())
            {
                _watchers[folder].Dispose();
                _watchers.Remove(folder);
                _logger.LogInformation("Tiempo real: deja de vigilar {Folder}", folder);
            }

            foreach (var folder in normalized.Where(f => !_watchers.ContainsKey(f)))
            {
                try
                {
                    var watcher = new FileSystemWatcher(folder)
                    {
                        IncludeSubdirectories = true,
                        NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size,
                        // Buffer del kernel para eventos: 32 KB es suficiente con el filtrado y debounce.
                        InternalBufferSize = 32 * 1024
                    };
                    watcher.Created += (_, e) => OnFileEvent(e.FullPath);
                    watcher.Changed += (_, e) => OnFileEvent(e.FullPath);
                    // Las descargas suelen llegar como .crdownload/.part y se RENOMBRAN al terminar.
                    watcher.Renamed += (_, e) => OnFileEvent(e.FullPath);
                    watcher.Error += (_, e) => OnWatcherError(folder, e.GetException());
                    watcher.EnableRaisingEvents = true;
                    _watchers[folder] = watcher;
                    _logger.LogInformation("Tiempo real: vigilando {Folder}", folder);
                }
                catch (Exception ex) when (ex is ArgumentException or IOException or UnauthorizedAccessException or PlatformNotSupportedException)
                {
                    _logger.LogWarning(ex, "No se pudo vigilar {Folder}", folder);
                }
            }
        }
        _hadWatcherError = false;
    }

    private void OnWatcherError(string folder, Exception ex)
    {
        // Desbordamiento del buffer o carpeta eliminada: recreamos el watcher en el siguiente ciclo.
        _logger.LogWarning(ex, "Error en el watcher de {Folder}; se recreará", folder);
        _hadWatcherError = true;
        lock (_watchers)
        {
            if (_watchers.Remove(folder, out var w))
                w.Dispose();
        }
        _refreshRequested = true;
    }

    private void DisposeAllWatchers()
    {
        lock (_watchers)
        {
            foreach (var w in _watchers.Values)
                w.Dispose();
            _watchers.Clear();
        }
    }

    // ---------------- Eventos y debounce ----------------

    private void OnFileEvent(string path)
    {
        // Este callback corre en hilos del pool del watcher: debe ser rapidísimo.
        if (!_extensions.Contains(Path.GetExtension(path)))
            return;
        if (_pending.Count >= MaxPending && !_pending.ContainsKey(path))
            return; // ráfaga enorme (p. ej. descomprimir miles de archivos): protegemos la memoria

        var now = DateTime.UtcNow;
        _pending.AddOrUpdate(path,
            _ => new Pending(now, now, 0),
            (_, old) => old with { LastEventUtc = now });
    }

    private void DispatchDueFiles()
    {
        var now = DateTime.UtcNow;
        foreach (var (path, p) in _pending)
        {
            if (now - p.LastEventUtc < SettleDelay || now < p.NotBeforeUtc)
                continue;
            if (_pending.TryRemove(path, out var removed))
                _queue.Writer.TryWrite((path, removed.Attempt));
        }
    }

    private async Task WorkerAsync(CancellationToken ct)
    {
        try
        {
            await foreach (var (path, attempt) in _queue.Reader.ReadAllAsync(ct).ConfigureAwait(false))
            {
                try
                {
                    var result = await _scanner.ScanAsync(path, FileScanContext.Realtime, ct).ConfigureAwait(false);

                    if (result.SkipReason == SkipReason.Locked && attempt < MaxLockedAttempts)
                    {
                        // Sigue en uso (descarga en curso, instalador...): lo reintentamos más tarde.
                        var retryAt = DateTime.UtcNow + LockedRetryDelay;
                        _pending.TryAdd(path, new Pending(DateTime.MinValue, retryAt, attempt + 1));
                        continue;
                    }

                    if (result.IsThreat)
                        await _responder.HandleAsync(result, null, ScanKind.Realtime, ct).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error en la protección en tiempo real con {Path}", path);
                }
            }
        }
        catch (OperationCanceledException) { }
    }
}
