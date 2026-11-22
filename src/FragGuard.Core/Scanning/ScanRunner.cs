using System.Diagnostics;
using System.Threading.Channels;
using FragGuard.Core.Configuration;
using FragGuard.Core.Data;
using FragGuard.Core.IO;
using FragGuard.Shared.Models;
using Microsoft.Extensions.Logging;

namespace FragGuard.Core.Scanning;

/// <summary>Un escaneo en curso (manual, programado o personalizado).</summary>
public sealed class ScanJob
{
    private long _scanned, _skipped, _threats, _errors;
    private readonly Stopwatch _clock = new();

    public ScanJob(ScanKind kind, IReadOnlyList<string> roots, bool onlyInterestingExtensions)
    {
        Kind = kind;
        Roots = roots;
        OnlyInterestingExtensions = onlyInterestingExtensions;
    }

    public string Id { get; } = Guid.NewGuid().ToString("N");
    public ScanKind Kind { get; }
    public IReadOnlyList<string> Roots { get; }
    public bool OnlyInterestingExtensions { get; }
    public DateTime StartedUtc { get; private set; }
    public volatile ScanState State = ScanState.Idle;
    public volatile string? CurrentFile;

    /// <summary>Pausa específica de este escaneo (usuario o modo juego).</summary>
    public PauseGate Gate { get; } = new();

    internal void Start()
    {
        StartedUtc = DateTime.UtcNow;
        _clock.Start();
        State = ScanState.Running;
    }

    internal void CountScanned() => Interlocked.Increment(ref _scanned);
    internal void CountSkipped() => Interlocked.Increment(ref _skipped);
    internal void CountThreat() => Interlocked.Increment(ref _threats);
    internal void CountError() => Interlocked.Increment(ref _errors);

    public ScanProgressDto GetProgress() => new()
    {
        ScanId = Id,
        Kind = Kind,
        State = Gate.IsPaused && State == ScanState.Running ? ScanState.Paused : State,
        FilesScanned = Interlocked.Read(ref _scanned),
        FilesSkipped = Interlocked.Read(ref _skipped),
        ThreatsFound = Interlocked.Read(ref _threats),
        CurrentFile = CurrentFile,
        StartedUtc = StartedUtc,
        ElapsedMs = _clock.ElapsedMilliseconds
    };

    public ScanSummaryDto GetSummary() => new()
    {
        ScanId = Id,
        Kind = Kind,
        State = State,
        StartedUtc = StartedUtc,
        FinishedUtc = State is ScanState.Completed or ScanState.Cancelled or ScanState.Failed ? DateTime.UtcNow : null,
        FilesScanned = Interlocked.Read(ref _scanned),
        FilesSkipped = Interlocked.Read(ref _skipped),
        ThreatsFound = Interlocked.Read(ref _threats),
        Errors = Interlocked.Read(ref _errors)
    };
}

/// <summary>
/// Ejecuta un <see cref="ScanJob"/>: un productor enumera archivos y N consumidores los analizan
/// (canal acotado para no acumular millones de rutas en memoria durante un escaneo completo).
/// </summary>
public sealed class ScanRunner
{
    private readonly FileScanner _scanner;
    private readonly ThreatResponder _responder;
    private readonly ScanHistoryRepository _history;
    private readonly SettingsStore _settings;
    private readonly EngineOptions _options;
    private readonly FragGuardPaths _paths;
    private readonly ScanThrottle _throttle;
    private readonly ILogger<ScanRunner> _logger;

    public ScanRunner(FileScanner scanner, ThreatResponder responder, ScanHistoryRepository history, SettingsStore settings,
        EngineOptions options, FragGuardPaths paths, ScanThrottle throttle, ILogger<ScanRunner> logger)
    {
        _scanner = scanner;
        _responder = responder;
        _history = history;
        _settings = settings;
        _options = options;
        _paths = paths;
        _throttle = throttle;
        _logger = logger;
    }

    public async Task<ScanSummaryDto> RunAsync(ScanJob job, Action<ScanProgressDto>? onProgress, CancellationToken ct)
    {
        job.Start();
        SafeHistory(job.GetSummary());
        _logger.LogInformation("Escaneo {Kind} {Id} iniciado sobre {Count} raíz/raíces", job.Kind, job.Id, job.Roots.Count);

        var channel = Channel.CreateBounded<string>(new BoundedChannelOptions(512)
        {
            SingleWriter = true,
            FullMode = BoundedChannelFullMode.Wait
        });

        // Progreso periódico (cada 500 ms) en lugar de un evento por archivo: menos tráfico por el pipe.
        using var progressCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var progressTask = onProgress is null ? Task.CompletedTask : ReportProgressAsync(job, onProgress, progressCts.Token);

        try
        {
            var producer = Task.Run(() => ProduceAsync(job, channel.Writer, ct), ct);
            var consumers = Enumerable.Range(0, _options.MaxScanParallelism)
                .Select(_ => Task.Run(() => ConsumeAsync(job, channel.Reader, ct), ct))
                .ToArray();

            await producer.ConfigureAwait(false);
            await Task.WhenAll(consumers).ConfigureAwait(false);
            job.State = ScanState.Completed;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            job.State = ScanState.Cancelled;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "El escaneo {Id} falló", job.Id);
            job.State = ScanState.Failed;
        }
        finally
        {
            progressCts.Cancel();
            try { await progressTask.ConfigureAwait(false); } catch (OperationCanceledException) { }
            job.CurrentFile = null;
        }

        var summary = job.GetSummary();
        SafeHistory(summary);
        onProgress?.Invoke(job.GetProgress());
        _logger.LogInformation("Escaneo {Id} terminado: {State}, {Files} archivos, {Threats} amenazas, {Skipped} omitidos",
            job.Id, summary.State, summary.FilesScanned, summary.ThreatsFound, summary.FilesSkipped);
        return summary;
    }

    private async Task ProduceAsync(ScanJob job, ChannelWriter<string> writer, CancellationToken ct)
    {
        try
        {
            var settings = _settings.Current;
            var excluded = settings.Exclusions
                .Concat(ScanTargets.GetDefaultExcludedDirectories())
                .Append(_paths.DataRoot)
                .ToList();

            var enumeration = new EnumerationOptions
            {
                RecurseSubdirectories = true,
                IgnoreInaccessible = true,           // carpetas sin permiso: se saltan sin excepción
                AttributesToSkip = FileAttributes.ReparsePoint | FileAttributes.Offline, // evita bucles de junctions y archivos solo-nube
                ReturnSpecialDirectories = false
            };

            foreach (string root in job.Roots)
            {
                ct.ThrowIfCancellationRequested();

                if (File.Exists(root))
                {
                    await writer.WriteAsync(root, ct).ConfigureAwait(false);
                    continue;
                }
                if (!Directory.Exists(root))
                    continue;

                IEnumerator<string> files;
                try
                {
                    files = Directory.EnumerateFiles(root, "*", enumeration).GetEnumerator();
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    _logger.LogDebug("No se puede enumerar {Root}: {Error}", root, ex.Message);
                    continue;
                }

                using (files)
                {
                    while (true)
                    {
                        string file;
                        try
                        {
                            if (!files.MoveNext())
                                break;
                            file = files.Current;
                        }
                        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                        {
                            // Un error a mitad de la enumeración (disco desconectado, etc.): pasamos a la siguiente raíz.
                            _logger.LogDebug("Enumeración interrumpida en {Root}: {Error}", root, ex.Message);
                            break;
                        }

                        if (SafeFile.IsUnder(file, excluded))
                            continue;
                        if (job.OnlyInterestingExtensions && !_options.InterestingExtensions.Contains(Path.GetExtension(file)))
                            continue;

                        await writer.WriteAsync(file, ct).ConfigureAwait(false);
                    }
                }
            }
        }
        finally
        {
            writer.TryComplete();
        }
    }

    private async Task ConsumeAsync(ScanJob job, ChannelReader<string> reader, CancellationToken ct)
    {
        var context = FileScanContext.ForScan(job.Kind);
        await foreach (string path in reader.ReadAllAsync(ct).ConfigureAwait(false))
        {
            // Pausa (usuario o modo juego) y modo bajo impacto.
            await job.Gate.WaitIfPausedAsync(ct).ConfigureAwait(false);
            using var slot = await _throttle.EnterAsync(ct).ConfigureAwait(false);

            job.CurrentFile = path;
            var result = await _scanner.ScanAsync(path, context, ct).ConfigureAwait(false);

            switch (result.Verdict)
            {
                case FileVerdict.Skipped: job.CountSkipped(); break;
                case FileVerdict.Error: job.CountError(); job.CountSkipped(); break;
                default: job.CountScanned(); break;
            }

            if (result.IsThreat)
            {
                job.CountThreat();
                try
                {
                    await _responder.HandleAsync(result, job.Id, job.Kind, ct).ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    // Si un consumidor muriera, el productor se quedaría bloqueado con el canal lleno.
                    _logger.LogError(ex, "Error respondiendo a la amenaza en {Path}", path);
                    job.CountError();
                }
            }
        }
    }

    private static async Task ReportProgressAsync(ScanJob job, Action<ScanProgressDto> onProgress, CancellationToken ct)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromMilliseconds(500));
        while (await timer.WaitForNextTickAsync(ct).ConfigureAwait(false))
        {
            try { onProgress(job.GetProgress()); }
            catch { /* un suscriptor roto no debe detener el escaneo */ }
        }
    }

    private void SafeHistory(ScanSummaryDto summary)
    {
        try { _history.Upsert(summary); }
        catch (Exception ex) { _logger.LogWarning(ex, "No se pudo guardar el historial del escaneo {Id}", summary.ScanId); }
    }
}
