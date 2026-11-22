using FragGuard.Core.Configuration;
using FragGuard.Core.Scanning;
using FragGuard.Shared.Models;

namespace FragGuard.Service.Protection;

/// <summary>
/// Memorias USB y discos extraíbles: cada 5 s comprueba las unidades extraíbles. Al conectar una nueva:
///  - Revisa autorun.inf (los gusanos de USB lo usan para ejecutarse solos).
///  - Analiza los ejecutables, scripts y comprimidos de los 3 primeros niveles (máx. 3.000 archivos).
///  - Avisa a la protección en tiempo real para que vigile la unidad mientras esté conectada.
/// </summary>
public sealed class RemovableDriveService : BackgroundService
{
    private const int MaxFiles = 3000;

    private readonly SettingsStore _settings;
    private readonly FileScanner _scanner;
    private readonly ThreatResponder _responder;
    private readonly EngineOptions _options;
    private readonly ILogger<RemovableDriveService> _logger;
    private HashSet<string> _drives = new(StringComparer.OrdinalIgnoreCase);

    public RemovableDriveService(SettingsStore settings, FileScanner scanner, ThreatResponder responder, EngineOptions options, ILogger<RemovableDriveService> logger)
    {
        _settings = settings;
        _scanner = scanner;
        _responder = responder;
        _options = options;
        _logger = logger;
    }

    /// <summary>Unidades extraíbles conectadas ahora (raíz, p. ej. "E:\").</summary>
    public IReadOnlyCollection<string> CurrentDrives => _drives;
    public bool IsActive => _settings.Current.RemovableDrivesEnabled;

    /// <summary>Se dispara al conectar o desconectar una unidad extraíble.</summary>
    public event Action? DrivesChanged;

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var now = DriveInfo.GetDrives()
                    .Where(d => d.DriveType == DriveType.Removable && d.IsReady)
                    .Select(d => d.RootDirectory.FullName)
                    .ToHashSet(StringComparer.OrdinalIgnoreCase);

                var added = now.Except(_drives).ToList();
                bool changed = added.Count > 0 || _drives.Except(now).Any();
                _drives = now;
                if (changed)
                    DrivesChanged?.Invoke();

                if (IsActive)
                    foreach (var drive in added)
                        await ScanDriveAsync(drive, ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
            catch (Exception ex) { _logger.LogDebug(ex, "Error comprobando unidades extraíbles"); }

            try { await Task.Delay(TimeSpan.FromSeconds(5), ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { break; }
        }
    }

    private async Task ScanDriveAsync(string root, CancellationToken ct)
    {
        _logger.LogInformation("Unidad extraíble conectada: {Drive}. Analizando…", root);
        CheckAutorunInf(root);

        int count = 0, threats = 0;
        var files = Directory.EnumerateFiles(root, "*", new EnumerationOptions
        {
            RecurseSubdirectories = true,
            MaxRecursionDepth = 3,
            IgnoreInaccessible = true,
            AttributesToSkip = FileAttributes.ReparsePoint
        });
        foreach (var file in files)
        {
            if (!_options.InterestingExtensions.Contains(Path.GetExtension(file)))
                continue;
            if (++count > MaxFiles)
                break;
            var result = await _scanner.ScanAsync(file, FileScanContext.ForScan(ScanKind.Realtime), ct).ConfigureAwait(false);
            if (result.IsThreat)
            {
                threats++;
                await _responder.HandleAsync(result, null, ScanKind.Realtime, ct).ConfigureAwait(false);
            }
        }
        _logger.LogInformation("Unidad {Drive} analizada: {Count} archivos, {Threats} amenazas", root, count, threats);
    }

    /// <summary>Un autorun.inf que lanza un programa es la firma clásica de los gusanos de USB.</summary>
    private void CheckAutorunInf(string root)
    {
        string inf = Path.Combine(root, "autorun.inf");
        if (!File.Exists(inf))
            return;
        string text;
        try { text = File.ReadAllText(inf); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return; }

        if (!System.Text.RegularExpressions.Regex.IsMatch(text, @"^\s*(open|shellexecute|shell\\[^=]*\\command)\s*=", System.Text.RegularExpressions.RegexOptions.IgnoreCase | System.Text.RegularExpressions.RegexOptions.Multiline))
            return;

        _responder.Report(new DetectionDto
        {
            ScanKind = ScanKind.Realtime,
            FilePath = inf,
            Verdict = FileVerdict.Suspicious,
            Action = ThreatAction.Warned,
            DetectedUtc = DateTime.UtcNow,
            Threats = new List<ThreatInfo>
            {
                new()
                {
                    Name = "FG.Heur.UsbAutorun",
                    Category = "Gusano USB",
                    Severity = ThreatSeverity.Medium,
                    Source = DetectionSource.Heuristic,
                    Description = "La memoria USB tiene un autorun.inf que intenta ejecutar un programa al conectarla: técnica clásica de los gusanos de USB."
                }
            }
        });
    }
}
