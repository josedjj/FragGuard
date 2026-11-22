using FragGuard.Core.Archives;
using FragGuard.Core.Configuration;
using FragGuard.Core.Data;
using FragGuard.Core.Detection;
using FragGuard.Core.Hashing;
using FragGuard.Core.IO;
using FragGuard.Shared.Models;
using Microsoft.Extensions.Logging;

namespace FragGuard.Core.Scanning;

/// <summary>Opciones de un análisis individual según quién lo pide.</summary>
public sealed class FileScanContext
{
    public ScanKind Kind { get; init; }

    /// <summary>
    /// Tiempo real: se puede esperar unos segundos por cuota de VirusTotal (es un único archivo recién descargado).
    /// Escaneos masivos: no se espera nunca (se consulta solo si hay cuota libre en ese momento).
    /// </summary>
    public bool WaitForVirusTotal { get; init; }

    /// <summary>Reintentar si el archivo está bloqueado (útil mientras el navegador termina la descarga).</summary>
    public bool RetryLocked { get; init; }

    public static FileScanContext Realtime => new() { Kind = ScanKind.Realtime, WaitForVirusTotal = true, RetryLocked = true };
    public static FileScanContext ForScan(ScanKind kind) => new() { Kind = kind };
}

/// <summary>Resultado del análisis de un archivo.</summary>
public sealed class FileScanResult
{
    public string Path { get; init; } = "";
    public string? Sha256 { get; set; }
    public long SizeBytes { get; set; }
    public FileVerdict Verdict { get; set; }
    public List<ThreatInfo> Threats { get; } = new();
    public SkipReason SkipReason { get; set; }
    public string? Error { get; set; }
    public bool FromCache { get; set; }

    public bool IsThreat => Verdict is FileVerdict.Malicious or FileVerdict.Suspicious;
}

/// <summary>
/// Pipeline de análisis de UN archivo:
///   exclusiones → tamaño → apertura segura → SHA-256 → lista de permitidos → caché →
///   YARA → contenido de comprimidos → VirusTotal → heurística de nombre → veredicto.
///
/// Nunca lanza excepciones (salvo cancelación): cualquier fallo se refleja en el resultado
/// para que un archivo problemático no detenga el escaneo ni tumbe el servicio.
/// </summary>
public sealed class FileScanner
{
    private readonly IYaraEngine _yara;
    private readonly ArchiveScanner _archives;
    private readonly VirusTotalClient _vt;
    private readonly HashCacheRepository _cache;
    private readonly AllowListRepository _allowList;
    private readonly SettingsStore _settings;
    private readonly EngineOptions _options;
    private readonly FragGuardPaths _paths;
    private readonly ILogger<FileScanner> _logger;

    public FileScanner(IYaraEngine yara, ArchiveScanner archives, VirusTotalClient vt, HashCacheRepository cache,
        AllowListRepository allowList, SettingsStore settings, EngineOptions options, FragGuardPaths paths, ILogger<FileScanner> logger)
    {
        _yara = yara;
        _archives = archives;
        _vt = vt;
        _cache = cache;
        _allowList = allowList;
        _settings = settings;
        _options = options;
        _paths = paths;
        _logger = logger;
    }

    public async Task<FileScanResult> ScanAsync(string path, FileScanContext context, CancellationToken ct)
    {
        var result = new FileScanResult { Path = path };
        try
        {
            await ScanCoreAsync(result, context, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            // Red de seguridad final: un archivo raro nunca debe tumbar el servicio.
            _logger.LogWarning(ex, "Error analizando {Path}", path);
            result.Verdict = FileVerdict.Error;
            result.Error = ex.Message;
        }
        return result;
    }

    private async Task ScanCoreAsync(FileScanResult result, FileScanContext context, CancellationToken ct)
    {
        var settings = _settings.Current;
        string path = result.Path;

        // Nunca analizamos nuestra propia carpeta de datos (la cuarentena contiene malware cifrado).
        if (SafeFile.IsUnder(path, settings.Exclusions) || SafeFile.IsUnder(path, [_paths.DataRoot]))
        {
            Skip(result, SkipReason.Excluded);
            return;
        }

        var info = new FileInfo(path);
        if (!info.Exists)
        {
            Skip(result, SkipReason.NotFound);
            return;
        }
        result.SizeBytes = info.Length;

        // La heurística de nombre no necesita leer el archivo: se aplica siempre.
        ThreatInfo? lure = CheatLureAnalyzer.Analyze(path);

        long maxBytes = settings.MaxFileSizeMb * 1024L * 1024L;
        if (info.Length > maxBytes)
        {
            Skip(result, SkipReason.TooLarge, lure);
            return;
        }

        var open = await SafeFile.OpenReadAsync(path, context.RetryLocked ? _options.LockedRetryCount : 0, _options.LockedRetryDelay, ct).ConfigureAwait(false);
        if (!open.Success)
        {
            Skip(result, open.Reason, lure);
            result.Error = open.Error;
            return;
        }

        byte[]? buffer = null;
        try
        {
            await using var stream = open.Stream!;
            bool inMemory = stream.Length <= _options.InMemoryScanMaxBytes;
            int length = 0;

            // 1) Hash. Archivos pequeños: una sola lectura a memoria que sirve para hash + YARA + comprimidos.
            if (inMemory)
            {
                buffer = ScanBuffers.Rent((int)stream.Length);
                length = await SafeFile.ReadFullyAsync(stream, buffer, (int)stream.Length, ct).ConfigureAwait(false);
                result.Sha256 = FileHasher.HashBuffer(buffer, length);
            }
            else
            {
                result.Sha256 = await FileHasher.HashStreamAsync(stream, ct).ConfigureAwait(false);
            }

            // 2) Lista de permitidos (archivos que el usuario restauró de la cuarentena).
            if (_allowList.Contains(result.Sha256))
            {
                result.Verdict = FileVerdict.Clean;
                return;
            }

            // 3) Caché por hash.
            var cached = _cache.Get(result.Sha256, _yara.RulesVersion, _options.HashCacheTtl);
            List<ThreatInfo> contentThreats;
            bool vtChecked;
            bool cacheDirty;
            if (cached is not null)
            {
                contentThreats = cached.Threats;
                vtChecked = cached.VtChecked;
                result.FromCache = true;
                cacheDirty = false;
            }
            else
            {
                // 4) YARA + comprimidos.
                contentThreats = new List<ThreatInfo>();
                contentThreats.AddRange(ScanWithYara(path, buffer, length));

                if (_archives.IsArchive(path) && !HasMalicious(contentThreats))
                {
                    if (inMemory)
                    {
                        using var ms = new MemoryStream(buffer!, 0, length, writable: false);
                        contentThreats.AddRange(_archives.Scan(ms, Path.GetFileName(path), ct).Threats);
                    }
                    else
                    {
                        stream.Position = 0;
                        contentThreats.AddRange(_archives.Scan(stream, Path.GetFileName(path), ct).Threats);
                    }
                }
                vtChecked = false;
                cacheDirty = true;
            }

            // 5) VirusTotal: solo si lo local no encontró nada grave, es un tipo relevante y no se consultó ya.
            if (!vtChecked && !HasMalicious(contentThreats) && ShouldQueryVirusTotal(path, settings))
            {
                var vt = await _vt.LookupAsync(result.Sha256, context.WaitForVirusTotal ? TimeSpan.FromSeconds(15) : TimeSpan.Zero, ct).ConfigureAwait(false);
                if (vt.Status is VtStatus.Found or VtStatus.Unknown)
                {
                    vtChecked = true;
                    cacheDirty = true;
                    if (MapVirusTotal(vt) is { } vtThreat)
                        contentThreats.Add(vtThreat);
                }
            }

            if (cacheDirty)
                _cache.Put(result.Sha256, ComputeVerdict(contentThreats), contentThreats, _yara.RulesVersion, vtChecked);

            result.Threats.AddRange(contentThreats);
            if (lure is not null)
                result.Threats.Add(lure);
            result.Verdict = ComputeVerdict(result.Threats);
        }
        finally
        {
            if (buffer is not null)
                ScanBuffers.Return(buffer);
        }
    }

    private IReadOnlyList<ThreatInfo> ScanWithYara(string path, byte[]? buffer, int length)
    {
        try
        {
            // En memoria si ya lo tenemos leído; si es grande, YARA mapea el archivo directamente.
            return buffer is not null ? _yara.ScanMemory(buffer, length) : _yara.ScanFile(path);
        }
        catch (Exception ex)
        {
            // Errores de libyara (archivo bloqueado al mapear, timeout...): seguimos con el resto del pipeline.
            _logger.LogDebug(ex, "YARA no pudo analizar {Path}", path);
            return Array.Empty<ThreatInfo>();
        }
    }

    private bool ShouldQueryVirusTotal(string path, FragGuardSettings settings) =>
        settings.VirusTotalEnabled && _vt.IsConfigured && _options.VirusTotalExtensions.Contains(Path.GetExtension(path));

    /// <summary>
    /// Umbrales de VirusTotal: ≥3 motores "malicious" = malicioso (≥10 crítico); 1-2 o ≥3 "suspicious" = sospechoso.
    /// Un solo motor suele ser falso positivo, por eso no se pone en cuarentena con 1.
    /// </summary>
    internal static ThreatInfo? MapVirusTotal(VtLookupResult vt)
    {
        if (vt.Status != VtStatus.Found)
            return null;

        string label = string.IsNullOrWhiteSpace(vt.ThreatLabel) ? "Generic" : vt.ThreatLabel!;
        if (vt.Malicious >= 3)
        {
            return new ThreatInfo
            {
                Name = $"VT.{label}",
                Category = "VirusTotal",
                Severity = vt.Malicious >= 10 ? ThreatSeverity.Critical : ThreatSeverity.High,
                Source = DetectionSource.VirusTotal,
                Description = $"{vt.Malicious} de {vt.TotalEngines} motores de VirusTotal lo marcan como malicioso."
            };
        }
        if (vt.Malicious >= 1 || vt.Suspicious >= 3)
        {
            return new ThreatInfo
            {
                Name = $"VT.Suspicious.{label}",
                Category = "VirusTotal",
                Severity = ThreatSeverity.Medium,
                Source = DetectionSource.VirusTotal,
                Description = $"{vt.Malicious} malicioso(s) y {vt.Suspicious} sospechoso(s) de {vt.TotalEngines} motores en VirusTotal."
            };
        }
        return null;
    }

    /// <summary>Malicioso si hay alguna amenaza High/Critical de origen YARA o VirusTotal; sospechoso si hay cualquier otra.</summary>
    internal static FileVerdict ComputeVerdict(IEnumerable<ThreatInfo> threats)
    {
        var list = threats as ICollection<ThreatInfo> ?? threats.ToList();
        if (list.Count == 0)
            return FileVerdict.Clean;
        return HasMalicious(list) ? FileVerdict.Malicious : FileVerdict.Suspicious;
    }

    private static bool HasMalicious(IEnumerable<ThreatInfo> threats) =>
        threats.Any(t => t.Severity >= ThreatSeverity.High && t.Source != DetectionSource.Heuristic);

    private static void Skip(FileScanResult result, SkipReason reason, ThreatInfo? lure = null)
    {
        result.SkipReason = reason;
        if (lure is not null)
        {
            // Aunque no se pudo leer, el nombre ya es sospechoso: avisamos igualmente.
            result.Threats.Add(lure);
            result.Verdict = FileVerdict.Suspicious;
        }
        else
        {
            result.Verdict = FileVerdict.Skipped;
        }
    }
}
