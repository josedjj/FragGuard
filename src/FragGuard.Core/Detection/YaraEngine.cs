using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using dnYara;
using dnYara.Exceptions;
using dnYara.Interop;
using FragGuard.Shared.Models;
using Microsoft.Extensions.Logging;

namespace FragGuard.Core.Detection;

/// <summary>
/// Implementación de <see cref="IYaraEngine"/> sobre libyara 4.x.
///
/// - La COMPILACIÓN de reglas usa dnYara (Compiler).
/// - El ESCANEO llama directamente a libyara (yr_rules_scan_mem / yr_rules_scan_file) a través de
///   dnYara.Interop. Motivo: Scanner.ScanMemory de dnYara 2.1 copia cada buffer con Marshal.AllocHGlobal
///   y NUNCA lo libera (fuga de memoria nativa igual al tamaño de cada archivo analizado; verificado con
///   MemoryTests). Aquí fijamos (pin) el array gestionado y se lo pasamos a YARA sin copias.
///
/// Concurrencia: libyara permite escanear en paralelo con las mismas reglas compiladas.
/// Un ReaderWriterLockSlim impide que una recarga de reglas libere la memoria nativa mientras
/// otro hilo la está usando (eso provocaría un crash del proceso).
/// </summary>
public sealed class YaraEngine : IYaraEngine
{
    // libyara tiene estado GLOBAL (yr_initialize / yr_finalize). Si cada instancia creara y destruyera
    // su propio contexto, un Dispose en un hilo rompería la compilación/escaneo de otro (AccessViolation).
    // Por eso el contexto es único por proceso y vive hasta que el proceso termina.
    private static readonly Lazy<YaraContext> SharedContext = new(() => new YaraContext(), LazyThreadSafetyMode.ExecutionAndPublication);

    // El compilador de YARA no es seguro para usarse desde varios hilos a la vez: serializamos las compilaciones.
    private static readonly object CompileLock = new();

    // Callback nativo único y estático: así el GC nunca lo recolecta mientras YARA lo está llamando.
    private static readonly YR_CALLBACK_FUNC Callback = OnYaraMessage;

    /// <summary>Tiempo máximo por archivo (segundos). Protege de reglas/archivos patológicos.</summary>
    private const int ScanTimeoutSeconds = 30;

    private readonly ILogger<YaraEngine> _logger;
    private readonly ReaderWriterLockSlim _lock = new();
    private IntPtr _rules;   // YR_RULES* propiedad de esta instancia (se libera con yr_rules_destroy)
    private bool _disposed;

    public YaraEngine(ILogger<YaraEngine> logger)
    {
        _logger = logger;
        _ = SharedContext.Value;
    }

    public int RuleCount { get; private set; }
    public string RulesVersion { get; private set; } = "none";

    // =====================================================================
    //  Carga / compilación de reglas
    // =====================================================================

    public void LoadRules(string rulesDirectory)
    {
        if (!Directory.Exists(rulesDirectory))
        {
            _logger.LogWarning("Carpeta de reglas YARA no encontrada: {Dir}", rulesDirectory);
            SwapRules(IntPtr.Zero, 0, "none");
            return;
        }

        var files = Directory.EnumerateFiles(rulesDirectory, "*.*", SearchOption.AllDirectories)
            .Where(f => f.EndsWith(".yar", StringComparison.OrdinalIgnoreCase) || f.EndsWith(".yara", StringComparison.OrdinalIgnoreCase))
            .OrderBy(f => f, StringComparer.OrdinalIgnoreCase)
            .ToList();

        IntPtr compiled;
        int count;
        var valid = new List<string>();

        lock (CompileLock)
        {
            (compiled, count) = CompileValidRules(files, valid);
        }

        SwapRules(compiled, count, ComputeVersion(valid));
        _logger.LogInformation("Reglas YARA cargadas: {Count} reglas de {Files} archivos (versión {Version})", count, valid.Count, RulesVersion);
    }

    private (IntPtr Rules, int Count) CompileValidRules(List<string> files, List<string> valid)
    {
        // 1) Validamos cada archivo por separado: una regla rota no debe impedir cargar las demás.
        foreach (var file in files)
        {
            try
            {
                using var probe = new Compiler();
                probe.AddRuleFile(file);
                using var _ = probe.Compile();
                valid.Add(file);
            }
            catch (CompilationException ex)
            {
                _logger.LogError("Regla YARA inválida, se omite {File}: {Errors}", file, string.Join(" | ", ex.Errors));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error compilando regla YARA {File}", file);
            }
        }

        // 2) Compilamos todas las válidas juntas (un único conjunto de reglas = un único escaneo por archivo).
        if (valid.Count == 0)
            return (IntPtr.Zero, 0);

        using var compiler = new Compiler();
        foreach (var file in valid)
            compiler.AddRuleFile(file);
        using var rules = compiler.Compile();
        int count = (int)rules.RuleCount;
        // Release() nos transfiere la propiedad del puntero nativo (y deja el del objeto a cero,
        // así su Dispose/finalizador ya no lo libera). A partir de aquí lo gestionamos nosotros.
        return (rules.Release(), count);
    }

    private void SwapRules(IntPtr rules, int count, string version)
    {
        _lock.EnterWriteLock();
        try
        {
            if (_rules != IntPtr.Zero)
                Methods.yr_rules_destroy(_rules);
            _rules = rules;
            RuleCount = count;
            RulesVersion = version;
        }
        finally
        {
            _lock.ExitWriteLock();
        }
    }

    // =====================================================================
    //  Escaneo
    // =====================================================================

    public IReadOnlyList<ThreatInfo> ScanFile(string path)
    {
        return Scan(results =>
        {
            var error = Methods.yr_rules_scan_file(_rules, path, 0, Callback, results, ScanTimeoutSeconds);
            return error;
        });
    }

    public IReadOnlyList<ThreatInfo> ScanMemory(byte[] buffer, int length)
    {
        if (length <= 0)
            return Array.Empty<ThreatInfo>();
        if (length > buffer.Length)
            throw new ArgumentOutOfRangeException(nameof(length));

        // Fijamos el array mientras YARA lo lee: sin copias y sin memoria nativa que liberar.
        var pin = GCHandle.Alloc(buffer, GCHandleType.Pinned);
        try
        {
            IntPtr data = pin.AddrOfPinnedObject();
            return Scan(results => Methods.yr_rules_scan_mem(_rules, data, (ulong)length, 0, Callback, results, ScanTimeoutSeconds));
        }
        finally
        {
            pin.Free();
        }
    }

    /// <summary>Ejecuta un escaneo con las reglas actuales bajo el lock de lectura y recoge las coincidencias.</summary>
    private IReadOnlyList<ThreatInfo> Scan(Func<IntPtr, YARA_ERROR> scan)
    {
        _lock.EnterReadLock();
        try
        {
            if (_rules == IntPtr.Zero)
                return Array.Empty<ThreatInfo>();

            var matches = new List<ThreatInfo>();
            var handle = GCHandle.Alloc(matches); // user_data del callback → nuestra lista
            try
            {
                var error = scan(GCHandle.ToIntPtr(handle));
                if (error == YARA_ERROR.ERROR_SCAN_TIMEOUT)
                {
                    _logger.LogWarning("Escaneo YARA agotó el tiempo ({Seconds} s); se usan las coincidencias encontradas hasta entonces", ScanTimeoutSeconds);
                }
                else if (error != YARA_ERROR.SUCCESS)
                {
                    ErrorUtility.ThrowOnError(error); // lanza YaraException (archivo bloqueado, etc.)
                }
                return matches;
            }
            finally
            {
                handle.Free();
            }
        }
        finally
        {
            _lock.ExitReadLock();
        }
    }

    /// <summary>
    /// Callback de libyara. Para cada regla que coincide, lee su identificador y metadatos
    /// (description, severity, category) y los añade a la lista pasada en user_data.
    /// </summary>
    private static YR_CALLBACK_RESULT OnYaraMessage(IntPtr context, int message, IntPtr messageData, IntPtr userData)
    {
        if (message == (int)YR_CALLBACK_MESSAGE.RuleMatching && messageData != IntPtr.Zero)
        {
            try
            {
                var list = (List<ThreatInfo>)GCHandle.FromIntPtr(userData).Target!;
                var rule = new Rule(Marshal.PtrToStructure<YR_RULE>(messageData));
                list.Add(new ThreatInfo
                {
                    Name = rule.Identifier,
                    Description = GetMeta(rule.Metas, "description") ?? "",
                    Category = GetMeta(rule.Metas, "category") ?? "Generic",
                    Severity = ParseSeverity(GetMeta(rule.Metas, "severity")),
                    Source = DetectionSource.Yara
                });
            }
            catch
            {
                // Nunca propagar excepciones a código nativo.
            }
        }
        return YR_CALLBACK_RESULT.Continue;
    }

    private static string? GetMeta(IDictionary<string, object>? metas, string key) =>
        metas is not null && metas.TryGetValue(key, out var value) ? value?.ToString() : null;

    internal static ThreatSeverity ParseSeverity(string? value) => value?.Trim().ToLowerInvariant() switch
    {
        "critical" => ThreatSeverity.Critical,
        "high" => ThreatSeverity.High,
        "medium" => ThreatSeverity.Medium,
        "low" => ThreatSeverity.Low,
        _ => ThreatSeverity.Medium // sin metadato: tratamos como sospechoso, no como malicioso
    };

    private static string ComputeVersion(List<string> files)
    {
        if (files.Count == 0)
            return "none";
        using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        foreach (var f in files)
        {
            sha.AppendData(Encoding.UTF8.GetBytes(Path.GetFileName(f)));
            sha.AppendData(File.ReadAllBytes(f));
        }
        return Convert.ToHexString(sha.GetHashAndReset())[..16];
    }

    public void Dispose()
    {
        if (_disposed)
            return;
        _disposed = true;
        SwapRules(IntPtr.Zero, 0, "none");
        _lock.Dispose();
        // El YaraContext compartido no se libera: lo hace el sistema al terminar el proceso.
    }
}
