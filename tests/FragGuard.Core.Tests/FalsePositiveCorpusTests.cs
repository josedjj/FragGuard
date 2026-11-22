using FragGuard.Core.Scanning;
using FragGuard.Shared.Models;
using Xunit.Abstractions;

namespace FragGuard.Core.Tests;

/// <summary>
/// Corpus de software LIMPIO: pasa el motor completo (YARA + comprimidos + heurística + política de firmas)
/// por miles de ejecutables reales del equipo y exige CERO detecciones maliciosas.
///
/// Es lento, así que solo se ejecuta si FG_FP_CORPUS=1:
///   $env:FG_FP_CORPUS = 1; dotnet test --filter "FullyQualifiedName~FalsePositiveCorpus"
/// Conviene ejecutarlo antes de publicar reglas nuevas.
/// </summary>
public class FalsePositiveCorpusTests : IDisposable
{
    private const int MaxFiles = 6000;
    private readonly TestEnvironment _env = new();
    private readonly ITestOutputHelper _out;

    public FalsePositiveCorpusTests(ITestOutputHelper output) => _out = output;

    [Fact]
    public async Task RealSoftwareOnThisMachine_HasNoMaliciousDetections()
    {
        if (Environment.GetEnvironmentVariable("FG_FP_CORPUS") != "1")
            return; // desactivado por defecto

        var roots = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs")
        }.Where(Directory.Exists);

        var extensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { ".exe", ".dll", ".ps1", ".bat", ".cmd", ".js", ".zip" };
        var files = roots.SelectMany(r => Directory.EnumerateFiles(r, "*", new EnumerationOptions
            {
                RecurseSubdirectories = true, IgnoreInaccessible = true, AttributesToSkip = FileAttributes.ReparsePoint, MaxRecursionDepth = 6
            }))
            .Where(f => extensions.Contains(Path.GetExtension(f)))
            .Where(f => { try { return new FileInfo(f).Length < 50L * 1024 * 1024; } catch { return false; } })
            .Take(MaxFiles)
            .ToList();

        var scanner = _env.Get<FileScanner>();
        int scanned = 0, suspicious = 0;
        var malicious = new List<string>();
        var sw = System.Diagnostics.Stopwatch.StartNew();

        foreach (var f in files)
        {
            var r = await scanner.ScanAsync(f, FileScanContext.ForScan(ScanKind.Custom), default);
            if (r.Verdict is FileVerdict.Skipped or FileVerdict.Error) continue;
            scanned++;
            if (r.Verdict == FileVerdict.Malicious)
                malicious.Add($"{f} → {string.Join(", ", r.Threats.Select(t => t.Name))}");
            else if (r.Verdict == FileVerdict.Suspicious)
            {
                suspicious++;
                _out.WriteLine($"[sospechoso] {f} → {string.Join(", ", r.Threats.Select(t => t.Name))}");
            }
        }

        _out.WriteLine($"Corpus limpio: {scanned} archivos analizados en {sw.Elapsed.TotalSeconds:0} s · {malicious.Count} maliciosos · {suspicious} sospechosos");
        foreach (var m in malicious)
            _out.WriteLine("[FALSO POSITIVO MALICIOSO] " + m);
        Assert.Empty(malicious);
    }

    public void Dispose() => _env.Dispose();
}
