using System.Diagnostics;
using FragGuard.Core.Detection;
using FragGuard.Core.Scanning;
using FragGuard.Shared.Models;
using Xunit.Abstractions;

namespace FragGuard.Core.Tests;

/// <summary>
/// Diagnóstico de memoria: el servicio debe volver a su consumo de reposo después de analizar archivos grandes.
/// Separa memoria gestionada (GC de .NET) de memoria nativa (libyara) para localizar fugas.
/// </summary>
[Collection("Memory")] // no en paralelo con otros tests: medimos memoria del proceso
public class MemoryTests : IDisposable
{
    private readonly TestEnvironment _env = new();
    private readonly ITestOutputHelper _out;

    public MemoryTests(ITestOutputHelper output) => _out = output;

    private static (double PrivateMb, double GcCommittedMb) Measure()
    {
        GC.Collect(GC.MaxGeneration, GCCollectionMode.Aggressive, blocking: true, compacting: true);
        GC.WaitForPendingFinalizers();
        using var p = Process.GetCurrentProcess();
        return (p.PrivateMemorySize64 / 1048576.0, GC.GetGCMemoryInfo().TotalCommittedBytes / 1048576.0);
    }

    [Fact]
    public void YaraScanMemory_DoesNotLeakNativeMemory()
    {
        var yara = _env.Get<IYaraEngine>();
        var buffer = new byte[8 * 1024 * 1024];
        new Random(1).NextBytes(buffer);
        yara.ScanMemory(buffer, buffer.Length); // calentamiento

        var before = Measure();
        for (int i = 0; i < 40; i++)
            yara.ScanMemory(buffer, buffer.Length); // 320 MB analizados en total
        var after = Measure();

        double nativeGrowth = (after.PrivateMb - after.GcCommittedMb) - (before.PrivateMb - before.GcCommittedMb);
        _out.WriteLine($"Antes: privada {before.PrivateMb:N1} MB (GC {before.GcCommittedMb:N1}) | Después: privada {after.PrivateMb:N1} MB (GC {after.GcCommittedMb:N1}) | crecimiento nativo {nativeGrowth:N1} MB");
        Assert.True(nativeGrowth < 40, $"Posible fuga nativa en YARA: +{nativeGrowth:N1} MB");
    }

    [Fact]
    public async Task ScanningLargeFiles_ReturnsMemoryAfterwards()
    {
        // 20 archivos de 12 MB (entran en el camino "en memoria" de 16 MB)
        var rnd = new Random(2);
        var data = new byte[12 * 1024 * 1024];
        for (int i = 0; i < 20; i++)
        {
            rnd.NextBytes(data);
            File.WriteAllBytes(Path.Combine(_env.WorkDir, $"big{i}.bin"), data);
        }

        var before = Measure();
        var scanner = _env.Get<FileScanner>();
        foreach (var f in Directory.GetFiles(_env.WorkDir))
            await scanner.ScanAsync(f, FileScanContext.ForScan(ScanKind.Custom), default);
        var after = Measure();

        _out.WriteLine($"Antes: privada {before.PrivateMb:N1} MB (GC {before.GcCommittedMb:N1}) | Después: privada {after.PrivateMb:N1} MB (GC {after.GcCommittedMb:N1})");
        Assert.True(after.PrivateMb - before.PrivateMb < 60, $"La memoria no vuelve tras escanear: +{after.PrivateMb - before.PrivateMb:N1} MB");
    }

    public void Dispose() => _env.Dispose();
}
