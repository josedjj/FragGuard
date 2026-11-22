using System.IO.Compression;
using FragGuard.Core.Quarantine;
using FragGuard.Core.Scanning;
using FragGuard.Shared.Models;

namespace FragGuard.Core.Tests;

public class FileScannerTests : IDisposable
{
    private readonly TestEnvironment _env = new();
    private FileScanner Scanner => _env.Get<FileScanner>();

    [Fact]
    public async Task MaliciousFile_IsDetected_AndSecondScanUsesCache()
    {
        string path = _env.CreateFile("payload.bin", "abc " + TestEnvironment.Marker + " xyz");

        var first = await Scanner.ScanAsync(path, FileScanContext.ForScan(ScanKind.Custom), default);
        Assert.Equal(FileVerdict.Malicious, first.Verdict);
        Assert.Contains(first.Threats, t => t.Name == "FG_UnitTest_Marker");
        Assert.False(first.FromCache);
        Assert.Equal(64, first.Sha256!.Length);

        var second = await Scanner.ScanAsync(path, FileScanContext.ForScan(ScanKind.Custom), default);
        Assert.Equal(FileVerdict.Malicious, second.Verdict);
        Assert.True(second.FromCache);
    }

    [Fact]
    public async Task CleanFile_IsClean()
    {
        string path = _env.CreateFile("readme.txt", "Nada que ver aquí.");
        var r = await Scanner.ScanAsync(path, FileScanContext.ForScan(ScanKind.Custom), default);
        Assert.Equal(FileVerdict.Clean, r.Verdict);
        Assert.Empty(r.Threats);
    }

    [Fact]
    public async Task ThreatInsideZip_IsDetected()
    {
        string zipPath = Path.Combine(_env.WorkDir, "mods.zip");
        using (var zip = ZipFile.Open(zipPath, ZipArchiveMode.Create))
        {
            var entry = zip.CreateEntry("mod/inner.dll");
            using var w = new StreamWriter(entry.Open());
            w.Write("data " + TestEnvironment.Marker);
        }

        var r = await Scanner.ScanAsync(zipPath, FileScanContext.ForScan(ScanKind.Custom), default);
        Assert.Equal(FileVerdict.Malicious, r.Verdict);
        Assert.Contains(r.Threats, t => t.Name == "FG_UnitTest_Marker" && t.Description.Contains("inner.dll"));
    }

    [Fact]
    public async Task NestedZip_IsInspected()
    {
        var innerMs = new MemoryStream();
        using (var inner = new ZipArchive(innerMs, ZipArchiveMode.Create, leaveOpen: true))
        using (var w = new StreamWriter(inner.CreateEntry("payload.exe").Open()))
            w.Write(TestEnvironment.Marker);

        string outerPath = Path.Combine(_env.WorkDir, "outer.zip");
        using (var outer = ZipFile.Open(outerPath, ZipArchiveMode.Create))
        using (var s = outer.CreateEntry("inner.zip").Open())
            s.Write(innerMs.ToArray());

        var r = await Scanner.ScanAsync(outerPath, FileScanContext.ForScan(ScanKind.Custom), default);
        Assert.Equal(FileVerdict.Malicious, r.Verdict);
    }

    [Fact]
    public async Task CheatNamedFile_IsSuspicious_NotMalicious()
    {
        string path = _env.CreateFile("CS2_Aimbot_Undetected.exe", "MZ fake");
        var r = await Scanner.ScanAsync(path, FileScanContext.ForScan(ScanKind.Custom), default);
        Assert.Equal(FileVerdict.Suspicious, r.Verdict);
        Assert.Contains(r.Threats, t => t.Source == DetectionSource.Heuristic && t.Category == "CheatLure");
    }

    [Fact]
    public async Task LockedFile_IsSkipped_WithoutThrowing()
    {
        string path = _env.CreateFile("locked.exe", "contenido");
        using var hold = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);

        var r = await Scanner.ScanAsync(path, FileScanContext.ForScan(ScanKind.Custom), default);
        Assert.Equal(FileVerdict.Skipped, r.Verdict);
        Assert.Equal(SkipReason.Locked, r.SkipReason);
    }

    [Fact]
    public async Task MissingFile_IsSkipped()
    {
        var r = await Scanner.ScanAsync(Path.Combine(_env.WorkDir, "no-existe.exe"), FileScanContext.ForScan(ScanKind.Custom), default);
        Assert.Equal(SkipReason.NotFound, r.SkipReason);
    }

    [Fact]
    public async Task Detection_IsQuarantined_ThenRestored_AndAllowListed()
    {
        string content = "x " + TestEnvironment.Marker;
        string path = _env.CreateFile("stealer.exe", content);
        var responder = _env.Get<ThreatResponder>();
        var quarantine = _env.Get<QuarantineManager>();

        var result = await Scanner.ScanAsync(path, FileScanContext.Realtime, default);
        var detection = await responder.HandleAsync(result, null, ScanKind.Realtime, default);

        Assert.NotNull(detection);
        Assert.Equal(ThreatAction.Quarantined, detection!.Action);
        Assert.False(File.Exists(path));
        var item = Assert.Single(quarantine.List());
        Assert.Equal(path, item.OriginalPath);

        // El archivo cifrado no contiene el marcador en claro
        string vaultFile = Directory.GetFiles(Path.Combine(_env.DataDir, "quarantine")).Single();
        Assert.DoesNotContain(TestEnvironment.Marker, File.ReadAllText(vaultFile));

        var (ok, restoredPath) = await quarantine.RestoreAsync(item.Id, default);
        Assert.True(ok, restoredPath);
        Assert.Equal(content, File.ReadAllText(path));
        Assert.Empty(quarantine.List());

        // Restaurado = permitido por el usuario: ya no se detecta
        var again = await Scanner.ScanAsync(path, FileScanContext.Realtime, default);
        Assert.Equal(FileVerdict.Clean, again.Verdict);
    }

    [Fact]
    public async Task ScanRunner_ScansFolder_AndCountsThreats()
    {
        _env.CreateFile("a/clean1.txt", "hola");
        _env.CreateFile("a/b/clean2.dll", "adios");
        _env.CreateFile("a/b/bad.dll", TestEnvironment.Marker);

        var runner = _env.Get<ScanRunner>();
        var job = new ScanJob(ScanKind.Custom, [_env.WorkDir], onlyInterestingExtensions: false);
        var progress = new List<ScanProgressDto>();

        var summary = await runner.RunAsync(job, p => progress.Add(p), default);

        Assert.Equal(ScanState.Completed, summary.State);
        Assert.Equal(3, summary.FilesScanned);
        Assert.Equal(1, summary.ThreatsFound);
        Assert.NotEmpty(progress);
    }

    [Fact]
    public async Task PausedScan_WaitsUntilResumed()
    {
        _env.CreateFile("c/one.txt", "1");
        var runner = _env.Get<ScanRunner>();
        var job = new ScanJob(ScanKind.Custom, [_env.WorkDir], false);
        job.Gate.Pause("gamemode");

        var task = runner.RunAsync(job, null, default);
        await Task.Delay(300);
        Assert.False(task.IsCompleted);

        job.Gate.Resume("gamemode");
        var summary = await task.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Equal(1, summary.FilesScanned);
    }

    public void Dispose() => _env.Dispose();
}
