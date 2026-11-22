using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using FragGuard.Core.Configuration;
using FragGuard.Core.Detection;
using FragGuard.Core.Quarantine;
using FragGuard.Core.Scanning;
using FragGuard.Shared.Ipc;
using FragGuard.Shared.Models;
using Microsoft.Extensions.Logging.Abstractions;

namespace FragGuard.Core.Tests;

public class CheatLureAnalyzerTests
{
    [Theory]
    [InlineData("Valorant_Aimbot_2025.exe")]
    [InlineData("cs2-wallhack.zip")]
    [InlineData("FREE_SKINS_GENERATOR.exe")]
    [InlineData("Fortnite Free VBucks.exe")]
    [InlineData("robux-generator.bat")]
    [InlineData("Apex_ESP_Hack.rar")]
    [InlineData("HWID Spoofer.exe")]
    [InlineData("Elden Ring Trainer +25.exe")]
    [InlineData("skin_changer.dll")]
    public void LureNames_AreFlagged(string name) => Assert.NotNull(CheatLureAnalyzer.Analyze(name));

    [Theory]
    [InlineData("steam_setup.exe")]
    [InlineData("BepInEx_Loader.dll")]        // mod loader legítimo
    [InlineData("Hackathon_Results.exe")]
    [InlineData("aimbot_notes.txt")]          // extensión no ejecutable
    [InlineData("DiscordSetup.exe")]
    [InlineData("nvidia_driver.exe")]
    // Falsos positivos reales encontrados en la primera instalación (librerías de desarrollo):
    [InlineData(@"C:\proyecto\node_modules\@babel\helper-module-imports\lib\import-injector.js")]
    [InlineData(@"C:\proyecto\node_modules\eslint\lib\rules\no-async-promise-executor.js")]
    [InlineData(@"C:\proyecto\node_modules\lucide-react\dist\esm\icons\heart-crack.js")]
    [InlineData(@"C:\venv\Lib\site-packages\androguard\pentest\disable_cert_chain_bypass_v7a.js")]
    [InlineData(@"C:\proyecto\node_modules\some-tool\bin\injector.exe")]
    public void NormalNames_AreNotFlagged(string name) => Assert.Null(CheatLureAnalyzer.Analyze(name));
}

public class VirusTotalTests
{
    private const string Hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

    [Fact]
    public void Parse_ReadsStatsAndLabel()
    {
        var json = """
            {"data":{"attributes":{"last_analysis_stats":{"malicious":40,"suspicious":1,"harmless":0,"undetected":20},
             "popular_threat_classification":{"suggested_threat_label":"trojan.redline/stealer"}}}}
            """;
        var r = VirusTotalClient.Parse(JsonDocument.Parse(json));
        Assert.Equal(VtStatus.Found, r.Status);
        Assert.Equal(40, r.Malicious);
        Assert.Equal(61, r.TotalEngines);
        Assert.Equal("trojan.redline/stealer", r.ThreatLabel);

        var threat = FileScanner.MapVirusTotal(r);
        Assert.Equal(ThreatSeverity.Critical, threat!.Severity);
    }

    [Theory]
    [InlineData(0, 0, null)]
    [InlineData(1, 0, ThreatSeverity.Medium)]   // un solo motor: sospechoso, no cuarentena
    [InlineData(3, 0, ThreatSeverity.High)]
    public void MapVirusTotal_Thresholds(int malicious, int suspicious, ThreatSeverity? expected)
    {
        var t = FileScanner.MapVirusTotal(new VtLookupResult(VtStatus.Found, malicious, suspicious, 10, 50));
        Assert.Equal(expected, t?.Severity);
    }

    [Fact]
    public async Task NotConfigured_WhenNoKey()
    {
        using var vt = new VirusTotalClient(new HttpClient(new FakeHandler(HttpStatusCode.OK)), () => null, NullLogger<VirusTotalClient>.Instance);
        Assert.Equal(VtStatus.NotConfigured, (await vt.LookupAsync(Hash, TimeSpan.Zero, default)).Status);
    }

    [Fact]
    public async Task NotFound_IsUnknown_AndSendsApiKeyHeader()
    {
        var handler = new FakeHandler(HttpStatusCode.NotFound);
        using var vt = new VirusTotalClient(new HttpClient(handler), () => "test-key", NullLogger<VirusTotalClient>.Instance);
        var r = await vt.LookupAsync(Hash, TimeSpan.Zero, default);
        Assert.Equal(VtStatus.Unknown, r.Status);
        Assert.Equal("test-key", handler.LastApiKey);
        Assert.EndsWith(Hash, handler.LastUri!.ToString());
    }

    [Fact]
    public async Task RateLimit_IsRespected_WithoutBlocking()
    {
        using var vt = new VirusTotalClient(new HttpClient(new FakeHandler(HttpStatusCode.NotFound)), () => "k",
            NullLogger<VirusTotalClient>.Instance, requestsPerMinute: 1);
        Assert.Equal(VtStatus.Unknown, (await vt.LookupAsync(Hash, TimeSpan.Zero, default)).Status);
        Assert.Equal(VtStatus.RateLimited, (await vt.LookupAsync(Hash, TimeSpan.Zero, default)).Status);
    }

    [Fact]
    public async Task Http429_TriggersCooldown()
    {
        using var vt = new VirusTotalClient(new HttpClient(new FakeHandler(HttpStatusCode.TooManyRequests)), () => "k", NullLogger<VirusTotalClient>.Instance);
        Assert.Equal(VtStatus.RateLimited, (await vt.LookupAsync(Hash, TimeSpan.Zero, default)).Status);
        Assert.Equal(VtStatus.RateLimited, (await vt.LookupAsync(Hash, TimeSpan.Zero, default)).Status);
    }

    private sealed class FakeHandler(HttpStatusCode code) : HttpMessageHandler
    {
        public string? LastApiKey { get; private set; }
        public Uri? LastUri { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            LastApiKey = request.Headers.TryGetValues("x-apikey", out var v) ? v.Single() : null;
            LastUri = request.RequestUri;
            return Task.FromResult(new HttpResponseMessage(code) { Content = new StringContent("{}") });
        }
    }
}

public class QuarantineVaultTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "FragGuardVault", Guid.NewGuid().ToString("N"));

    public QuarantineVaultTests() => Directory.CreateDirectory(_dir);

    [Theory]
    [InlineData(0)]
    [InlineData(10)]
    [InlineData(1024 * 1024)]           // exactamente un bloque
    [InlineData(2 * 1024 * 1024 + 123)] // varios bloques
    public void EncryptDecrypt_RoundTrip(int size)
    {
        var vault = new QuarantineVault(Path.Combine(_dir, "q.key"));
        byte[] data = RandomNumberGenerator.GetBytes(size);

        var encrypted = new MemoryStream();
        vault.Encrypt(new MemoryStream(data), encrypted);
        encrypted.Position = 0;

        var decrypted = new MemoryStream();
        vault.Decrypt(encrypted, decrypted);
        Assert.Equal(data, decrypted.ToArray());
    }

    [Fact]
    public void TamperedFile_FailsToDecrypt()
    {
        var vault = new QuarantineVault(Path.Combine(_dir, "q.key"));
        var encrypted = new MemoryStream();
        vault.Encrypt(new MemoryStream(RandomNumberGenerator.GetBytes(5000)), encrypted);
        byte[] bytes = encrypted.ToArray();
        bytes[^10] ^= 0xFF; // alteramos un byte cifrado

        Assert.ThrowsAny<CryptographicException>(() => vault.Decrypt(new MemoryStream(bytes), new MemoryStream()));
    }

    [Fact]
    public void TruncatedFile_FailsToDecrypt()
    {
        var vault = new QuarantineVault(Path.Combine(_dir, "q.key"));
        var encrypted = new MemoryStream();
        vault.Encrypt(new MemoryStream(RandomNumberGenerator.GetBytes(3 * 1024 * 1024)), encrypted);
        // Quitamos el último bloque entero: el penúltimo no está marcado como "último" → falla la autenticación
        byte[] bytes = encrypted.ToArray();
        int lastBlock = 4 + 16 + 1024 * 1024;
        byte[] truncated = bytes[..(bytes.Length - lastBlock)];

        Assert.ThrowsAny<Exception>(() => vault.Decrypt(new MemoryStream(truncated), new MemoryStream()));
    }

    [Fact]
    public void Key_IsReusedAcrossInstances()
    {
        string keyPath = Path.Combine(_dir, "q.key");
        var encrypted = new MemoryStream();
        new QuarantineVault(keyPath).Encrypt(new MemoryStream([1, 2, 3]), encrypted);
        encrypted.Position = 0;
        var output = new MemoryStream();
        new QuarantineVault(keyPath).Decrypt(encrypted, output);
        Assert.Equal(new byte[] { 1, 2, 3 }, output.ToArray());
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, true); } catch { }
    }
}

public class SettingsAndProtocolTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "FragGuardSettings", Guid.NewGuid().ToString("N"));

    [Fact]
    public void Settings_PersistAndReload_AndVirusTotalKeyIsEncrypted()
    {
        var paths = new FragGuardPaths(_dir, _dir);
        Directory.CreateDirectory(_dir);
        var store = new SettingsStore(paths, NullLogger<SettingsStore>.Instance);

        var s = store.GetForClient();
        s.WatchedFolders.Add(@"D:\Games\Mods");
        s.MaxFileSizeMb = 999999; // fuera de rango: se corrige
        store.Update(s);
        store.SetVirusTotalKey("mi-clave-secreta");

        var reloaded = new SettingsStore(paths, NullLogger<SettingsStore>.Instance);
        Assert.Contains(@"D:\Games\Mods", reloaded.Current.WatchedFolders);
        Assert.Equal(4096, reloaded.Current.MaxFileSizeMb);
        Assert.Equal("mi-clave-secreta", reloaded.GetVirusTotalKey());
        Assert.True(reloaded.GetForClient().HasVirusTotalKey);

        // La clave no aparece en claro ni en settings.json ni en vt.key
        Assert.DoesNotContain("mi-clave-secreta", File.ReadAllText(paths.SettingsPath));
        Assert.DoesNotContain("mi-clave-secreta", File.ReadAllText(paths.VirusTotalKeyPath));
    }

    [Fact]
    public void CorruptSettings_FallBackToDefaults()
    {
        Directory.CreateDirectory(_dir);
        var paths = new FragGuardPaths(_dir, _dir);
        File.WriteAllText(paths.SettingsPath, "{ esto no es json");
        var store = new SettingsStore(paths, NullLogger<SettingsStore>.Instance);
        Assert.True(store.Current.RealtimeEnabled);
        Assert.True(File.Exists(paths.SettingsPath + ".corrupt"));
    }

    [Fact]
    public async Task PipeProtocol_RoundTrip()
    {
        var ms = new MemoryStream();
        var request = PipeProtocol.Create(MessageTypes.StartScan, new ScanRequest { Kind = ScanKind.Custom, CustomPath = @"C:\Juegos" },
            FragGuardJsonContext.Default.ScanRequest, "abc");
        await PipeProtocol.WriteAsync(ms, request, default);
        ms.Position = 0;

        var read = await PipeProtocol.ReadAsync(ms, default);
        Assert.Equal(MessageTypes.StartScan, read!.Type);
        Assert.Equal("abc", read.CorrelationId);
        var payload = read.GetPayload(FragGuardJsonContext.Default.ScanRequest);
        Assert.Equal(ScanKind.Custom, payload!.Kind);
        Assert.Equal(@"C:\Juegos", payload.CustomPath);

        Assert.Null(await PipeProtocol.ReadAsync(ms, default)); // EOF
    }

    [Fact]
    public async Task PipeProtocol_RejectsOversizedMessage()
    {
        var ms = new MemoryStream(BitConverter.GetBytes(int.MaxValue));
        await Assert.ThrowsAsync<InvalidDataException>(() => PipeProtocol.ReadAsync(ms, default));
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, true); } catch { }
    }
}
