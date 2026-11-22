using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using FragGuard.Core.Configuration;
using FragGuard.Core.Detection;
using FragGuard.Core.IO;
using FragGuard.Core.Scanning;
using FragGuard.Core.Security;
using FragGuard.Core.Updates;
using FragGuard.Shared.Models;
using Microsoft.Extensions.Logging.Abstractions;

namespace FragGuard.Core.Tests;

public class AuthenticodeTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "FgAuth" + Guid.NewGuid().ToString("N")[..8]);
    private static readonly string DotnetExe = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "dotnet", "dotnet.exe");

    public AuthenticodeTests() => Directory.CreateDirectory(_dir);

    [Fact]
    public void MicrosoftSignedBinary_IsValid_AndTrusted()
    {
        var sig = Authenticode.Verify(DotnetExe);
        Assert.True(sig.IsSigned);
        Assert.True(sig.IsValid);
        Assert.Equal("Microsoft Corporation", sig.Publisher);
        Assert.True(sig.IsTrustedPublisher);
    }

    [Fact]
    public void UnsignedFile_IsNotSigned()
    {
        string f = Path.Combine(_dir, "unsigned.exe");
        File.WriteAllBytes(f, new byte[] { 0x4D, 0x5A, 0, 0 });
        Assert.False(Authenticode.Verify(f).IsSigned);
    }

    [Fact]
    public void TamperedSignedBinary_IsSignedButInvalid()
    {
        string copy = Path.Combine(_dir, "tampered.exe");
        File.Copy(DotnetExe, copy);
        byte[] bytes = File.ReadAllBytes(copy);
        bytes[bytes.Length / 3] ^= 0xFF; // modificamos código ya firmado
        File.WriteAllBytes(copy, bytes);

        var sig = Authenticode.Verify(copy);
        Assert.True(sig.IsSigned);
        Assert.False(sig.IsValid);
        Assert.False(sig.IsTrustedPublisher); // una firma rota NUNCA relaja detecciones
    }

    public void Dispose() { try { Directory.Delete(_dir, true); } catch { } }
}

public class MarkOfTheWebTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "FgMotw" + Guid.NewGuid().ToString("N")[..8]);
    public MarkOfTheWebTests() => Directory.CreateDirectory(_dir);

    [Fact]
    public void Parse_ReadsZoneAndUrls()
    {
        var o = MarkOfTheWeb.Parse("[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://ejemplo.com/p\r\nHostUrl=https://cdn.ejemplo.com/skins.exe\r\n")!;
        Assert.Equal(3, o.ZoneId);
        Assert.True(o.IsFromInternet);
        Assert.Equal("cdn.ejemplo.com", o.Host);
        Assert.Equal("https://ejemplo.com/p", o.ReferrerUrl);
    }

    [Fact]
    public void Parse_RejectsNonHttpUrls()
    {
        var o = MarkOfTheWeb.Parse("ZoneId=3\nHostUrl=file:///C:/x.exe")!;
        Assert.Null(o.HostUrl);
    }

    [Fact]
    public void Read_FromRealAlternateDataStream()
    {
        string f = Path.Combine(_dir, "descarga.exe");
        File.WriteAllText(f, "x");
        File.WriteAllText(f + ":Zone.Identifier", "[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://cdn.discordapp.com/attachments/1/2/cheat.exe\r\n");

        var o = MarkOfTheWeb.Read(f);
        Assert.NotNull(o);
        Assert.Equal("cdn.discordapp.com", o!.Host);
        Assert.Null(MarkOfTheWeb.Read(Path.Combine(_dir, "no-existe.exe")));
    }

    public void Dispose() { try { Directory.Delete(_dir, true); } catch { } }
}

public class AbuseChTests
{
    [Fact]
    public void ParseHash_Found()
    {
        var r = AbuseChClient.ParseHash(JsonDocument.Parse("""{"query_status":"ok","data":[{"signature":"RedLineStealer","tags":["exe","RedLineStealer"]}]}"""));
        Assert.Equal(AbuseStatus.Found, r.Status);
        Assert.Equal("RedLineStealer", r.Signature);
        var threat = FileScanner.MapMalwareBazaar(r)!;
        Assert.Equal(ThreatSeverity.Critical, threat.Severity);
        Assert.Equal(DetectionSource.Reputation, threat.Source);
        Assert.Equal("MB.RedLineStealer", threat.Name);
    }

    [Theory]
    [InlineData("""{"query_status":"hash_not_found"}""", AbuseStatus.NotFound)]
    [InlineData("""{"query_status":"unknown_auth_key"}""", AbuseStatus.InvalidKey)]
    [InlineData("""{"query_status":"illegal_hash"}""", AbuseStatus.Error)]
    public void ParseHash_OtherStatuses(string json, AbuseStatus expected) =>
        Assert.Equal(expected, AbuseChClient.ParseHash(JsonDocument.Parse(json)).Status);

    [Fact]
    public void ParseUrl()
    {
        var r = AbuseChClient.ParseUrl(JsonDocument.Parse("""{"query_status":"ok","url_status":"online","threat":"malware_download"}"""));
        Assert.Equal(("malware_download", "online"), (r.Threat, r.UrlStatus));
        Assert.Equal(AbuseStatus.NotFound, AbuseChClient.ParseUrl(JsonDocument.Parse("""{"query_status":"no_results"}""")).Status);
    }

    [Fact]
    public async Task NoKey_IsNotConfigured_AndDoesNotCallNetwork()
    {
        using var client = new AbuseChClient(new HttpClient(new ThrowingHandler()), () => null, NullLogger<AbuseChClient>.Instance);
        Assert.Equal(AbuseStatus.NotConfigured, (await client.LookupHashAsync(new string('a', 64), default)).Status);
    }

    private sealed class ThrowingHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage r, CancellationToken ct) => throw new InvalidOperationException("No debía llamar a la red");
    }
}

public class PupAndMinerRulesTests : IDisposable
{
    private readonly TestEnvironment _env = new();

    [Fact]
    public async Task HiddenMinerInExe_IsMalicious()
    {
        string f = _env.CreateFile("FPS_Booster.exe", "MZ stratum+tcp://pool.minexmr.com:4444 Taskmgr.exe --background");
        var r = await _env.Get<FileScanner>().ScanAsync(f, FileScanContext.ForScan(ScanKind.Custom), default);
        Assert.Contains(r.Threats, t => t.Name == "FG_Miner_Hidden" && t.Category == "Miner");
        Assert.Equal(FileVerdict.Malicious, r.Verdict);
    }

    [Fact]
    public async Task Pup_IsOnlyWarned_AndCanBeDisabled()
    {
        string f = _env.CreateFile("setup_free_app.exe", "MZ OpenCandy OCSetupHlp");
        var scanner = _env.Get<FileScanner>();

        var r = await scanner.ScanAsync(f, FileScanContext.ForScan(ScanKind.Custom), default);
        Assert.Equal(FileVerdict.Suspicious, r.Verdict); // aviso, nunca cuarentena automática

        var store = _env.Get<SettingsStore>();
        var s = store.GetForClient();
        s.DetectPup = false;
        store.Update(s);
        var r2 = await scanner.ScanAsync(f, FileScanContext.ForScan(ScanKind.Custom), default);
        Assert.Equal(FileVerdict.Clean, r2.Verdict);
    }

    [Fact]
    public async Task MinerStringsInNonExecutable_AreIgnored()
    {
        string f = _env.CreateFile("guia_mineria.txt", "Para minar usa xmrig con --donate-level 1 y stratum+tcp://pool");
        var r = await _env.Get<FileScanner>().ScanAsync(f, FileScanContext.ForScan(ScanKind.Custom), default);
        Assert.Equal(FileVerdict.Clean, r.Verdict); // las reglas exigen cabecera PE
    }

    public void Dispose() => _env.Dispose();
}

/// <summary>El canal de reglas es un vector de ataque: estos tests intentan colar reglas por todas las vías.</summary>
public class RulesChannelTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "FgChan" + Guid.NewGuid().ToString("N")[..8]);
    private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly Dictionary<string, byte[]> _server = new();
    private const string Rule = "rule FG_Channel_Test { strings: $a = \"CHANNEL-TEST-7731\" condition: $a }";

    public RulesChannelTests() => Directory.CreateDirectory(_dir);

    private string PublicKey => Convert.ToBase64String(_key.ExportSubjectPublicKeyInfo());

    private RulesChannel Channel(string? publicKey = null) =>
        new(new HttpClient(new FakeServer(_server)), new FragGuardPaths(_dir, _dir), NullLogger<RulesChannel>.Instance, "https://test/", publicKey ?? PublicKey);

    private void Publish(long version, string ruleContent, ECDsa? signer = null, string fileName = "channel_test.yar", string? fakeHash = null)
    {
        byte[] rule = Encoding.UTF8.GetBytes(ruleContent);
        string hash = fakeHash ?? Convert.ToHexString(SHA256.HashData(rule));
        byte[] manifest = JsonSerializer.SerializeToUtf8Bytes(new { version, createdUtc = DateTime.UtcNow, files = new[] { new { name = fileName, sha256 = hash } } });
        _server.Clear();
        _server["manifest.json"] = manifest;
        _server["manifest.sig"] = Encoding.ASCII.GetBytes(Convert.ToBase64String((signer ?? _key).SignData(manifest, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation)));
        _server[fileName] = rule;
    }

    [Fact]
    public async Task ValidSignedUpdate_IsApplied_ThenUpToDate()
    {
        Publish(100, Rule);
        var r = await Channel().CheckAndApplyAsync(default);
        Assert.Equal(RulesUpdateOutcome.Applied, r.Outcome);
        Assert.True(File.Exists(Path.Combine(_dir, "rules-updates", "channel_test.yar")));
        Assert.Equal(100, Channel().InstalledVersion);

        Assert.Equal(RulesUpdateOutcome.UpToDate, (await Channel().CheckAndApplyAsync(default)).Outcome);
    }

    [Fact]
    public async Task SignedWithAnotherKey_IsRejected()
    {
        using var attacker = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        Publish(100, Rule, signer: attacker);
        Assert.Equal(RulesUpdateOutcome.InvalidSignature, (await Channel().CheckAndApplyAsync(default)).Outcome);
        Assert.False(Directory.Exists(Path.Combine(_dir, "rules-updates")));
    }

    [Fact]
    public async Task RuleFileSwappedAfterSigning_IsRejected()
    {
        Publish(100, Rule);
        _server["channel_test.yar"] = Encoding.UTF8.GetBytes("rule Malicious_Swap { condition: true }"); // detectaría TODO
        Assert.Equal(RulesUpdateOutcome.InvalidSignature, (await Channel().CheckAndApplyAsync(default)).Outcome);
    }

    [Fact]
    public async Task OlderVersion_IsNotApplied()
    {
        Publish(200, Rule);
        await Channel().CheckAndApplyAsync(default);
        Publish(150, Rule.Replace("7731", "0000"));
        Assert.Equal(RulesUpdateOutcome.UpToDate, (await Channel().CheckAndApplyAsync(default)).Outcome);
        Assert.Contains("7731", File.ReadAllText(Path.Combine(_dir, "rules-updates", "channel_test.yar")));
    }

    [Fact]
    public async Task PathTraversalFileName_IsRejected()
    {
        Publish(100, Rule, fileName: "..\\..\\evil.yar");
        var r = await Channel().CheckAndApplyAsync(default);
        Assert.NotEqual(RulesUpdateOutcome.Applied, r.Outcome);
        Assert.False(File.Exists(Path.Combine(Path.GetTempPath(), "evil.yar")));
    }

    [Fact]
    public async Task ChannelUnavailable_IsHandledGracefully()
    {
        _server.Clear();
        Assert.Equal(RulesUpdateOutcome.NotAvailable, (await Channel().CheckAndApplyAsync(default)).Outcome);
    }

    [Fact]
    public void EmbeddedPublicKey_IsValidP256()
    {
        using var ecdsa = ECDsa.Create();
        ecdsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(RulesChannel.EmbeddedPublicKey), out _);
        Assert.Equal(256, ecdsa.KeySize);
    }

    [Fact]
    public async Task AppliedRules_AreLoadedByYaraEngine()
    {
        Publish(100, Rule);
        await Channel().CheckAndApplyAsync(default);
        using var yara = new YaraEngine(NullLogger<YaraEngine>.Instance);
        yara.LoadRules(Path.Combine(AppContext.BaseDirectory, "rules"), Path.Combine(_dir, "rules-updates"));
        var data = Encoding.UTF8.GetBytes("xx CHANNEL-TEST-7731 xx");
        Assert.Contains(yara.ScanMemory(data, data.Length), t => t.Name == "FG_Channel_Test");
    }

    private sealed class FakeServer(Dictionary<string, byte[]> files) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            string name = Uri.UnescapeDataString(request.RequestUri!.AbsolutePath.TrimStart('/'));
            return Task.FromResult(files.TryGetValue(name, out var content)
                ? new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(content) }
                : new HttpResponseMessage(HttpStatusCode.NotFound));
        }
    }

    public void Dispose()
    {
        _key.Dispose();
        try { Directory.Delete(_dir, true); } catch { }
    }
}
