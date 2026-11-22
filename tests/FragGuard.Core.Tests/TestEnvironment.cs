using FragGuard.Core.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace FragGuard.Core.Tests;

/// <summary>
/// Entorno aislado para tests de integración: carpeta de datos temporal, copia de las reglas reales
/// más una regla marcador propia de los tests (así no hace falta escribir malware ni EICAR en disco).
/// </summary>
public sealed class TestEnvironment : IDisposable
{
    /// <summary>Cadena que dispara la regla de test. Es texto inocuo.</summary>
    public const string Marker = "FRAGGUARD-UNIT-TEST-MARKER-7f3a9c";

    public TestEnvironment()
    {
        Root = Path.Combine(Path.GetTempPath(), "FragGuardTests", Guid.NewGuid().ToString("N"));
        DataDir = Path.Combine(Root, "data");
        RulesDir = Path.Combine(Root, "rules");
        WorkDir = Path.Combine(Root, "work");
        Directory.CreateDirectory(RulesDir);
        Directory.CreateDirectory(WorkDir);

        // Reglas reales copiadas a la salida del test (carpeta "rules" junto al ensamblado)
        string shippedRules = Path.Combine(AppContext.BaseDirectory, "rules");
        foreach (var file in Directory.GetFiles(shippedRules, "*.yar"))
            File.Copy(file, Path.Combine(RulesDir, Path.GetFileName(file)));

        File.WriteAllText(Path.Combine(RulesDir, "99_unit_test.yar"), $$"""
            rule FG_UnitTest_Marker
            {
                meta:
                    description = "Marcador de pruebas unitarias"
                    severity = "high"
                    category = "Test"
                strings:
                    $m = "{{Marker}}"
                condition:
                    $m
            }
            """);

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddFragGuardCore(
            new FragGuardPaths(DataDir, RulesDir),
            new EngineOptions { HardenDataDirectoryAcl = false }); // si no, el usuario del test perdería el acceso
        Provider = services.BuildServiceProvider();
        Provider.GetRequiredService<EngineBootstrapper>().Initialize();
    }

    public string Root { get; }
    public string DataDir { get; }
    public string RulesDir { get; }
    public string WorkDir { get; }
    public ServiceProvider Provider { get; }

    public T Get<T>() where T : notnull => Provider.GetRequiredService<T>();

    public string CreateFile(string name, string content)
    {
        string path = Path.Combine(WorkDir, name);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, content);
        return path;
    }

    public void Dispose()
    {
        Provider.Dispose();
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools(); // suelta el archivo .db para poder borrarlo
        try { Directory.Delete(Root, recursive: true); } catch { /* best effort */ }
    }
}
