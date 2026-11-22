using System.Net;
using FragGuard.Core.Archives;
using FragGuard.Core.Configuration;
using FragGuard.Core.Data;
using FragGuard.Core.Detection;
using FragGuard.Core.Quarantine;
using FragGuard.Core.Scanning;
using FragGuard.Core.Security;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace FragGuard.Core;

/// <summary>Registro del motor en el contenedor de dependencias del host (servicio o tests).</summary>
public static class CoreServiceCollectionExtensions
{
    public static IServiceCollection AddFragGuardCore(this IServiceCollection services, FragGuardPaths? paths = null, EngineOptions? options = null)
    {
        services.AddSingleton(paths ?? new FragGuardPaths());
        services.AddSingleton(options ?? new EngineOptions());

        services.AddSingleton<SettingsStore>();
        services.AddSingleton<FragGuardDatabase>();
        services.AddSingleton<HashCacheRepository>();
        services.AddSingleton<AllowListRepository>();
        services.AddSingleton<ScanHistoryRepository>();
        services.AddSingleton<DetectionRepository>();
        services.AddSingleton<QuarantineRepository>();

        services.AddSingleton<IYaraEngine, YaraEngine>();
        services.AddSingleton<ArchiveScanner>();
        services.AddSingleton(sp => new VirusTotalClient(
            // Un único HttpClient de larga vida; PooledConnectionLifetime evita quedarse con DNS obsoleto.
            new HttpClient(new SocketsHttpHandler
            {
                PooledConnectionLifetime = TimeSpan.FromMinutes(5),
                AutomaticDecompression = DecompressionMethods.All
            }),
            () => sp.GetRequiredService<SettingsStore>().GetVirusTotalKey(),
            sp.GetRequiredService<ILogger<VirusTotalClient>>()));

        services.AddSingleton(sp => new QuarantineVault(sp.GetRequiredService<FragGuardPaths>().QuarantineKeyPath));
        services.AddSingleton<QuarantineManager>();

        services.AddSingleton<ScanThrottle>();
        services.AddSingleton<FileScanner>();
        services.AddSingleton<ThreatResponder>();
        services.AddSingleton<ScanRunner>();
        services.AddSingleton<Games.GameLibrary>();
        services.AddSingleton<EngineBootstrapper>();
        return services;
    }
}

/// <summary>
/// Preparación del motor en el arranque: carpetas, ACL, base de datos y reglas YARA.
/// Se llama una vez antes de empezar a escanear.
/// </summary>
public sealed class EngineBootstrapper
{
    private readonly FragGuardPaths _paths;
    private readonly EngineOptions _options;
    private readonly FragGuardDatabase _db;
    private readonly ScanHistoryRepository _history;
    private readonly IYaraEngine _yara;
    private readonly ILogger<EngineBootstrapper> _logger;

    public EngineBootstrapper(FragGuardPaths paths, EngineOptions options, FragGuardDatabase db,
        ScanHistoryRepository history, IYaraEngine yara, ILogger<EngineBootstrapper> logger)
    {
        _paths = paths;
        _options = options;
        _db = db;
        _history = history;
        _yara = yara;
        _logger = logger;
    }

    public void Initialize()
    {
        _paths.EnsureCreated();

        if (_options.HardenDataDirectoryAcl)
        {
            try
            {
                DirectoryHardening.RestrictToSystemAndAdmins(_paths.DataRoot);
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException or InvalidOperationException or IOException)
            {
                _logger.LogWarning(ex, "No se pudo restringir la ACL de {Dir} (¿no se ejecuta como SYSTEM/administrador?)", _paths.DataRoot);
            }
        }

        _db.Initialize();
        _history.MarkInterrupted();
        _yara.LoadRules(_paths.RulesDirectory);
    }
}
