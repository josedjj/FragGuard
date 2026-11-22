using FragGuard.Core;
using FragGuard.Core.Configuration;
using FragGuard.Service;
using FragGuard.Service.GameMode;
using FragGuard.Service.Infrastructure;
using FragGuard.Service.Ipc;
using FragGuard.Service.Realtime;
using FragGuard.Service.Scanning;
using FragGuard.Service.Status;
using FragGuard.Shared;
using Serilog;
using Serilog.Events;

// =====================================================================================
//  FragGuard.Service - punto de entrada
//  Se ejecuta como servicio de Windows (LocalSystem) o, en desarrollo, como consola.
// =====================================================================================

var builder = Host.CreateApplicationBuilder(args);

// Carpeta de datos: %ProgramData%\FragGuard por defecto. En desarrollo (consola sin admin) se puede
// redirigir con FragGuard:DataRoot, porque la carpeta real queda restringida a SYSTEM/Administradores.
var paths = new FragGuardPaths(builder.Configuration["FragGuard:DataRoot"], builder.Configuration["FragGuard:RulesDirectory"]);
Directory.CreateDirectory(paths.LogsDirectory);

// ---------- Serilog ----------
var logConfig = new LoggerConfiguration()
    .ReadFrom.Configuration(builder.Configuration) // niveles mínimos desde appsettings.json
    .Enrich.FromLogContext()
    .WriteTo.File(
        Path.Combine(paths.LogsDirectory, "service-.log"),
        rollingInterval: RollingInterval.Day,
        retainedFileCountLimit: 14,
        fileSizeLimitBytes: 10 * 1024 * 1024,
        rollOnFileSizeLimit: true,
        outputTemplate: "{Timestamp:yyyy-MM-dd HH:mm:ss.fff} [{Level:u3}] {SourceContext}: {Message:lj}{NewLine}{Exception}");
if (Environment.UserInteractive)
    logConfig.WriteTo.Console(restrictedToMinimumLevel: LogEventLevel.Information);
Log.Logger = logConfig.CreateLogger();

try
{
    Log.Information("Iniciando {Product} {Version} (PID {Pid}, datos en {DataRoot})",
        AppInfo.ProductName, AppInfo.Version, Environment.ProcessId, paths.DataRoot);

    builder.Services.AddSerilog();
    builder.Services.AddWindowsService(o => o.ServiceName = AppInfo.ServiceName);

    // ---------- Motor (Core) ----------
    builder.Services.AddFragGuardCore(paths, new EngineOptions
    {
        HardenDataDirectoryAcl = builder.Configuration.GetValue("FragGuard:HardenDataDirectoryAcl", true)
    });

    // ---------- Componentes del servicio ----------
    builder.Services.AddSingleton<ProcessPriority>();
    builder.Services.AddSingleton<UserFolderRegistry>();
    builder.Services.AddSingleton<EventBroadcaster>();
    builder.Services.AddSingleton<ScanCoordinator>();
    builder.Services.AddSingleton<StatusProvider>();
    builder.Services.AddSingleton(sp => new RequestDispatcher(
        sp.GetRequiredService<StatusProvider>(), sp.GetRequiredService<ScanCoordinator>(),
        sp.GetRequiredService<FragGuard.Core.Data.ScanHistoryRepository>(), sp.GetRequiredService<FragGuard.Core.Data.DetectionRepository>(),
        sp.GetRequiredService<FragGuard.Core.Quarantine.QuarantineManager>(), sp.GetRequiredService<SettingsStore>(),
        sp.GetRequiredService<GameModeService>(), sp.GetRequiredService<UserFolderRegistry>(),
        sp.GetRequiredService<FragGuard.Core.Games.GameLibrary>(),
        sp.GetRequiredService<ILogger<RequestDispatcher>>())
    {
        RequireAdminForSensitiveOperations = builder.Configuration.GetValue("FragGuard:RequireAdminForSensitiveOperations", true)
    });

    // Servicios en segundo plano. El orden importa: StartupService inicializa el motor ANTES que el resto.
    builder.Services.AddHostedService<StartupService>();
    AddSingletonHostedService<ResourceMonitor>(builder.Services);
    AddSingletonHostedService<GameModeService>(builder.Services);
    AddSingletonHostedService<RealtimeProtectionService>(builder.Services);
    builder.Services.AddHostedService<ScheduledScanService>();
    builder.Services.AddHostedService<PipeServer>();

    // Si un servicio en segundo plano falla de forma inesperada, lo registramos pero NO paramos el host.
    builder.Services.Configure<HostOptions>(o => o.BackgroundServiceExceptionBehavior = BackgroundServiceExceptionBehavior.Ignore);

    var host = builder.Build();
    await host.RunAsync();
    return 0;
}
catch (Exception ex)
{
    Log.Fatal(ex, "El servicio terminó por un error fatal");
    return 1;
}
finally
{
    await Log.CloseAndFlushAsync();
}

// Registra un servicio como singleton Y como hosted service (la misma instancia), para poder consultarlo desde otros.
static void AddSingletonHostedService<T>(IServiceCollection services) where T : class, IHostedService
{
    services.AddSingleton<T>();
    services.AddHostedService(sp => sp.GetRequiredService<T>());
}
