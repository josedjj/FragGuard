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

// ---------- Modo desinstalación ----------
// "FragGuard.Service.exe --uninstall-cleanup" (como administrador y con el servicio ya detenido) deshace los
// cambios que FragGuard hace en el sistema: señuelos anti-ransomware, auditoría de cuentas y DNS protegido.
// Lo llaman el desinstalador y scripts\uninstall.ps1. Los autoruns desactivados por el usuario NO se tocan.
if (args.Contains("--uninstall-cleanup", StringComparer.OrdinalIgnoreCase))
{
    using var loggerFactory = LoggerFactory.Create(b => b.AddSerilog(dispose: false));
    var log = loggerFactory.CreateLogger("Uninstall");
    int failures = 0;
    void Step(string name, Action action)
    {
        try { action(); }
        catch (Exception ex) { failures++; log.LogError(ex, "Limpieza: fallo en {Step}", name); }
    }

    Log.Information("Limpieza de desinstalación de {Product} {Version}", AppInfo.ProductName, AppInfo.Version);
    Step("señuelos", () => log.LogInformation("Señuelos eliminados: {Count}", FragGuard.Service.Protection.RansomwareShield.RemoveCanaries(log)));
    Step("auditoría", () => FragGuard.Service.Protection.AccountProtectionService.CleanupForUninstall(paths, log));
    Step("DNS", () =>
    {
        var dns = new FragGuard.Service.Protection.DnsProtection(paths, loggerFactory.CreateLogger<FragGuard.Service.Protection.DnsProtection>());
        if (File.Exists(Path.Combine(paths.DataRoot, "dns-backup.json")))
            log.LogInformation("DNS: {Result}", dns.Disable().Message);
    });
    await Log.CloseAndFlushAsync();
    return failures == 0 ? 0 : 2;
}

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
    builder.Services.AddSingleton<FragGuard.Service.Protection.SelfIntegrity>();
    builder.Services.AddSingleton<FragGuard.Service.Protection.AutorunManager>();
    builder.Services.AddSingleton<FragGuard.Service.Protection.MemoryScanService>();
    builder.Services.AddSingleton<FragGuard.Service.Protection.ProtectionStatusProvider>();
    builder.Services.AddSingleton<FragGuard.Service.Protection.DnsProtection>();
    builder.Services.AddSingleton(sp =>
    {
        var dispatcher = ActivatorUtilities.CreateInstance<RequestDispatcher>(sp);
        dispatcher.RequireAdminForSensitiveOperations = builder.Configuration.GetValue("FragGuard:RequireAdminForSensitiveOperations", true);
        return dispatcher;
    });

    // Servicios en segundo plano. El orden importa: StartupService inicializa el motor ANTES que el resto.
    builder.Services.AddHostedService<StartupService>();
    AddSingletonHostedService<ResourceMonitor>(builder.Services);
    AddSingletonHostedService<GameModeService>(builder.Services);
    AddSingletonHostedService<FragGuard.Service.Protection.RemovableDriveService>(builder.Services);
    AddSingletonHostedService<RealtimeProtectionService>(builder.Services);
    // Protección en ejecución (todo en modo usuario, sin drivers)
    AddSingletonHostedService<FragGuard.Service.Protection.ProcessMonitorService>(builder.Services);
    AddSingletonHostedService<FragGuard.Service.Protection.RansomwareShield>(builder.Services);
    AddSingletonHostedService<FragGuard.Service.Protection.PersistenceMonitorService>(builder.Services);
    AddSingletonHostedService<FragGuard.Service.Protection.AccountProtectionService>(builder.Services);
    AddSingletonHostedService<FragGuard.Service.Protection.PrivacyMonitorService>(builder.Services);
    builder.Services.AddHostedService<ScheduledScanService>();
    AddSingletonHostedService<FragGuard.Service.Updates.RulesUpdateService>(builder.Services);
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
