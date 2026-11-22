using FragGuard.Core;
using FragGuard.Service.Infrastructure;

namespace FragGuard.Service;

/// <summary>
/// Primer servicio en arrancar: prepara el motor (carpetas, ACL, base de datos, reglas YARA),
/// baja la prioridad del proceso y, pasados unos segundos, recorta la memoria del arranque.
/// Los demás servicios (tiempo real, pipe...) arrancan después, con el motor ya listo.
/// </summary>
public sealed class StartupService : IHostedService
{
    private readonly EngineBootstrapper _bootstrapper;
    private readonly ProcessPriority _priority;
    private readonly ILogger<StartupService> _logger;

    public StartupService(EngineBootstrapper bootstrapper, ProcessPriority priority, ILogger<StartupService> logger)
    {
        _bootstrapper = bootstrapper;
        _priority = priority;
        _logger = logger;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        _priority.ApplyDefault();
        _bootstrapper.Initialize();

        // La compilación de reglas y la carga inicial dejan basura: la liberamos cuando todo está en marcha.
        _ = Task.Run(async () =>
        {
            await Task.Delay(TimeSpan.FromSeconds(15), cancellationToken).ConfigureAwait(false);
            ProcessPriority.TrimMemory();
            _logger.LogInformation("Arranque completado; memoria recortada");
        }, cancellationToken);

        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("Servicio detenido");
        return Task.CompletedTask;
    }
}
