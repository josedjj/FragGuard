using System.Diagnostics;
using Microsoft.Extensions.Hosting;

namespace FragGuard.Service.Infrastructure;

/// <summary>
/// Mide el consumo del propio servicio (RAM privada y % de CPU) cada 5 s para mostrarlo en el panel.
/// Medirse a uno mismo es barato: no se consultan contadores de rendimiento ni WMI.
///
/// También mantiene el servicio por debajo de ~40 MB en reposo: el trabajo en ráfagas (análisis de los
/// procesos abiertos al arrancar, inventario de autoruns, escaneos en tiempo real) deja memoria que el GC
/// no devuelve al sistema por sí solo. Si la RAM privada supera el umbral y ha crecido desde el último
/// recorte, se recorta (GC compactando + working set). Como mucho una vez cada 2 minutos: cuesta ~10-30 ms.
/// </summary>
public sealed class ResourceMonitor : BackgroundService
{
    private const double TrimThresholdMb = 40;
    private const double TrimMinGrowthMb = 4;
    private static readonly TimeSpan TrimMinInterval = TimeSpan.FromMinutes(2);
    // Los primeros minutos concentran el trabajo del arranque (análisis de todos los procesos abiertos,
    // inventario de autoruns...): ahí se permite recortar más a menudo para no superar los 50 MB.
    private static readonly TimeSpan StartupPhase = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan StartupTrimInterval = TimeSpan.FromSeconds(30);

    private readonly Process _self = Process.GetCurrentProcess();
    private readonly ILogger<ResourceMonitor> _logger;
    private TimeSpan _lastCpu;
    private long _lastTicks;
    private DateTime _lastTrimUtc = DateTime.UtcNow;
    private double _afterLastTrimMb;

    public ResourceMonitor(ILogger<ResourceMonitor> logger) => _logger = logger;

    public double CpuPercent { get; private set; }
    public double PrivateMb { get; private set; }
    public DateTime StartedUtc { get; } = DateTime.UtcNow;

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        Sample();
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(5));
        while (await timer.WaitForNextTickAsync(ct).ConfigureAwait(false))
            Sample();
    }

    private void Sample()
    {
        _self.Refresh();
        TimeSpan cpu = _self.TotalProcessorTime;
        long now = Stopwatch.GetTimestamp();

        if (_lastTicks != 0)
        {
            double wallMs = Stopwatch.GetElapsedTime(_lastTicks, now).TotalMilliseconds;
            double cpuMs = (cpu - _lastCpu).TotalMilliseconds;
            // % del total de la máquina (igual que el Administrador de tareas)
            CpuPercent = wallMs > 0 ? Math.Round(cpuMs / (wallMs * Environment.ProcessorCount) * 100.0, 2) : 0;
        }

        _lastCpu = cpu;
        _lastTicks = now;
        PrivateMb = Math.Round(_self.PrivateMemorySize64 / 1024.0 / 1024.0, 1);
        TrimIfGrown();
    }

    private void TrimIfGrown()
    {
        if (PrivateMb < TrimThresholdMb
            || PrivateMb - _afterLastTrimMb < TrimMinGrowthMb
            || DateTime.UtcNow - _lastTrimUtc < (DateTime.UtcNow - StartedUtc < StartupPhase ? StartupTrimInterval : TrimMinInterval))
            return;

        double before = PrivateMb;
        ProcessPriority.TrimMemory();
        _self.Refresh();
        _afterLastTrimMb = PrivateMb = Math.Round(_self.PrivateMemorySize64 / 1024.0 / 1024.0, 1);
        _lastTrimUtc = DateTime.UtcNow;
        _logger.LogDebug("Memoria recortada: {Before} MB → {After} MB", before, PrivateMb);
    }

    public override void Dispose()
    {
        _self.Dispose();
        base.Dispose();
    }
}
