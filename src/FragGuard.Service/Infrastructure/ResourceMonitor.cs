using System.Diagnostics;
using Microsoft.Extensions.Hosting;

namespace FragGuard.Service.Infrastructure;

/// <summary>
/// Mide el consumo del propio servicio (RAM privada y % de CPU) cada 5 s para mostrarlo en el panel.
/// Medirse a uno mismo es barato: no se consultan contadores de rendimiento ni WMI.
/// </summary>
public sealed class ResourceMonitor : BackgroundService
{
    private readonly Process _self = Process.GetCurrentProcess();
    private TimeSpan _lastCpu;
    private long _lastTicks;

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
    }

    public override void Dispose()
    {
        _self.Dispose();
        base.Dispose();
    }
}
