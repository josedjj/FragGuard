using System.Runtime;
using Microsoft.Extensions.Logging;
using static FragGuard.Service.Infrastructure.NativeMethods;

namespace FragGuard.Service.Infrastructure;

/// <summary>Control de la prioridad y la memoria del propio servicio.</summary>
public sealed class ProcessPriority
{
    private readonly ILogger<ProcessPriority> _logger;
    private readonly object _sync = new();
    private bool _background;

    public ProcessPriority(ILogger<ProcessPriority> logger) => _logger = logger;

    public bool IsBackground
    {
        get { lock (_sync) return _background; }
    }

    /// <summary>Prioridad base del servicio: "por debajo de lo normal". Un antivirus nunca debe competir con el juego.</summary>
    public void ApplyDefault()
    {
        if (!SetPriorityClass(GetCurrentProcess(), BELOW_NORMAL_PRIORITY_CLASS))
            _logger.LogDebug("No se pudo fijar la prioridad BelowNormal");
    }

    /// <summary>
    /// Modo juego: PROCESS_MODE_BACKGROUND_BEGIN baja la prioridad de CPU, E/S y memoria de todo el proceso.
    /// Al salir (END) se vuelve a la prioridad anterior (BelowNormal).
    /// </summary>
    public void SetBackgroundMode(bool enabled)
    {
        lock (_sync)
        {
            if (_background == enabled)
                return;
            if (SetPriorityClass(GetCurrentProcess(), enabled ? PROCESS_MODE_BACKGROUND_BEGIN : PROCESS_MODE_BACKGROUND_END))
            {
                _background = enabled;
                _logger.LogInformation("Prioridad del servicio: {Mode}", enabled ? "segundo plano (CPU + E/S bajas)" : "normal (BelowNormal)");
            }
            else
            {
                _logger.LogWarning("No se pudo cambiar el modo de prioridad (error {Error})", System.Runtime.InteropServices.Marshal.GetLastWin32Error());
            }
        }
    }

    /// <summary>
    /// Devuelve memoria al sistema tras un escaneo: GC completo compactando el Large Object Heap
    /// (donde acaban los buffers grandes) y recorte del working set.
    /// </summary>
    public static void TrimMemory()
    {
        GCSettings.LargeObjectHeapCompactionMode = GCLargeObjectHeapCompactionMode.CompactOnce;
        GC.Collect(GC.MaxGeneration, GCCollectionMode.Aggressive, blocking: true, compacting: true);
        GC.WaitForPendingFinalizers();
        SetProcessWorkingSetSize(GetCurrentProcess(), -1, -1);
    }
}
