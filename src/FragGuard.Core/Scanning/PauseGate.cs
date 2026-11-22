namespace FragGuard.Core.Scanning;

/// <summary>
/// "Puerta" de pausa con varios motivos independientes (p. ej. "user" y "gamemode"):
/// los escaneos se detienen mientras haya AL MENOS un motivo activo y se reanudan solos cuando desaparecen todos.
/// </summary>
public sealed class PauseGate
{
    private readonly object _sync = new();
    private readonly HashSet<string> _reasons = new(StringComparer.OrdinalIgnoreCase);
    private TaskCompletionSource _resumed = NewCompleted();

    public bool IsPaused
    {
        get { lock (_sync) return _reasons.Count > 0; }
    }

    public void Pause(string reason)
    {
        lock (_sync)
        {
            if (_reasons.Count == 0)
                _resumed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            _reasons.Add(reason);
        }
    }

    public void Resume(string reason)
    {
        TaskCompletionSource? toRelease = null;
        lock (_sync)
        {
            if (_reasons.Remove(reason) && _reasons.Count == 0)
                toRelease = _resumed;
        }
        toRelease?.TrySetResult();
    }

    public Task WaitIfPausedAsync(CancellationToken ct)
    {
        Task task;
        lock (_sync)
            task = _resumed.Task;
        return task.IsCompleted ? Task.CompletedTask : task.WaitAsync(ct);
    }

    private static TaskCompletionSource NewCompleted()
    {
        var tcs = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        tcs.SetResult();
        return tcs;
    }
}

/// <summary>
/// Modo de bajo impacto (modo juego): fuerza un único hilo de análisis y una pequeña pausa entre archivos
/// para que un escaneo manual en curso no robe CPU/disco al juego.
/// </summary>
public sealed class ScanThrottle
{
    private readonly SemaphoreSlim _single = new(1, 1);
    private volatile bool _lowImpact;

    public bool LowImpact
    {
        get => _lowImpact;
        set => _lowImpact = value;
    }

    public async ValueTask<IDisposable?> EnterAsync(CancellationToken ct)
    {
        if (!_lowImpact)
            return null;
        await _single.WaitAsync(ct).ConfigureAwait(false);
        await Task.Delay(15, ct).ConfigureAwait(false);
        return new Releaser(_single);
    }

    private sealed class Releaser(SemaphoreSlim semaphore) : IDisposable
    {
        private int _disposed;
        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) == 0)
                semaphore.Release();
        }
    }
}
