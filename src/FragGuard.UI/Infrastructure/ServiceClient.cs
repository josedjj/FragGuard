using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text.Json.Serialization.Metadata;
using FragGuard.Shared;
using FragGuard.Shared.Ipc;
using FragGuard.Shared.Models;
using Serilog;

namespace FragGuard.UI.Infrastructure;

/// <summary>El servicio no está disponible (no instalado, detenido o reiniciándose).</summary>
public sealed class ServiceUnavailableException(string message) : Exception(message);

/// <summary>El servicio respondió con un error.</summary>
public sealed class ServiceErrorException(string message) : Exception(message);

/// <summary>La operación necesita que la UI se ejecute como administrador (UAC).</summary>
public sealed class ElevationRequiredException() : Exception("Se necesitan permisos de administrador.");

/// <summary>
/// Cliente del named pipe del servicio.
/// - Se conecta solo y se reconecta automáticamente si el servicio se reinicia.
/// - Empareja respuestas con peticiones por CorrelationId (permite varias peticiones en vuelo).
/// - Convierte los mensajes push del servicio en eventos tipados.
/// - Verifica que al otro lado del pipe está de verdad FragGuard.Service (anti-suplantación).
/// Los eventos se disparan en hilos de fondo: los ViewModels deben pasar al hilo de UI.
/// </summary>
public sealed class ServiceClient : IDisposable
{
    private static readonly FragGuardJsonContext Json = FragGuardJsonContext.Default;
    private static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(15);

    private readonly ConcurrentDictionary<string, TaskCompletionSource<PipeMessage>> _pending = new();
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private readonly CancellationTokenSource _cts = new();
    private NamedPipeClientStream? _pipe;
    private volatile bool _connected;

    public bool IsConnected => _connected;

    public event Action<bool>? ConnectionChanged;
    public event Action<DetectionDto>? ThreatDetected;
    public event Action<CheatWarningDto>? CheatWarning;
    public event Action<ScanProgressDto>? ScanProgress;
    public event Action<ScanSummaryDto>? ScanCompleted;
    public event Action<GameModeDto>? GameModeChanged;

    public void Start() => _ = Task.Run(() => RunAsync(_cts.Token));

    // ---------------- Conexión ----------------

    private async Task RunAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            var pipe = new NamedPipeClientStream(".", AppInfo.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous,
                // Identification: el servicio puede comprobar quiénes somos (y si estamos elevados),
                // pero NO puede actuar en nuestro nombre.
                TokenImpersonationLevel.Identification);
            try
            {
                await pipe.ConnectAsync(3000, ct).ConfigureAwait(false);
                VerifyServer(pipe);

                _pipe = pipe;
                SetConnected(true);
                await ReadLoopAsync(pipe, ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                break;
            }
            catch (TimeoutException)
            {
                // Servicio no disponible: reintentamos.
            }
            catch (Exception ex)
            {
                Log.Debug(ex, "Conexión con el servicio perdida");
            }
            finally
            {
                _pipe = null;
                await pipe.DisposeAsync().ConfigureAwait(false);
                FailPending();
                if (_connected)
                    SetConnected(false);
            }

            try { await Task.Delay(2000, ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { break; }
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeServerProcessId(IntPtr pipe, out uint serverProcessId);

    /// <summary>
    /// Anti-suplantación: un malware podría crear un pipe con nuestro nombre para engañar a la UI
    /// (p. ej. mostrar "protegido" o robar la clave de VirusTotal). Comprobamos el proceso servidor.
    /// </summary>
    private static void VerifyServer(NamedPipeClientStream pipe)
    {
        if (!GetNamedPipeServerProcessId(pipe.SafePipeHandle.DangerousGetHandle(), out uint pid))
            throw new IOException("No se pudo identificar el proceso del servicio.");
        using var process = Process.GetProcessById((int)pid);
        if (!string.Equals(process.ProcessName, "FragGuard.Service", StringComparison.OrdinalIgnoreCase))
        {
            Log.Error("El pipe {Pipe} lo sirve un proceso inesperado: {Name} (PID {Pid}). Conexión rechazada.", AppInfo.PipeName, process.ProcessName, pid);
            throw new IOException("Proceso de servicio no verificado.");
        }
    }

    private async Task ReadLoopAsync(NamedPipeClientStream pipe, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            var message = await PipeProtocol.ReadAsync(pipe, ct).ConfigureAwait(false);
            if (message is null)
                return; // el servicio cerró la conexión

            if (message.Type == MessageTypes.Response)
            {
                if (message.CorrelationId is { } id && _pending.TryRemove(id, out var tcs))
                    tcs.TrySetResult(message);
                continue;
            }

            try { DispatchEvent(message); }
            catch (Exception ex) { Log.Warning(ex, "Error procesando el evento {Type}", message.Type); }
        }
    }

    private void DispatchEvent(PipeMessage m)
    {
        switch (m.Type)
        {
            case MessageTypes.EventThreatDetected:
                if (m.GetPayload(Json.DetectionDto) is { } d) ThreatDetected?.Invoke(d);
                break;
            case MessageTypes.EventCheatWarning:
                if (m.GetPayload(Json.CheatWarningDto) is { } w) CheatWarning?.Invoke(w);
                break;
            case MessageTypes.EventScanProgress:
                if (m.GetPayload(Json.ScanProgressDto) is { } p) ScanProgress?.Invoke(p);
                break;
            case MessageTypes.EventScanCompleted:
                if (m.GetPayload(Json.ScanSummaryDto) is { } s) ScanCompleted?.Invoke(s);
                break;
            case MessageTypes.EventGameModeChanged:
                if (m.GetPayload(Json.GameModeDto) is { } g) GameModeChanged?.Invoke(g);
                break;
        }
    }

    private void SetConnected(bool value)
    {
        _connected = value;
        Log.Information(value ? "Conectado al servicio" : "Desconectado del servicio");
        ConnectionChanged?.Invoke(value);
    }

    private void FailPending()
    {
        foreach (var id in _pending.Keys.ToList())
            if (_pending.TryRemove(id, out var tcs))
                tcs.TrySetException(new ServiceUnavailableException("Se perdió la conexión con el servicio."));
    }

    // ---------------- Peticiones ----------------

    private async Task<PipeMessage> SendAsync(PipeMessage request, TimeSpan? timeout = null)
    {
        var pipe = _pipe;
        if (!_connected || pipe is null)
            throw new ServiceUnavailableException("El servicio de FragGuard no está en ejecución.");

        string id = Guid.NewGuid().ToString("N");
        request.CorrelationId = id;
        var tcs = new TaskCompletionSource<PipeMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
        _pending[id] = tcs;

        try
        {
            await _writeLock.WaitAsync().ConfigureAwait(false);
            try { await PipeProtocol.WriteAsync(pipe, request, _cts.Token).ConfigureAwait(false); }
            finally { _writeLock.Release(); }

            var response = await tcs.Task.WaitAsync(timeout ?? DefaultTimeout).ConfigureAwait(false);
            if (response.Error == MessageTypes.ErrorElevationRequired)
                throw new ElevationRequiredException();
            if (response.Error is { } error)
                throw new ServiceErrorException(error);
            return response;
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException or TimeoutException)
        {
            throw new ServiceUnavailableException("No hay respuesta del servicio de FragGuard.");
        }
        finally
        {
            _pending.TryRemove(id, out _);
        }
    }

    private async Task<TRes> RequestAsync<TRes>(string type, JsonTypeInfo<TRes> resType)
    {
        var response = await SendAsync(PipeProtocol.Create(type)).ConfigureAwait(false);
        return response.GetPayload(resType) ?? throw new ServiceErrorException("Respuesta vacía del servicio.");
    }

    private async Task<TRes> RequestAsync<TReq, TRes>(string type, TReq payload, JsonTypeInfo<TReq> reqType, JsonTypeInfo<TRes> resType)
    {
        var response = await SendAsync(PipeProtocol.Create(type, payload, reqType)).ConfigureAwait(false);
        return response.GetPayload(resType) ?? throw new ServiceErrorException("Respuesta vacía del servicio.");
    }

    /// <summary>Lanza ServiceErrorException si el servicio devolvió Success = false.</summary>
    private static OperationResult EnsureOk(OperationResult r) =>
        r.Success ? r : throw new ServiceErrorException(r.Message ?? "La operación no se pudo completar.");

    // ---------------- API tipada ----------------

    public Task<StatusDto> GetStatusAsync() => RequestAsync(MessageTypes.GetStatus, Json.StatusDto);

    public async Task<OperationResult> StartScanAsync(ScanRequest request) =>
        EnsureOk(await RequestAsync(MessageTypes.StartScan, request, Json.ScanRequest, Json.OperationResult).ConfigureAwait(false));

    public async Task CancelScanAsync() => EnsureOk(await RequestAsync(MessageTypes.CancelScan, Json.OperationResult).ConfigureAwait(false));
    public async Task PauseScanAsync() => EnsureOk(await RequestAsync(MessageTypes.PauseScan, Json.OperationResult).ConfigureAwait(false));
    public async Task ResumeScanAsync() => EnsureOk(await RequestAsync(MessageTypes.ResumeScan, Json.OperationResult).ConfigureAwait(false));

    public Task<List<ScanSummaryDto>> GetHistoryAsync(int limit) =>
        RequestAsync(MessageTypes.GetHistory, new LimitRequest { Limit = limit }, Json.LimitRequest, Json.ListScanSummaryDto);

    public Task<List<DetectionDto>> GetDetectionsAsync(int limit) =>
        RequestAsync(MessageTypes.GetDetections, new LimitRequest { Limit = limit }, Json.LimitRequest, Json.ListDetectionDto);

    public Task<List<QuarantineItemDto>> ListQuarantineAsync() => RequestAsync(MessageTypes.ListQuarantine, Json.ListQuarantineItemDto);

    public async Task<OperationResult> RestoreQuarantineAsync(string id) =>
        EnsureOk(await RequestAsync(MessageTypes.RestoreQuarantine, new IdRequest { Id = id }, Json.IdRequest, Json.OperationResult).ConfigureAwait(false));

    public async Task DeleteQuarantineAsync(string id) =>
        EnsureOk(await RequestAsync(MessageTypes.DeleteQuarantine, new IdRequest { Id = id }, Json.IdRequest, Json.OperationResult).ConfigureAwait(false));

    public Task<FragGuardSettings> GetSettingsAsync() => RequestAsync(MessageTypes.GetSettings, Json.FragGuardSettings);

    public async Task UpdateSettingsAsync(FragGuardSettings settings) =>
        EnsureOk(await RequestAsync(MessageTypes.UpdateSettings, settings, Json.FragGuardSettings, Json.OperationResult).ConfigureAwait(false));

    public async Task SetVirusTotalKeyAsync(string? apiKey) =>
        EnsureOk(await RequestAsync(MessageTypes.SetVirusTotalKey, new SetVirusTotalKeyRequest { ApiKey = apiKey }, Json.SetVirusTotalKeyRequest, Json.OperationResult).ConfigureAwait(false));

    public Task ReportFullscreenAsync(bool isFullscreen, string? processName) =>
        RequestAsync(MessageTypes.FullscreenChanged, new FullscreenChangedRequest { IsFullscreen = isFullscreen, ProcessName = processName },
            Json.FullscreenChangedRequest, Json.OperationResult);

    public Task RegisterUserFoldersAsync(string? downloads, string? desktop) =>
        RequestAsync(MessageTypes.RegisterUserFolders, new RegisterUserFoldersRequest { DownloadsFolder = downloads, DesktopFolder = desktop },
            Json.RegisterUserFoldersRequest, Json.OperationResult);

    /// <summary>Lista de juegos instalados. Escanear las bibliotecas puede tardar unos segundos la primera vez.</summary>
    public async Task<List<GameDto>> ListGamesAsync(bool forceRefresh)
    {
        var response = await SendAsync(PipeProtocol.Create(MessageTypes.ListGames, new ListGamesRequest { ForceRefresh = forceRefresh }, Json.ListGamesRequest),
            TimeSpan.FromSeconds(90)).ConfigureAwait(false);
        return response.GetPayload(Json.ListGameDto) ?? new List<GameDto>();
    }

    public async Task KillProcessAsync(int pid) =>
        EnsureOk(await RequestAsync(MessageTypes.KillProcess, new KillProcessRequest { ProcessId = pid }, Json.KillProcessRequest, Json.OperationResult).ConfigureAwait(false));

    public void Dispose()
    {
        _cts.Cancel();
        _pipe?.Dispose();
        _cts.Dispose();
    }
}
