using System.IO.Pipes;
using System.Threading.Channels;
using FragGuard.Shared.Ipc;
using Microsoft.Extensions.Logging;

namespace FragGuard.Service.Ipc;

/// <summary>
/// Una UI conectada por el pipe.
/// - Lectura: bucle que procesa peticiones de una en una y responde con el mismo CorrelationId.
/// - Escritura: TODO (respuestas y eventos) pasa por una cola con un único escritor, así nunca se mezclan
///   dos mensajes en el pipe. Si la UI deja de leer, la cola descarta los eventos más antiguos
///   en lugar de crecer sin límite.
/// </summary>
public sealed class ClientConnection
{
    private readonly NamedPipeServerStream _pipe;
    private readonly RequestDispatcher _dispatcher;
    private readonly EventBroadcaster _broadcaster;
    private readonly ILogger _logger;
    private readonly Channel<PipeMessage> _outbox = Channel.CreateBounded<PipeMessage>(
        new BoundedChannelOptions(256) { FullMode = BoundedChannelFullMode.DropOldest, SingleReader = true });

    public ClientConnection(NamedPipeServerStream pipe, RequestDispatcher dispatcher, EventBroadcaster broadcaster, ILogger logger)
    {
        _pipe = pipe;
        _dispatcher = dispatcher;
        _broadcaster = broadcaster;
        _logger = logger;
    }

    public Guid Id { get; } = Guid.NewGuid();
    public string User { get; private set; } = "?";

    /// <summary>
    /// True si el cliente es un administrador con el token ELEVADO (o SYSTEM).
    /// Se comprueba suplantando al cliente (nivel Identification): no se puede falsificar desde el cliente.
    /// </summary>
    public bool IsElevatedAdmin { get; private set; }

    private bool CheckElevatedAdmin()
    {
        bool result = false;
        try
        {
            _pipe.RunAsClient(() =>
            {
                using var identity = System.Security.Principal.WindowsIdentity.GetCurrent(ifImpersonating: true)
                                     ?? System.Security.Principal.WindowsIdentity.GetCurrent();
                result = identity.IsSystem ||
                         new System.Security.Principal.WindowsPrincipal(identity).IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
            });
        }
        catch (Exception ex)
        {
            // Sin privilegio de suplantación (servicio ejecutado como usuario normal en desarrollo): no elevado.
            _logger.LogDebug("No se pudo comprobar la elevación del cliente: {Error}", ex.Message);
        }
        return result;
    }

    public void PostEvent(PipeMessage message) => _outbox.Writer.TryWrite(message);

    public async Task RunAsync(CancellationToken serviceToken)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(serviceToken);
        try
        {
            // Nombre del usuario que se conecta (para auditar operaciones sensibles en el log).
            try { User = _pipe.GetImpersonationUserName(); } catch { User = "desconocido"; }
            IsElevatedAdmin = CheckElevatedAdmin();
            _logger.LogInformation("UI conectada ({User}, admin elevado: {Admin}, {Id})", User, IsElevatedAdmin, Id);

            _broadcaster.Register(this);
            var writer = WriteLoopAsync(cts.Token);

            while (!cts.IsCancellationRequested)
            {
                PipeMessage? request = await PipeProtocol.ReadAsync(_pipe, cts.Token).ConfigureAwait(false);
                if (request is null)
                    break; // la UI cerró la conexión

                PipeMessage response = await _dispatcher.HandleAsync(request, this, cts.Token).ConfigureAwait(false);
                await _outbox.Writer.WriteAsync(response, cts.Token).ConfigureAwait(false);
            }

            cts.Cancel();
            try { await writer.ConfigureAwait(false); } catch (OperationCanceledException) { }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex) when (ex is IOException or InvalidDataException or ObjectDisposedException or System.Text.Json.JsonException)
        {
            // Cliente roto o malicioso: cerramos esta conexión; el servicio sigue.
            _logger.LogDebug("Conexión {Id} cerrada: {Error}", Id, ex.Message);
        }
        finally
        {
            _broadcaster.Unregister(this);
            _dispatcher.ClientDisconnected(this);
            _outbox.Writer.TryComplete();
            await _pipe.DisposeAsync().ConfigureAwait(false);
            _logger.LogInformation("UI desconectada ({User}, {Id})", User, Id);
        }
    }

    private async Task WriteLoopAsync(CancellationToken ct)
    {
        await foreach (var message in _outbox.Reader.ReadAllAsync(ct).ConfigureAwait(false))
        {
            // Si la UI no lee en 10 s, la consideramos colgada.
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromSeconds(10));
            await PipeProtocol.WriteAsync(_pipe, message, timeout.Token).ConfigureAwait(false);
        }
    }
}
