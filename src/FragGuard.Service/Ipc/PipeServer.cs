using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using FragGuard.Core.Scanning;
using FragGuard.Shared;
using FragGuard.Shared.Ipc;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace FragGuard.Service.Ipc;

/// <summary>
/// Servidor del named pipe \\.\pipe\FragGuard.v1.
///
/// Seguridad:
///  - ACL: SYSTEM y Administradores (control total), usuarios autenticados (lectura/escritura).
///    Se DENIEGA explícitamente el acceso por red: el pipe solo es accesible localmente.
///  - La primera instancia se crea con FirstPipeInstance: si otro proceso ya hubiera creado un pipe
///    con este nombre (para suplantar al servicio), fallamos en lugar de compartirlo.
///  - Cada mensaje está limitado a 4 MB (PipeProtocol) y los errores de un cliente no afectan a los demás.
/// </summary>
public sealed class PipeServer : BackgroundService
{
    private const int MaxClients = 8;

    private readonly RequestDispatcher _dispatcher;
    private readonly EventBroadcaster _broadcaster;
    private readonly ThreatResponder _responder;
    private readonly ILogger<PipeServer> _logger;

    public PipeServer(RequestDispatcher dispatcher, EventBroadcaster broadcaster, ThreatResponder responder, ILogger<PipeServer> logger)
    {
        _dispatcher = dispatcher;
        _broadcaster = broadcaster;
        _responder = responder;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        // Las detecciones del motor (tiempo real o escaneos) se reenvían a todas las UIs conectadas.
        _responder.ThreatDetected += d => _broadcaster.Publish(MessageTypes.EventThreatDetected, d, FragGuardJsonContext.Default.DetectionDto);

        var security = CreatePipeSecurity();
        bool first = true;
        _logger.LogInformation("Pipe escuchando en \\\\.\\pipe\\{Pipe}", AppInfo.PipeName);

        while (!ct.IsCancellationRequested)
        {
            NamedPipeServerStream pipe;
            try
            {
                pipe = NamedPipeServerStreamAcl.Create(
                    AppInfo.PipeName,
                    PipeDirection.InOut,
                    MaxClients,
                    PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous | (first ? PipeOptions.FirstPipeInstance : PipeOptions.None),
                    inBufferSize: 0,
                    outBufferSize: 0,
                    security);
                first = false;
            }
            catch (UnauthorizedAccessException) when (first)
            {
                // Con FirstPipeInstance, "acceso denegado" significa que el pipe ya existe y es de otro proceso.
                _logger.LogCritical("Ya existe un pipe llamado {Pipe} creado por otro proceso. ¿Otra instancia del servicio o un intento de suplantación? Reintentando en 10 s", AppInfo.PipeName);
                await Task.Delay(TimeSpan.FromSeconds(10), ct).ConfigureAwait(false);
                continue;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // Todas las instancias ocupadas u otro error transitorio: NUNCA dejamos morir el servidor del pipe
                // (el servicio seguiría vivo pero la UI ya no podría conectarse).
                _logger.LogWarning("No se pudo crear otra instancia del pipe: {Error}. Reintentando…", ex.Message);
                await Task.Delay(1000, ct).ConfigureAwait(false);
                continue;
            }

            try
            {
                await pipe.WaitForConnectionAsync(ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                await pipe.DisposeAsync().ConfigureAwait(false);
                break;
            }
            catch (IOException ex)
            {
                _logger.LogDebug("Fallo aceptando conexión: {Error}", ex.Message);
                await pipe.DisposeAsync().ConfigureAwait(false);
                continue;
            }

            var connection = new ClientConnection(pipe, _dispatcher, _broadcaster, _logger);
            _ = Task.Run(() => connection.RunAsync(ct), CancellationToken.None);
        }
    }

    private static PipeSecurity CreatePipeSecurity()
    {
        var security = new PipeSecurity();
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var users = new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null);
        var network = new SecurityIdentifier(WellKnownSidType.NetworkSid, null);

        // La identidad del propio servicio necesita control total para crear instancias adicionales del pipe
        // (CreateNewInstance). Instalado es SYSTEM; en desarrollo es el usuario que lo ejecuta.
        using var self = WindowsIdentity.GetCurrent();

        security.AddAccessRule(new PipeAccessRule(network, PipeAccessRights.FullControl, AccessControlType.Deny));
        security.AddAccessRule(new PipeAccessRule(self.User!, PipeAccessRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(system, PipeAccessRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(admins, PipeAccessRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(users, PipeAccessRights.ReadWrite, AccessControlType.Allow));
        return security;
    }
}
