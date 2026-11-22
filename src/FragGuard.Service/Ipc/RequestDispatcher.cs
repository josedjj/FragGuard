using System.Text.Json;
using System.Text.Json.Serialization.Metadata;
using FragGuard.Core.Configuration;
using FragGuard.Core.Data;
using FragGuard.Core.Quarantine;
using FragGuard.Service.GameMode;
using FragGuard.Service.Infrastructure;
using FragGuard.Service.Scanning;
using FragGuard.Service.Status;
using FragGuard.Shared.Ipc;
using FragGuard.Shared.Models;
using Microsoft.Extensions.Logging;

namespace FragGuard.Service.Ipc;

/// <summary>
/// Traduce cada petición del pipe en una llamada al motor/servicio y construye la respuesta.
/// Cualquier excepción se convierte en una respuesta con Error: un fallo nunca tumba la conexión ni el servicio.
/// </summary>
public sealed class RequestDispatcher
{
    private static readonly FragGuardJsonContext Json = FragGuardJsonContext.Default;

    private readonly StatusProvider _status;
    private readonly ScanCoordinator _scans;
    private readonly ScanHistoryRepository _history;
    private readonly DetectionRepository _detections;
    private readonly QuarantineManager _quarantine;
    private readonly SettingsStore _settings;
    private readonly GameModeService _gameMode;
    private readonly UserFolderRegistry _userFolders;
    private readonly FragGuard.Core.Games.GameLibrary _games;
    private readonly Updates.RulesUpdateService _rulesUpdates;
    private readonly Protection.ProtectionStatusProvider _protection;
    private readonly Protection.AutorunManager _autoruns;
    private readonly Protection.PrivacyMonitorService _privacy;
    private readonly Protection.MemoryScanService _memory;
    private readonly ILogger<RequestDispatcher> _logger;

    public RequestDispatcher(StatusProvider status, ScanCoordinator scans, ScanHistoryRepository history, DetectionRepository detections,
        QuarantineManager quarantine, SettingsStore settings, GameModeService gameMode, UserFolderRegistry userFolders,
        FragGuard.Core.Games.GameLibrary games, Updates.RulesUpdateService rulesUpdates,
        Protection.ProtectionStatusProvider protection, Protection.AutorunManager autoruns, Protection.PrivacyMonitorService privacy,
        Protection.MemoryScanService memory, ILogger<RequestDispatcher> logger)
    {
        _protection = protection;
        _autoruns = autoruns;
        _privacy = privacy;
        _memory = memory;
        _games = games;
        _rulesUpdates = rulesUpdates;
        _status = status;
        _scans = scans;
        _history = history;
        _detections = detections;
        _quarantine = quarantine;
        _settings = settings;
        _gameMode = gameMode;
        _userFolders = userFolders;
        _logger = logger;
    }

    /// <summary>
    /// Operaciones que pueden DEBILITAR la protección: exigen administrador elevado.
    /// Sin esto, un malware ejecutándose como el usuario podría desactivar el tiempo real, añadir
    /// exclusiones o restaurarse a sí mismo de la cuarentena a través del pipe.
    /// </summary>
    private static readonly HashSet<string> SensitiveOperations = new(StringComparer.Ordinal)
    {
        MessageTypes.UpdateSettings,
        MessageTypes.SetVirusTotalKey,
        MessageTypes.SetAbuseChKey,
        MessageTypes.RestoreQuarantine,
        MessageTypes.DeleteQuarantine,
        MessageTypes.KillProcess,
        MessageTypes.DisableAutorun,
        MessageTypes.RestoreAutorun
    };

    /// <summary>Se puede desactivar (solo para desarrollo) con FragGuard:RequireAdminForSensitiveOperations = false.</summary>
    public bool RequireAdminForSensitiveOperations { get; set; } = true;

    public async Task<PipeMessage> HandleAsync(PipeMessage request, ClientConnection client, CancellationToken ct)
    {
        string? id = request.CorrelationId;

        if (RequireAdminForSensitiveOperations && SensitiveOperations.Contains(request.Type) && !client.IsElevatedAdmin)
        {
            _logger.LogWarning("Operación {Type} denegada a {User}: requiere administrador elevado", request.Type, client.User);
            return Error(id, MessageTypes.ErrorElevationRequired);
        }

        try
        {
            switch (request.Type)
            {
                case MessageTypes.GetStatus:
                    return Reply(id, _status.Get(), Json.StatusDto);

                case MessageTypes.StartScan:
                {
                    var req = Require(request, Json.ScanRequest);
                    _logger.LogInformation("{User} solicita escaneo {Kind} {Path}", client.User, req.Kind, req.CustomPath);
                    return Reply(id, _scans.Start(req), Json.OperationResult);
                }
                case MessageTypes.CancelScan:
                    return Reply(id, _scans.Cancel(), Json.OperationResult);
                case MessageTypes.PauseScan:
                    return Reply(id, _scans.Pause(), Json.OperationResult);
                case MessageTypes.ResumeScan:
                    return Reply(id, _scans.Resume(), Json.OperationResult);

                case MessageTypes.GetHistory:
                    return Reply(id, _history.GetRecent(ClampLimit(request)), Json.ListScanSummaryDto);
                case MessageTypes.GetDetections:
                    return Reply(id, _detections.GetRecent(ClampLimit(request)), Json.ListDetectionDto);

                case MessageTypes.ListQuarantine:
                    return Reply(id, _quarantine.List(), Json.ListQuarantineItemDto);
                case MessageTypes.RestoreQuarantine:
                {
                    var req = Require(request, Json.IdRequest);
                    _logger.LogWarning("{User} restaura de cuarentena {Id}", client.User, req.Id);
                    var (ok, msg) = await _quarantine.RestoreAsync(req.Id, ct).ConfigureAwait(false);
                    return Reply(id, ok ? OperationResult.Ok(msg) : OperationResult.Fail(msg), Json.OperationResult);
                }
                case MessageTypes.DeleteQuarantine:
                {
                    var req = Require(request, Json.IdRequest);
                    _logger.LogInformation("{User} elimina de cuarentena {Id}", client.User, req.Id);
                    var (ok, msg) = await _quarantine.DeleteAsync(req.Id, ct).ConfigureAwait(false);
                    return Reply(id, ok ? OperationResult.Ok(msg) : OperationResult.Fail(msg), Json.OperationResult);
                }

                case MessageTypes.GetSettings:
                    return Reply(id, _settings.GetForClient(), Json.FragGuardSettings);
                case MessageTypes.UpdateSettings:
                {
                    var req = Require(request, Json.FragGuardSettings);
                    _logger.LogInformation("{User} actualiza la configuración", client.User);
                    _settings.Update(req);
                    return Reply(id, OperationResult.Ok(), Json.OperationResult);
                }
                case MessageTypes.SetVirusTotalKey:
                {
                    var req = Require(request, Json.SetVirusTotalKeyRequest);
                    _logger.LogInformation("{User} cambia la clave de VirusTotal", client.User);
                    _settings.SetVirusTotalKey(req.ApiKey);
                    return Reply(id, OperationResult.Ok(), Json.OperationResult);
                }

                case MessageTypes.SetAbuseChKey:
                {
                    var req = Require(request, Json.SetVirusTotalKeyRequest);
                    _logger.LogInformation("{User} cambia la Auth-Key de abuse.ch", client.User);
                    _settings.SetAbuseChKey(req.ApiKey);
                    return Reply(id, OperationResult.Ok(), Json.OperationResult);
                }
                case MessageTypes.CheckRuleUpdates:
                {
                    var result = await _rulesUpdates.CheckNowAsync(ct).ConfigureAwait(false);
                    bool ok = result.Outcome is Core.Updates.RulesUpdateOutcome.Applied or Core.Updates.RulesUpdateOutcome.UpToDate or Core.Updates.RulesUpdateOutcome.NotAvailable;
                    return Reply(id, new OperationResult { Success = ok, Message = _rulesUpdates.LastResult }, Json.OperationResult);
                }

                case MessageTypes.GetProtectionStatus:
                    return Reply(id, _protection.Get(), Json.ProtectionStatusDto);
                case MessageTypes.ListAutoruns:
                    return Reply(id, await Task.Run(_autoruns.List, ct).ConfigureAwait(false), Json.ListAutorunEntryDto);
                case MessageTypes.DisableAutorun:
                {
                    var req = Require(request, Json.IdRequest);
                    _logger.LogWarning("{User} desactiva el programa de inicio {Id}", client.User, req.Id);
                    return Reply(id, _autoruns.Disable(req.Id), Json.OperationResult);
                }
                case MessageTypes.RestoreAutorun:
                {
                    var req = Require(request, Json.IdRequest);
                    _logger.LogInformation("{User} restaura el programa de inicio {Id}", client.User, req.Id);
                    return Reply(id, _autoruns.Restore(req.Id), Json.OperationResult);
                }
                case MessageTypes.GetDeviceUsage:
                    return Reply(id, _privacy.Read(), Json.ListDeviceUsageDto);
                case MessageTypes.ScanMemory:
                    _logger.LogInformation("{User} solicita un escaneo de memoria", client.User);
                    return Reply(id, _memory.Start(), Json.OperationResult);

                case MessageTypes.FullscreenChanged:
                {
                    var req = Require(request, Json.FullscreenChangedRequest);
                    _gameMode.ReportFullscreen(client.Id, req.IsFullscreen, req.ProcessName);
                    return Reply(id, OperationResult.Ok(), Json.OperationResult);
                }
                case MessageTypes.RegisterUserFolders:
                {
                    var req = Require(request, Json.RegisterUserFoldersRequest);
                    _userFolders.Register(req.DownloadsFolder, req.DesktopFolder);
                    return Reply(id, OperationResult.Ok(), Json.OperationResult);
                }
                case MessageTypes.ListGames:
                {
                    var req = request.GetPayload(Json.ListGamesRequest) ?? new ListGamesRequest();
                    var games = await _games.GetGamesAsync(req.ForceRefresh, ct).ConfigureAwait(false);
                    return Reply(id, games, Json.ListGameDto);
                }

                case MessageTypes.KillProcess:
                {
                    var req = Require(request, Json.KillProcessRequest);
                    _logger.LogWarning("{User} pide cerrar el proceso {Pid}", client.User, req.ProcessId);
                    return Reply(id, _gameMode.KillFlaggedProcess(req.ProcessId), Json.OperationResult);
                }

                default:
                    return Error(id, $"Tipo de mensaje desconocido: {request.Type}");
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (ex is JsonException or InvalidDataException or ArgumentException)
        {
            return Error(id, "Petición mal formada: " + ex.Message);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error procesando {Type}", request.Type);
            return Error(id, "Error interno del servicio.");
        }
    }

    public void ClientDisconnected(ClientConnection client) => _gameMode.ClientDisconnected(client.Id);

    private static T Require<T>(PipeMessage request, JsonTypeInfo<T> typeInfo) =>
        request.GetPayload(typeInfo) ?? throw new InvalidDataException("Falta el contenido de la petición.");

    private static int ClampLimit(PipeMessage request) =>
        Math.Clamp(request.GetPayload(Json.LimitRequest)?.Limit ?? 50, 1, 500);

    private static PipeMessage Reply<T>(string? correlationId, T payload, JsonTypeInfo<T> typeInfo) =>
        PipeProtocol.Create(MessageTypes.Response, payload, typeInfo, correlationId);

    private static PipeMessage Error(string? correlationId, string error) => new()
    {
        Type = MessageTypes.Response,
        CorrelationId = correlationId,
        Error = error
    };
}
