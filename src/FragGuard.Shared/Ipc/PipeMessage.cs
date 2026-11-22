using System.Text.Json;

namespace FragGuard.Shared.Ipc;

/// <summary>
/// Sobre común de todos los mensajes del pipe.
/// - Peticiones UI → servicio: Type = MessageTypes.*, CorrelationId = GUID generado por la UI.
/// - Respuestas servicio → UI: Type = MessageTypes.Response, mismo CorrelationId, Error != null si falló.
/// - Eventos servicio → UI (push): Type = MessageTypes.Event*, CorrelationId = null.
/// </summary>
public sealed class PipeMessage
{
    public string Type { get; set; } = "";
    public string? CorrelationId { get; set; }
    public JsonElement? Payload { get; set; }
    public string? Error { get; set; }
}

/// <summary>Tipos de mensaje del protocolo.</summary>
public static class MessageTypes
{
    // ----- Peticiones (UI → servicio) -----
    public const string GetStatus = "GetStatus";
    public const string StartScan = "StartScan";
    public const string CancelScan = "CancelScan";
    public const string PauseScan = "PauseScan";
    public const string ResumeScan = "ResumeScan";
    public const string GetHistory = "GetHistory";
    public const string GetDetections = "GetDetections";
    public const string ListQuarantine = "ListQuarantine";
    public const string RestoreQuarantine = "RestoreQuarantine";
    public const string DeleteQuarantine = "DeleteQuarantine";
    public const string GetSettings = "GetSettings";
    public const string UpdateSettings = "UpdateSettings";
    public const string SetVirusTotalKey = "SetVirusTotalKey";
    /// <summary>Guarda la Auth-Key de abuse.ch (mismo payload que SetVirusTotalKey).</summary>
    public const string SetAbuseChKey = "SetAbuseChKey";
    /// <summary>La UI informa de que hay (o no) una app a pantalla completa en la sesión del usuario.</summary>
    public const string FullscreenChanged = "FullscreenChanged";
    /// <summary>La UI envía las carpetas conocidas del usuario (Descargas, Escritorio) resueltas en su sesión.</summary>
    public const string RegisterUserFolders = "RegisterUserFolders";
    public const string KillProcess = "KillProcess";
    /// <summary>Lista de juegos instalados (solo lectura).</summary>
    public const string ListGames = "ListGames";
    /// <summary>Comprobar ahora el canal firmado de reglas.</summary>
    public const string CheckRuleUpdates = "CheckRuleUpdates";
    /// <summary>Estado de los módulos de protección en ejecución.</summary>
    public const string GetProtectionStatus = "GetProtectionStatus";
    /// <summary>Programas de inicio (registro, carpeta Inicio, tareas, servicios).</summary>
    public const string ListAutoruns = "ListAutoruns";
    /// <summary>Desactivar un programa de inicio (IdRequest). Requiere administrador.</summary>
    public const string DisableAutorun = "DisableAutorun";
    /// <summary>Restaurar un programa de inicio desactivado por FragGuard (IdRequest). Requiere administrador.</summary>
    public const string RestoreAutorun = "RestoreAutorun";
    /// <summary>Uso reciente de cámara y micrófono.</summary>
    public const string GetDeviceUsage = "GetDeviceUsage";
    /// <summary>Escaneo de la memoria de los procesos en ejecución (no se permite en modo juego).</summary>
    public const string ScanMemory = "ScanMemory";
    /// <summary>Estado del DNS protegido (Quad9). Success = activo; Message = detalle.</summary>
    public const string GetDnsProtection = "GetDnsProtection";
    /// <summary>Activar/desactivar el DNS protegido (ToggleRequest). Requiere administrador.</summary>
    public const string SetDnsProtection = "SetDnsProtection";

    // ----- Respuesta -----
    public const string Response = "Response";

    /// <summary>
    /// Valor de PipeMessage.Error cuando la operación exige administrador elevado
    /// (cambiar configuración, restaurar/eliminar de cuarentena, cerrar procesos).
    /// </summary>
    public const string ErrorElevationRequired = "ELEVATION_REQUIRED";

    // ----- Eventos (servicio → UI) -----
    public const string EventScanProgress = "Event.ScanProgress";
    public const string EventScanCompleted = "Event.ScanCompleted";
    public const string EventThreatDetected = "Event.ThreatDetected";
    public const string EventCheatWarning = "Event.CheatWarning";
    public const string EventGameModeChanged = "Event.GameModeChanged";
}

// ----- Payloads auxiliares de peticiones -----

public sealed class IdRequest
{
    public string Id { get; set; } = "";
}

public sealed class LimitRequest
{
    public int Limit { get; set; } = 50;
}

public sealed class SetVirusTotalKeyRequest
{
    /// <summary>Clave en claro (solo viaja por el pipe local). null o vacío = borrar la clave.</summary>
    public string? ApiKey { get; set; }
}

public sealed class FullscreenChangedRequest
{
    public bool IsFullscreen { get; set; }
    public string? ProcessName { get; set; }
}

/// <summary>
/// Carpetas conocidas del usuario resueltas en SU sesión (el servicio corre como SYSTEM y no puede usar
/// Environment.GetFolderPath para el usuario). Descargas se vigila en tiempo real; Escritorio entra en el escaneo rápido.
/// </summary>
public sealed class RegisterUserFoldersRequest
{
    public string? DownloadsFolder { get; set; }
    public string? DesktopFolder { get; set; }
}

public sealed class ToggleRequest
{
    public bool Enabled { get; set; }
}

public sealed class KillProcessRequest
{
    public int ProcessId { get; set; }
}

public sealed class OperationResult
{
    public bool Success { get; set; }
    public string? Message { get; set; }

    public static OperationResult Ok(string? msg = null) => new() { Success = true, Message = msg };
    public static OperationResult Fail(string msg) => new() { Success = false, Message = msg };
}
