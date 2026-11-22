using System.Text.Json;
using System.Text.Json.Serialization;
using FragGuard.Shared.Models;

namespace FragGuard.Shared.Ipc;

/// <summary>
/// Contexto de System.Text.Json generado en compilación: evita reflexión en tiempo de ejecución
/// (menos RAM y arranque más rápido, importante para el objetivo de ~50 MB del servicio).
/// </summary>
[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    UseStringEnumConverter = true,
    WriteIndented = false)]
[JsonSerializable(typeof(PipeMessage))]
[JsonSerializable(typeof(StatusDto))]
[JsonSerializable(typeof(ScanRequest))]
[JsonSerializable(typeof(ScanProgressDto))]
[JsonSerializable(typeof(ScanSummaryDto))]
[JsonSerializable(typeof(List<ScanSummaryDto>))]
[JsonSerializable(typeof(DetectionDto))]
[JsonSerializable(typeof(List<DetectionDto>))]
[JsonSerializable(typeof(QuarantineItemDto))]
[JsonSerializable(typeof(List<QuarantineItemDto>))]
[JsonSerializable(typeof(FragGuardSettings))]
[JsonSerializable(typeof(CheatWarningDto))]
[JsonSerializable(typeof(GameModeDto))]
[JsonSerializable(typeof(IdRequest))]
[JsonSerializable(typeof(LimitRequest))]
[JsonSerializable(typeof(SetVirusTotalKeyRequest))]
[JsonSerializable(typeof(FullscreenChangedRequest))]
[JsonSerializable(typeof(RegisterUserFoldersRequest))]
[JsonSerializable(typeof(KillProcessRequest))]
[JsonSerializable(typeof(OperationResult))]
[JsonSerializable(typeof(List<ThreatInfo>))]
[JsonSerializable(typeof(GameDto))]
[JsonSerializable(typeof(List<GameDto>))]
[JsonSerializable(typeof(ListGamesRequest))]
public partial class FragGuardJsonContext : JsonSerializerContext
{
    private static readonly Lazy<FragGuardJsonContext> IndentedLazy = new(() => new FragGuardJsonContext(new JsonSerializerOptions
    {
        // Mismas convenciones que el contexto por defecto, pero con sangría (settings.json legible por humanos).
        // Ojo: no se puede reutilizar Default.Options porque ya está ligado a otro contexto.
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter() },
        WriteIndented = true
    }));

    /// <summary>Contexto con salida indentada para el archivo settings.json.</summary>
    public static FragGuardJsonContext Indented => IndentedLazy.Value;
}
