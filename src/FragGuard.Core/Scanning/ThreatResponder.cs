using FragGuard.Core.Configuration;
using FragGuard.Core.Data;
using FragGuard.Core.Quarantine;
using FragGuard.Shared.Models;
using Microsoft.Extensions.Logging;

namespace FragGuard.Core.Scanning;

/// <summary>
/// Decide qué hacer con un archivo detectado (cuarentena automática o solo aviso),
/// lo registra en el historial y emite el evento <see cref="ThreatDetected"/> (el servicio lo reenvía a la UI).
/// </summary>
public sealed class ThreatResponder
{
    private readonly QuarantineManager _quarantine;
    private readonly DetectionRepository _detections;
    private readonly SettingsStore _settings;
    private readonly ILogger<ThreatResponder> _logger;

    public ThreatResponder(QuarantineManager quarantine, DetectionRepository detections, SettingsStore settings, ILogger<ThreatResponder> logger)
    {
        _quarantine = quarantine;
        _detections = detections;
        _settings = settings;
        _logger = logger;
    }

    public event Action<DetectionDto>? ThreatDetected;

    public async Task<DetectionDto?> HandleAsync(FileScanResult result, string? scanId, ScanKind kind, CancellationToken ct)
    {
        if (!result.IsThreat)
            return null;

        var detection = new DetectionDto
        {
            ScanId = scanId,
            ScanKind = kind,
            FilePath = result.Path,
            Sha256 = result.Sha256,
            Verdict = result.Verdict,
            Threats = result.Threats.ToList(),
            DetectedUtc = DateTime.UtcNow,
            Action = ThreatAction.Warned,
            SourceUrl = result.SourceUrl,
            Signer = result.Signer
        };

        // Solo lo MALICIOSO va a cuarentena automática. Lo sospechoso (heurística, 1-2 motores de VT) se avisa.
        if (result.Verdict == FileVerdict.Malicious && _settings.Current.AutoQuarantine && result.Sha256 is not null)
        {
            var outcome = await _quarantine.QuarantineAsync(result.Path, result.Sha256, detection.PrimaryThreatName, ct).ConfigureAwait(false);
            detection.Action = outcome.Action;
            detection.QuarantineId = outcome.QuarantineId;
        }

        try
        {
            detection.Id = _detections.Add(detection);
        }
        catch (Exception ex)
        {
            // Si la BD falla seguimos: la cuarentena ya se hizo y el aviso debe llegar al usuario.
            _logger.LogError(ex, "No se pudo registrar la detección de {Path}", result.Path);
        }

        _logger.LogWarning("Amenaza {Verdict}: {Path} [{Threats}] -> {Action}",
            detection.Verdict, detection.FilePath, string.Join(", ", detection.Threats.Select(t => t.Name)), detection.Action);

        try { ThreatDetected?.Invoke(detection); }
        catch (Exception ex) { _logger.LogError(ex, "Error en un suscriptor de ThreatDetected"); }

        return detection;
    }
}
