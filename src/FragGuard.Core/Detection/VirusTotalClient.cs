using System.Net;
using System.Text.Json;
using System.Threading.RateLimiting;
using Microsoft.Extensions.Logging;

namespace FragGuard.Core.Detection;

public enum VtStatus
{
    NotConfigured,
    /// <summary>Sin cuota disponible ahora mismo (4/min o 500/día en el plan gratuito).</summary>
    RateLimited,
    /// <summary>VirusTotal no conoce el hash (404).</summary>
    Unknown,
    Found,
    InvalidKey,
    Error
}

public sealed record VtLookupResult(VtStatus Status, int Malicious = 0, int Suspicious = 0, int Harmless = 0, int Undetected = 0, string? ThreatLabel = null)
{
    public int TotalEngines => Malicious + Suspicious + Harmless + Undetected;
}

/// <summary>
/// Cliente mínimo de la API v3 de VirusTotal. SOLO consulta hashes SHA-256: nunca sube archivos del usuario.
///
/// Respeta la cuota del plan gratuito (4 peticiones/minuto y 500/día) con un limitador de ventana deslizante;
/// si no hay cuota, devuelve <see cref="VtStatus.RateLimited"/> en lugar de bloquear el escaneo.
/// </summary>
public sealed class VirusTotalClient : IDisposable
{
    private const string BaseUrl = "https://www.virustotal.com/api/v3/files/";

    private readonly HttpClient _http;
    private readonly Func<string?> _apiKeyProvider;
    private readonly ILogger<VirusTotalClient> _logger;
    private readonly SlidingWindowRateLimiter _perMinute;
    private readonly int _dailyLimit;
    private readonly object _dailySync = new();
    private DateOnly _dailyDate = DateOnly.FromDateTime(DateTime.UtcNow);
    private int _dailyCount;
    private DateTime _cooldownUntilUtc = DateTime.MinValue;

    public VirusTotalClient(HttpClient http, Func<string?> apiKeyProvider, ILogger<VirusTotalClient> logger,
        int requestsPerMinute = 4, int dailyLimit = 500)
    {
        _http = http;
        _http.Timeout = TimeSpan.FromSeconds(20);
        _apiKeyProvider = apiKeyProvider;
        _logger = logger;
        _dailyLimit = dailyLimit;
        _perMinute = new SlidingWindowRateLimiter(new SlidingWindowRateLimiterOptions
        {
            PermitLimit = requestsPerMinute,
            Window = TimeSpan.FromMinutes(1),
            SegmentsPerWindow = 6,
            QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
            QueueLimit = 32,
            AutoReplenishment = true
        });
    }

    public bool IsConfigured => !string.IsNullOrWhiteSpace(_apiKeyProvider());

    /// <summary>
    /// Consulta un hash. <paramref name="maxWait"/> = cuánto se puede esperar por cuota:
    /// TimeSpan.Zero en escaneos masivos (no frenar el escaneo), unos segundos en tiempo real.
    /// </summary>
    public async Task<VtLookupResult> LookupAsync(string sha256, TimeSpan maxWait, CancellationToken ct)
    {
        string? key = _apiKeyProvider();
        if (string.IsNullOrWhiteSpace(key))
            return new(VtStatus.NotConfigured);

        if (DateTime.UtcNow < _cooldownUntilUtc || !TryConsumeDaily())
            return new(VtStatus.RateLimited);

        RateLimitLease lease;
        if (maxWait <= TimeSpan.Zero)
        {
            lease = _perMinute.AttemptAcquire();
        }
        else
        {
            using var waitCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            waitCts.CancelAfter(maxWait);
            try { lease = await _perMinute.AcquireAsync(1, waitCts.Token).ConfigureAwait(false); }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested) { return new(VtStatus.RateLimited); }
        }

        using (lease)
        {
            if (!lease.IsAcquired)
            {
                RefundDaily();
                return new(VtStatus.RateLimited);
            }
            return await QueryAsync(sha256, key, ct).ConfigureAwait(false);
        }
    }

    private async Task<VtLookupResult> QueryAsync(string sha256, string key, CancellationToken ct)
    {
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, BaseUrl + sha256);
            request.Headers.Add("x-apikey", key);
            request.Headers.Add("accept", "application/json");

            using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
            switch (response.StatusCode)
            {
                case HttpStatusCode.NotFound:
                    return new(VtStatus.Unknown);
                case HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden:
                    _logger.LogWarning("VirusTotal rechazó la clave API (HTTP {Code})", (int)response.StatusCode);
                    return new(VtStatus.InvalidKey);
                case HttpStatusCode.TooManyRequests:
                    // Cuota agotada en el servidor: pausamos 60 s todas las consultas.
                    _cooldownUntilUtc = DateTime.UtcNow.AddSeconds(60);
                    return new(VtStatus.RateLimited);
            }

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("VirusTotal devolvió HTTP {Code}", (int)response.StatusCode);
                return new(VtStatus.Error);
            }

            await using var body = await response.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
            return Parse(await JsonDocument.ParseAsync(body, cancellationToken: ct).ConfigureAwait(false));
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or JsonException)
        {
            // Sin conexión, timeout o respuesta inesperada: el escaneo local sigue siendo válido.
            _logger.LogDebug(ex, "Fallo consultando VirusTotal");
            return new(VtStatus.Error);
        }
    }

    /// <summary>Extrae data.attributes.last_analysis_stats y la etiqueta sugerida de la amenaza.</summary>
    internal static VtLookupResult Parse(JsonDocument doc)
    {
        using (doc)
        {
            if (!doc.RootElement.TryGetProperty("data", out var data) ||
                !data.TryGetProperty("attributes", out var attrs) ||
                !attrs.TryGetProperty("last_analysis_stats", out var stats))
                return new(VtStatus.Error);

            static int Get(JsonElement e, string name) =>
                e.TryGetProperty(name, out var v) && v.TryGetInt32(out int i) ? i : 0;

            string? label = null;
            if (attrs.TryGetProperty("popular_threat_classification", out var ptc) &&
                ptc.TryGetProperty("suggested_threat_label", out var l))
                label = l.GetString();

            return new(VtStatus.Found, Get(stats, "malicious"), Get(stats, "suspicious"), Get(stats, "harmless"), Get(stats, "undetected"), label);
        }
    }

    private bool TryConsumeDaily()
    {
        lock (_dailySync)
        {
            var today = DateOnly.FromDateTime(DateTime.UtcNow);
            if (today != _dailyDate)
            {
                _dailyDate = today;
                _dailyCount = 0;
            }
            if (_dailyCount >= _dailyLimit)
                return false;
            _dailyCount++;
            return true;
        }
    }

    private void RefundDaily()
    {
        lock (_dailySync)
            _dailyCount = Math.Max(0, _dailyCount - 1);
    }

    public void Dispose() => _perMinute.Dispose();
}
