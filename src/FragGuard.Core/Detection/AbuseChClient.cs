using System.Collections.Concurrent;
using System.Net;
using System.Text.Json;
using System.Threading.RateLimiting;
using Microsoft.Extensions.Logging;

namespace FragGuard.Core.Detection;

public enum AbuseStatus { NotConfigured, Found, NotFound, RateLimited, InvalidKey, Error }

public sealed record AbuseHashResult(AbuseStatus Status, string? Signature = null, IReadOnlyList<string>? Tags = null);
public sealed record AbuseUrlResult(AbuseStatus Status, string? Threat = null, string? UrlStatus = null);

/// <summary>
/// Cliente de las APIs de abuse.ch (requieren una Auth-Key gratuita desde 2026):
///  - MalwareBazaar: ¿este SHA-256 es una muestra de malware conocida? (y su familia: RedLine, Lumma...)
///  - URLhaus: ¿esta URL de descarga (de Mark-of-the-Web) está registrada como distribuidora de malware?
///
/// Igual que con VirusTotal, solo se envían HASHES y URLs, nunca archivos. Con un limitador propio para no
/// abusar del servicio y una caché de URLs para no repetir consultas.
/// </summary>
public sealed class AbuseChClient : IDisposable
{
    private const string MalwareBazaarApi = "https://mb-api.abuse.ch/api/v1/";
    private const string UrlhausUrlApi = "https://urlhaus-api.abuse.ch/v1/url/";

    private readonly HttpClient _http;
    private readonly Func<string?> _keyProvider;
    private readonly ILogger<AbuseChClient> _logger;
    private readonly TokenBucketRateLimiter _limiter = new(new TokenBucketRateLimiterOptions
    {
        TokenLimit = 20,
        TokensPerPeriod = 20,
        ReplenishmentPeriod = TimeSpan.FromMinutes(1),
        QueueLimit = 0,
        AutoReplenishment = true
    });
    private readonly ConcurrentDictionary<string, (AbuseUrlResult Result, DateTime AtUtc)> _urlCache = new();
    private DateTime _cooldownUntilUtc = DateTime.MinValue;

    public AbuseChClient(HttpClient http, Func<string?> keyProvider, ILogger<AbuseChClient> logger)
    {
        _http = http;
        _keyProvider = keyProvider;
        _logger = logger;
    }

    public bool IsConfigured => !string.IsNullOrWhiteSpace(_keyProvider());

    public async Task<AbuseHashResult> LookupHashAsync(string sha256, CancellationToken ct)
    {
        var (status, json) = await PostAsync(MalwareBazaarApi, new Dictionary<string, string> { ["query"] = "get_info", ["hash"] = sha256 }, ct).ConfigureAwait(false);
        return status == AbuseStatus.Found && json is not null ? ParseHash(json) : new AbuseHashResult(status);
    }

    public async Task<AbuseUrlResult> LookupUrlAsync(string url, CancellationToken ct)
    {
        if (_urlCache.TryGetValue(url, out var c) && DateTime.UtcNow - c.AtUtc < TimeSpan.FromHours(12))
            return c.Result;

        var (status, json) = await PostAsync(UrlhausUrlApi, new Dictionary<string, string> { ["url"] = url }, ct).ConfigureAwait(false);
        var result = status == AbuseStatus.Found && json is not null ? ParseUrl(json) : new AbuseUrlResult(status);
        if (result.Status is AbuseStatus.Found or AbuseStatus.NotFound)
        {
            if (_urlCache.Count > 5000) _urlCache.Clear();
            _urlCache[url] = (result, DateTime.UtcNow);
        }
        return result;
    }

    /// <summary>Envía la petición. Devuelve Found + JSON si hubo respuesta válida (el detalle lo decide el parser).</summary>
    private async Task<(AbuseStatus, JsonDocument?)> PostAsync(string url, Dictionary<string, string> form, CancellationToken ct)
    {
        string? key = _keyProvider();
        if (string.IsNullOrWhiteSpace(key))
            return (AbuseStatus.NotConfigured, null);
        if (DateTime.UtcNow < _cooldownUntilUtc)
            return (AbuseStatus.RateLimited, null);

        using var lease = _limiter.AttemptAcquire();
        if (!lease.IsAcquired)
            return (AbuseStatus.RateLimited, null);

        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, url) { Content = new FormUrlEncodedContent(form) };
            request.Headers.Add("Auth-Key", key);
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromSeconds(15));
            using var response = await _http.SendAsync(request, timeout.Token).ConfigureAwait(false);

            if (response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
            {
                _logger.LogWarning("abuse.ch rechazó la Auth-Key (HTTP {Code})", (int)response.StatusCode);
                return (AbuseStatus.InvalidKey, null);
            }
            if (response.StatusCode == HttpStatusCode.TooManyRequests)
            {
                _cooldownUntilUtc = DateTime.UtcNow.AddMinutes(2);
                return (AbuseStatus.RateLimited, null);
            }
            if (!response.IsSuccessStatusCode)
                return (AbuseStatus.Error, null);

            string body = await response.Content.ReadAsStringAsync(timeout.Token).ConfigureAwait(false);
            return (AbuseStatus.Found, JsonDocument.Parse(body));
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or JsonException)
        {
            _logger.LogDebug(ex, "Fallo consultando abuse.ch");
            return (AbuseStatus.Error, null);
        }
    }

    /// <summary>{"query_status":"ok","data":[{"signature":"RedLineStealer","tags":["exe","RedLineStealer"]}]}</summary>
    internal static AbuseHashResult ParseHash(JsonDocument doc)
    {
        using (doc)
        {
            string? qs = doc.RootElement.TryGetProperty("query_status", out var q) ? q.GetString() : null;
            switch (qs)
            {
                case "ok":
                    if (doc.RootElement.TryGetProperty("data", out var data) && data.ValueKind == JsonValueKind.Array && data.GetArrayLength() > 0)
                    {
                        var first = data[0];
                        string? sig = first.TryGetProperty("signature", out var s) && s.ValueKind == JsonValueKind.String ? s.GetString() : null;
                        var tags = first.TryGetProperty("tags", out var t) && t.ValueKind == JsonValueKind.Array
                            ? t.EnumerateArray().Where(x => x.ValueKind == JsonValueKind.String).Select(x => x.GetString()!).ToList()
                            : new List<string>();
                        return new AbuseHashResult(AbuseStatus.Found, sig, tags);
                    }
                    return new AbuseHashResult(AbuseStatus.NotFound);
                case "hash_not_found":
                case "no_results":
                    return new AbuseHashResult(AbuseStatus.NotFound);
                case "unknown_auth_key":
                case "invalid_auth_key":
                    return new AbuseHashResult(AbuseStatus.InvalidKey);
                default:
                    return new AbuseHashResult(AbuseStatus.Error);
            }
        }
    }

    /// <summary>{"query_status":"ok","url_status":"online","threat":"malware_download"} | {"query_status":"no_results"}</summary>
    internal static AbuseUrlResult ParseUrl(JsonDocument doc)
    {
        using (doc)
        {
            var root = doc.RootElement;
            string? qs = root.TryGetProperty("query_status", out var q) ? q.GetString() : null;
            return qs switch
            {
                "ok" => new AbuseUrlResult(AbuseStatus.Found,
                    root.TryGetProperty("threat", out var t) ? t.GetString() : null,
                    root.TryGetProperty("url_status", out var s) ? s.GetString() : null),
                "no_results" => new AbuseUrlResult(AbuseStatus.NotFound),
                "unknown_auth_key" or "invalid_auth_key" => new AbuseUrlResult(AbuseStatus.InvalidKey),
                _ => new AbuseUrlResult(AbuseStatus.Error)
            };
        }
    }

    public void Dispose() => _limiter.Dispose();
}
