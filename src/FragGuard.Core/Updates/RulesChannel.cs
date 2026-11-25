using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using FragGuard.Core.Configuration;
using Microsoft.Extensions.Logging;

namespace FragGuard.Core.Updates;

public enum RulesUpdateOutcome { UpToDate, Applied, NotAvailable, InvalidSignature, Error }

public sealed record RulesUpdateResult(RulesUpdateOutcome Outcome, long? Version = null, int FileCount = 0, string? Message = null);

/// <summary>
/// Canal de actualización de reglas YARA, FIRMADO.
///
/// Formato publicado (p. ej. en el repositorio público de FragGuard):
///   manifest.json  { "version": 202611221830, "createdUtc": "...", "files": [ { "name": "x.yar", "sha256": "..." } ] }
///   manifest.sig   firma ECDSA P-256 / SHA-256 (formato IEEE P1363, base64) de los bytes EXACTOS de manifest.json
///   *.yar          los archivos de reglas
///
/// Garantías:
///  - Solo se aplica si la firma del manifiesto es válida con la clave pública EMBEBIDA en FragGuard
///    (la privada nunca está en el repositorio): un atacante que controle el servidor o la red no puede
///    colar reglas propias (p. ej. reglas que "detecten" archivos legítimos para borrarlos).
///  - Cada archivo debe coincidir con el SHA-256 del manifiesto firmado.
///  - Nombres restringidos (sin rutas) y límites de tamaño.
///  - Nunca baja de versión (protección contra reenvío de manifiestos antiguos).
///  - Si algo falla, las reglas instaladas no se tocan.
/// </summary>
public sealed class RulesChannel
{
    /// <summary>Clave pública del canal (SubjectPublicKeyInfo, base64). La privada la guarda el autor fuera del repositorio.</summary>
    public const string EmbeddedPublicKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEpf/YOZLl7Y5k3h3KY3xUTxqZbtBSzISVxdi2OUzckKDJpsI61rkdIUR38hxAxNc+YkUAvxG/QzN/hJOwuAkN1A==";

    public const string DefaultBaseUrl = "https://raw.githubusercontent.com/josedjj/FragGuard/main/rules-channel/";

    private const int MaxManifestBytes = 64 * 1024;
    private const int MaxRuleFileBytes = 2 * 1024 * 1024;
    private const int MaxFiles = 200;
    private static readonly Regex SafeName = new(@"^[A-Za-z0-9_\-]{1,64}\.yar$", RegexOptions.CultureInvariant);

    private readonly HttpClient _http;
    private readonly FragGuardPaths _paths;
    private readonly ILogger<RulesChannel> _logger;
    private readonly string _baseUrl;
    private readonly string _publicKey;

    public RulesChannel(HttpClient http, FragGuardPaths paths, ILogger<RulesChannel> logger, string? baseUrl = null, string? publicKey = null)
    {
        _http = http;
        _paths = paths;
        _logger = logger;
        _baseUrl = (baseUrl ?? DefaultBaseUrl).TrimEnd('/') + "/";
        _publicKey = publicKey ?? EmbeddedPublicKey;
    }

    /// <summary>Versión de las reglas actualizadas instaladas (0 si no hay).</summary>
    public long InstalledVersion
    {
        get
        {
            string path = Path.Combine(_paths.UpdatedRulesDirectory, "manifest.json");
            try { return File.Exists(path) ? ParseManifest(File.ReadAllBytes(path)).Version : 0; }
            catch (Exception ex) when (ex is IOException or JsonException or InvalidDataException) { return 0; }
        }
    }

    public async Task<RulesUpdateResult> CheckAndApplyAsync(CancellationToken ct)
    {
        if (_publicKey.StartsWith("__", StringComparison.Ordinal))
            return new(RulesUpdateOutcome.NotAvailable, Message: "Canal sin clave pública configurada.");

        string staging = Path.Combine(_paths.DataRoot, "rules-staging");
        try
        {
            byte[]? manifestBytes = await DownloadAsync("manifest.json", MaxManifestBytes, ct).ConfigureAwait(false);
            byte[]? sigBytes = await DownloadAsync("manifest.sig", 4096, ct).ConfigureAwait(false);
            if (manifestBytes is null || sigBytes is null)
                return new(RulesUpdateOutcome.NotAvailable, Message: "El canal de reglas no está disponible.");

            byte[] signature;
            try { signature = Convert.FromBase64String(System.Text.Encoding.ASCII.GetString(sigBytes).Trim()); }
            catch (FormatException) { return Fail(RulesUpdateOutcome.InvalidSignature, "Firma con formato inválido."); }

            if (!VerifySignature(manifestBytes, signature, _publicKey))
                return Fail(RulesUpdateOutcome.InvalidSignature, "La firma del manifiesto NO es válida: actualización rechazada.");

            var manifest = ParseManifest(manifestBytes);
            if (manifest.Version <= InstalledVersion)
                return new(RulesUpdateOutcome.UpToDate, manifest.Version);

            // Descarga y verificación de cada archivo en una carpeta temporal.
            if (Directory.Exists(staging))
                Directory.Delete(staging, recursive: true);
            Directory.CreateDirectory(staging);

            foreach (var file in manifest.Files)
            {
                byte[]? content = await DownloadAsync(file.Name, MaxRuleFileBytes, ct).ConfigureAwait(false);
                if (content is null)
                    return Fail(RulesUpdateOutcome.Error, $"No se pudo descargar {file.Name}.");
                string hash = Convert.ToHexString(SHA256.HashData(content));
                if (!hash.Equals(file.Sha256, StringComparison.OrdinalIgnoreCase))
                    return Fail(RulesUpdateOutcome.InvalidSignature, $"{file.Name} no coincide con el hash firmado.");
                await File.WriteAllBytesAsync(Path.Combine(staging, file.Name), content, ct).ConfigureAwait(false);
            }
            await File.WriteAllBytesAsync(Path.Combine(staging, "manifest.json"), manifestBytes, ct).ConfigureAwait(false);

            // Sustitución: se borra lo anterior y se mueve lo nuevo.
            string target = _paths.UpdatedRulesDirectory;
            if (Directory.Exists(target))
                Directory.Delete(target, recursive: true);
            Directory.Move(staging, target);

            _logger.LogInformation("Reglas actualizadas a la versión {Version} ({Count} archivos)", manifest.Version, manifest.Files.Count);
            return new(RulesUpdateOutcome.Applied, manifest.Version, manifest.Files.Count);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or HttpRequestException or JsonException or InvalidDataException or TaskCanceledException)
        {
            return Fail(RulesUpdateOutcome.Error, ex.Message);
        }
        finally
        {
            try { if (Directory.Exists(staging)) Directory.Delete(staging, recursive: true); } catch { }
        }
    }

    private RulesUpdateResult Fail(RulesUpdateOutcome outcome, string message)
    {
        if (outcome == RulesUpdateOutcome.InvalidSignature)
            _logger.LogError("Canal de reglas: {Message}", message);
        else
            _logger.LogWarning("Canal de reglas: {Message}", message);
        return new(outcome, Message: message);
    }

    private async Task<byte[]?> DownloadAsync(string name, int maxBytes, CancellationToken ct)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromSeconds(30));
        using var response = await _http.GetAsync(_baseUrl + name, HttpCompletionOption.ResponseHeadersRead, timeout.Token).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
            return null;
        if (response.Content.Headers.ContentLength > maxBytes)
            throw new InvalidDataException($"{name} es demasiado grande.");

        await using var stream = await response.Content.ReadAsStreamAsync(timeout.Token).ConfigureAwait(false);
        using var ms = new MemoryStream();
        byte[] buffer = new byte[16 * 1024];
        int read;
        while ((read = await stream.ReadAsync(buffer, timeout.Token).ConfigureAwait(false)) > 0)
        {
            ms.Write(buffer, 0, read);
            if (ms.Length > maxBytes)
                throw new InvalidDataException($"{name} es demasiado grande.");
        }
        return ms.ToArray();
    }

    // ---------------- Manifiesto y firma (también los usa la herramienta de publicación) ----------------

    public sealed record ManifestFile(string Name, string Sha256);
    public sealed record Manifest(long Version, DateTime CreatedUtc, List<ManifestFile> Files);

    public static Manifest ParseManifest(byte[] json)
    {
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        long version = root.GetProperty("version").GetInt64();
        DateTime created = root.TryGetProperty("createdUtc", out var c) && c.TryGetDateTime(out var d) ? d : DateTime.MinValue;
        var files = new List<ManifestFile>();
        foreach (var f in root.GetProperty("files").EnumerateArray())
        {
            string name = f.GetProperty("name").GetString() ?? "";
            string sha = f.GetProperty("sha256").GetString() ?? "";
            if (!SafeName.IsMatch(name) || sha.Length != 64)
                throw new InvalidDataException($"Entrada de manifiesto no válida: {name}");
            files.Add(new ManifestFile(name, sha));
        }
        if (files.Count == 0 || files.Count > MaxFiles || files.Select(f => f.Name).Distinct(StringComparer.OrdinalIgnoreCase).Count() != files.Count)
            throw new InvalidDataException("Lista de archivos del manifiesto no válida.");
        return new Manifest(version, created, files);
    }

    public static bool VerifySignature(byte[] data, byte[] signature, string publicKeyBase64)
    {
        try
        {
            using var ecdsa = ECDsa.Create();
            ecdsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(publicKeyBase64), out _);
            if (ecdsa.KeySize != 256)
                return false; // solo P-256
            return ecdsa.VerifyData(data, signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
        catch (CryptographicException) { return false; }
        catch (FormatException) { return false; }
    }
}
