using System.Text;
using System.Text.Json;
using FragGuard.Core.Security;
using FragGuard.Shared.Ipc;
using FragGuard.Shared.Models;
using Microsoft.Extensions.Logging;

namespace FragGuard.Core.Configuration;

/// <summary>
/// Persistencia de la configuración (settings.json) y de la clave de VirusTotal (vt.key, cifrada con DPAPI).
/// Es thread-safe: los consumidores leen <see cref="Current"/> (una instantánea inmutable por convención).
/// </summary>
public sealed class SettingsStore
{
    private readonly FragGuardPaths _paths;
    private readonly ILogger<SettingsStore> _logger;
    private readonly object _sync = new();
    private FragGuardSettings _current;
    private string? _vtKeyCache;
    private string? _abuseKeyCache;

    public SettingsStore(FragGuardPaths paths, ILogger<SettingsStore> logger)
    {
        _paths = paths;
        _logger = logger;
        _current = Load();
        _vtKeyCache = LoadSecret(_paths.VirusTotalKeyPath);
        _abuseKeyCache = LoadSecret(_paths.AbuseChKeyPath);
    }

    /// <summary>Se dispara tras guardar una configuración nueva.</summary>
    public event Action<FragGuardSettings>? Changed;

    public FragGuardSettings Current
    {
        get { lock (_sync) return _current; }
    }

    /// <summary>Copia de la configuración con HasVirusTotalKey rellenado, lista para enviar a la UI.</summary>
    public FragGuardSettings GetForClient()
    {
        var copy = Clone(Current);
        copy.HasVirusTotalKey = !string.IsNullOrEmpty(GetVirusTotalKey());
        copy.HasAbuseChKey = !string.IsNullOrEmpty(GetAbuseChKey());
        return copy;
    }

    public void Update(FragGuardSettings settings)
    {
        Sanitize(settings);
        lock (_sync)
        {
            Save(settings);
            _current = settings;
        }
        _logger.LogInformation("Configuración actualizada");
        Changed?.Invoke(settings);
    }

    // ---------------- VirusTotal ----------------

    public string? GetVirusTotalKey()
    {
        lock (_sync) return _vtKeyCache;
    }

    public void SetVirusTotalKey(string? apiKey)
    {
        lock (_sync)
            _vtKeyCache = SaveSecret(_paths.VirusTotalKeyPath, apiKey);
        // Nunca registramos la clave en el log, solo el hecho de que cambió.
        _logger.LogInformation("Clave de VirusTotal {Action}", string.IsNullOrWhiteSpace(apiKey) ? "eliminada" : "actualizada");
        Changed?.Invoke(Current);
    }

    // ---------------- abuse.ch ----------------

    public string? GetAbuseChKey()
    {
        lock (_sync) return _abuseKeyCache;
    }

    public void SetAbuseChKey(string? apiKey)
    {
        lock (_sync)
            _abuseKeyCache = SaveSecret(_paths.AbuseChKeyPath, apiKey);
        _logger.LogInformation("Auth-Key de abuse.ch {Action}", string.IsNullOrWhiteSpace(apiKey) ? "eliminada" : "actualizada");
        Changed?.Invoke(Current);
    }

    /// <summary>Guarda (o borra, si está vacío) un secreto cifrado con DPAPI. Devuelve el valor en claro para la caché.</summary>
    private static string? SaveSecret(string path, string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            File.Delete(path);
            return null;
        }
        string trimmed = value.Trim();
        SecretProtector.SaveToFile(path, Encoding.UTF8.GetBytes(trimmed));
        return trimmed;
    }

    private static string? LoadSecret(string path)
    {
        byte[]? plain = SecretProtector.LoadFromFile(path);
        return plain is null ? null : Encoding.UTF8.GetString(plain);
    }

    // ---------------- Persistencia ----------------

    private FragGuardSettings Load()
    {
        try
        {
            if (File.Exists(_paths.SettingsPath))
            {
                using var fs = File.OpenRead(_paths.SettingsPath);
                var loaded = JsonSerializer.Deserialize(fs, FragGuardJsonContext.Default.FragGuardSettings);
                if (loaded is not null)
                {
                    Sanitize(loaded);
                    return loaded;
                }
            }
        }
        catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException)
        {
            // Configuración corrupta: la apartamos y seguimos con los valores por defecto (el servicio no debe caer).
            _logger.LogWarning(ex, "settings.json no válido, se usan valores por defecto");
            TryBackupCorrupt();
        }

        var defaults = new FragGuardSettings();
        try { Save(defaults); }
        catch (Exception ex) { _logger.LogWarning(ex, "No se pudo guardar la configuración por defecto"); }
        return defaults;
    }

    private void Save(FragGuardSettings settings)
    {
        Directory.CreateDirectory(_paths.DataRoot);
        settings.HasVirusTotalKey = false; // no se persisten: se calculan al vuelo
        settings.HasAbuseChKey = false;
        string tmp = _paths.SettingsPath + ".tmp";
        File.WriteAllBytes(tmp, JsonSerializer.SerializeToUtf8Bytes(settings, FragGuardJsonContext.Indented.FragGuardSettings));
        File.Move(tmp, _paths.SettingsPath, overwrite: true); // escritura atómica
    }

    private void TryBackupCorrupt()
    {
        try { File.Move(_paths.SettingsPath, _paths.SettingsPath + ".corrupt", overwrite: true); }
        catch { /* best effort */ }
    }

    /// <summary>Normaliza valores para que una configuración mal editada no rompa el servicio.</summary>
    private static void Sanitize(FragGuardSettings s)
    {
        s.MaxFileSizeMb = Math.Clamp(s.MaxFileSizeMb, 1, 4096);
        s.WatchedFolders = Distinct(s.WatchedFolders);
        s.Exclusions = Distinct(s.Exclusions);
        s.RealtimeExtensions = s.RealtimeExtensions
            .Where(e => !string.IsNullOrWhiteSpace(e))
            .Select(e => e.Trim().StartsWith('.') ? e.Trim().ToLowerInvariant() : "." + e.Trim().ToLowerInvariant())
            .Distinct()
            .ToList();
        s.LauncherProcesses = Distinct(s.LauncherProcesses);
        s.LauncherHelperProcesses = Distinct(s.LauncherHelperProcesses);
        s.GameProcesses = Distinct(s.GameProcesses);
        if (!TimeOnly.TryParseExact(s.ScheduledScanTime, "HH:mm", out _))
            s.ScheduledScanTime = "13:00";
    }

    private static List<string> Distinct(List<string>? items) =>
        (items ?? new()).Where(i => !string.IsNullOrWhiteSpace(i))
            .Select(i => i.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

    private static FragGuardSettings Clone(FragGuardSettings s) =>
        JsonSerializer.Deserialize(JsonSerializer.SerializeToUtf8Bytes(s, FragGuardJsonContext.Default.FragGuardSettings),
            FragGuardJsonContext.Default.FragGuardSettings)!;
}
