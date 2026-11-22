using FragGuard.Core.Configuration;
using FragGuard.Core.Scanning;
using FragGuard.Core.Security;
using FragGuard.Shared.Models;
using Microsoft.Win32;

namespace FragGuard.Service.Protection;

/// <summary>
/// Cámara y micrófono: Windows registra qué aplicación los usó y cuándo en
///   HKU\{usuario}\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\{webcam|microphone}
/// (LastUsedTimeStart / LastUsedTimeStop; Stop = 0 significa "en uso ahora").
/// Leerlo cada 5 s es prácticamente gratis y no requiere hooks. Si un programa SIN FIRMA de confianza
/// empieza a usar la cámara o el micrófono, se avisa (spyware, RATs, "stalkerware").
/// </summary>
public sealed class PrivacyMonitorService : BackgroundService
{
    private const string ConsentStore = @"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore";

    private readonly SettingsStore _settings;
    private readonly ThreatResponder _responder;
    private readonly ILogger<PrivacyMonitorService> _logger;
    private Dictionary<string, long>? _lastStarts;

    public PrivacyMonitorService(SettingsStore settings, ThreatResponder responder, ILogger<PrivacyMonitorService> logger)
    {
        _settings = settings;
        _responder = responder;
        _logger = logger;
    }

    public bool IsActive { get; private set; }

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            IsActive = _settings.Current.PrivacyMonitorEnabled;
            if (IsActive)
            {
                try { Check(); }
                catch (Exception ex) { _logger.LogDebug(ex, "Error leyendo el uso de cámara/micrófono"); }
            }
            try { await Task.Delay(TimeSpan.FromSeconds(5), ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { break; }
        }
    }

    private void Check()
    {
        var usages = Read();
        var starts = usages.Where(u => u.LastStartUtc is not null)
            .ToDictionary(u => u.Device + "|" + (u.Path ?? u.App), u => u.LastStartUtc!.Value.Ticks);

        if (_lastStarts is null)
        {
            _lastStarts = starts;
            return;
        }

        foreach (var u in usages.Where(u => u.InUse && !u.IsTrusted && !u.IsStoreApp))
        {
            string key = u.Device + "|" + (u.Path ?? u.App);
            if (_lastStarts.TryGetValue(key, out long prev) && prev == starts.GetValueOrDefault(key))
                continue; // ya avisado de esta sesión de uso

            _logger.LogWarning("{App} está usando {Device} y no es un programa de confianza", u.App, u.Device);
            _responder.Report(new DetectionDto
            {
                ScanKind = ScanKind.Realtime,
                FilePath = u.Path ?? u.App,
                Verdict = FileVerdict.Suspicious,
                Action = ThreatAction.Warned,
                DetectedUtc = DateTime.UtcNow,
                Threats = new List<ThreatInfo>
                {
                    new()
                    {
                        Name = u.Device == "Cámara" ? "FG.Privacy.WebcamAccess" : "FG.Privacy.MicrophoneAccess",
                        Category = "Privacidad",
                        Severity = ThreatSeverity.Medium,
                        Source = DetectionSource.Behavior,
                        Description = $"{u.App} está usando tu {u.Device.ToLowerInvariant()} y no tiene una firma de confianza. Si no lo has abierto tú, ciérralo y analízalo."
                    }
                }
            });
        }
        _lastStarts = starts;
    }

    /// <summary>Uso de cámara y micrófono de todos los usuarios con sesión iniciada.</summary>
    public List<DeviceUsageDto> Read()
    {
        var result = new List<DeviceUsageDto>();
        foreach (var profile in ScanTargets.GetUserProfiles().Where(p => !string.IsNullOrEmpty(p.Sid)))
        {
            foreach (var (capability, device) in new[] { ("webcam", "Cámara"), ("microphone", "Micrófono") })
            {
                using var root = Registry.Users.OpenSubKey($@"{profile.Sid}\{ConsentStore}\{capability}");
                if (root is null)
                    continue;

                // Aplicaciones de escritorio: subclave NonPackaged, una por ejecutable (ruta con # en vez de \).
                using (var nonPackaged = root.OpenSubKey("NonPackaged"))
                {
                    if (nonPackaged is not null)
                        foreach (string name in nonPackaged.GetSubKeyNames())
                        {
                            using var k = nonPackaged.OpenSubKey(name);
                            if (k is null) continue;
                            string path = name.Replace('#', '\\');
                            result.Add(Build(device, k, Path.GetFileNameWithoutExtension(path), path, store: false));
                        }
                }

                // Aplicaciones de la Microsoft Store: subclave = nombre del paquete.
                foreach (string name in root.GetSubKeyNames().Where(n => !n.Equals("NonPackaged", StringComparison.OrdinalIgnoreCase)))
                {
                    using var k = root.OpenSubKey(name);
                    if (k is null || k.GetValue("LastUsedTimeStart") is null) continue;
                    result.Add(Build(device, k, name.Split('_')[0], null, store: true));
                }
            }
        }
        return result.OrderByDescending(u => u.InUse).ThenByDescending(u => u.LastStartUtc).ToList();
    }

    private static DeviceUsageDto Build(string device, RegistryKey k, string app, string? path, bool store)
    {
        DateTime? start = FromFileTime(k.GetValue("LastUsedTimeStart"));
        DateTime? stop = FromFileTime(k.GetValue("LastUsedTimeStop"));

        // Programa que ya no existe (p. ej. versiones antiguas de Discord en app-1.0.x): Windows conserva su
        // registro, a veces sin hora de parada si se cerró mal. No puede estar en uso ni es sospechoso.
        bool exists = path is null || File.Exists(path);
        var sig = path is not null && exists ? Authenticode.Verify(path) : SignatureInfo.Unsigned;
        bool trusted = !exists || store || ProcessGuard.IsTrustedImage(path) || sig.IsTrustedPublisher;
        return new DeviceUsageDto
        {
            Device = device,
            App = app,
            Path = path,
            IsStoreApp = store,
            LastStartUtc = start,
            LastStopUtc = stop,
            InUse = exists && start is not null && (stop is null || stop < start),
            Publisher = !exists ? "Ya no está instalado" : store ? "Microsoft Store" : sig.IsValid ? sig.Publisher : null,
            IsTrusted = trusted
        };
    }

    private static DateTime? FromFileTime(object? value) =>
        value is long ft && ft > 0 ? DateTime.FromFileTimeUtc(ft) : null;
}
