using System.Collections.Concurrent;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Security.AccessControl;
using System.Security.Principal;
using FragGuard.Core.Configuration;
using FragGuard.Core.Games;
using FragGuard.Core.Scanning;
using FragGuard.Core.Security;
using FragGuard.Service.Infrastructure;
using FragGuard.Shared.Models;

namespace FragGuard.Service.Protection;

/// <summary>
/// Protección de cuentas gamer con la AUDITORÍA nativa de Windows (sin drivers):
///
///  1. Se activa la subcategoría de auditoría "Sistema de archivos" (solo éxitos).
///  2. Se pone una regla de auditoría (SACL) en los archivos más robados por los infostealers:
///       - Tokens de Discord:  %APPDATA%\discord*\Local Storage\leveldb
///       - Sesión de Steam:    Steam\config (loginusers.vdf, config.vdf) y Steam\ssfn*
///  3. Windows escribe el evento 4663 en el registro de Seguridad cada vez que ALGUIEN lee esos archivos,
///     con la ruta del proceso. FragGuard lo lee en tiempo real y avisa si el lector no es Discord/Steam,
///     el propio sistema (Defender, Explorer) o FragGuard.
///
/// Es una DETECCIÓN (el acceso ya ocurrió), pero llega en ~1 s: da tiempo a detener el proceso antes de que
/// envíe los datos, y sobre todo te avisa para que cierres sesión en Discord/Steam (invalida el token robado).
/// Al desactivarlo se quitan las reglas y se restaura la configuración de auditoría original.
/// </summary>
public sealed class AccountProtectionService : BackgroundService
{
    private const string FileSystemAuditSubcategory = "{0CCE921D-69AE-11D9-BED3-505400B6D0E1}";

    private readonly SettingsStore _settings;
    private readonly FragGuardPaths _paths;
    private readonly ThreatResponder _responder;
    private readonly ILogger<AccountProtectionService> _logger;

    private readonly List<(string Path, string Label, bool IsDirectory)> _targets = new();
    private readonly ConcurrentDictionary<string, DateTime> _recentAlerts = new();
    private EventLogWatcher? _watcher;

    public AccountProtectionService(SettingsStore settings, FragGuardPaths paths, ThreatResponder responder, ILogger<AccountProtectionService> logger)
    {
        _settings = settings;
        _paths = paths;
        _responder = responder;
        _logger = logger;
    }

    public bool IsActive { get; private set; }
    public List<string> TargetLabels => _targets.Select(t => t.Label).Distinct().ToList();
    public string? LastError { get; private set; }

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        try { await Task.Delay(TimeSpan.FromSeconds(10), ct).ConfigureAwait(false); }
        catch (OperationCanceledException) { return; }

        while (!ct.IsCancellationRequested)
        {
            try
            {
                bool enabled = _settings.Current.AccountProtectionEnabled;
                if (enabled && !IsActive) Activate();
                else if (!enabled && IsActive) Deactivate();
                else if (enabled && IsActive) RefreshTargets(); // Discord/Steam instalados después
            }
            catch (Exception ex)
            {
                LastError = ex.Message;
                _logger.LogWarning(ex, "Error en la protección de cuentas");
            }

            try { await Task.Delay(TimeSpan.FromMinutes(10), ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { break; }
        }
        _watcher?.Dispose();
    }

    // ---------------- Activación ----------------

    private void Activate()
    {
        if (!NativeMethods.EnablePrivilege("SeSecurityPrivilege"))
        {
            LastError = "Sin privilegio de auditoría (¿el servicio no se ejecuta como SYSTEM?).";
            _logger.LogWarning("Protección de cuentas no disponible: {Error}", LastError);
            return;
        }

        SaveOriginalAuditSetting();
        if (!RunAuditpol($"/set /subcategory:{FileSystemAuditSubcategory} /success:enable"))
        {
            LastError = "No se pudo activar la auditoría del sistema de archivos.";
            return;
        }

        RefreshTargets();
        StartWatcher();
        IsActive = true;
        LastError = null;
        _logger.LogInformation("Protección de cuentas activa: {Targets}", string.Join(", ", TargetLabels));
    }

    private void Deactivate()
    {
        _watcher?.Dispose();
        _watcher = null;
        foreach (var (path, _, isDir) in _targets)
            SetAuditRule(path, isDir, add: false);
        _targets.Clear();
        RestoreOriginalAuditSetting();
        IsActive = false;
        _logger.LogInformation("Protección de cuentas desactivada y auditoría restaurada");
    }

    private void RefreshTargets()
    {
        foreach (var (path, label, isDir) in DiscoverTargets())
        {
            if (_targets.Any(t => t.Path.Equals(path, StringComparison.OrdinalIgnoreCase)))
                continue;
            if (SetAuditRule(path, isDir, add: true))
                _targets.Add((path, label, isDir));
        }
    }

    private static IEnumerable<(string Path, string Label, bool IsDirectory)> DiscoverTargets()
    {
        foreach (var profile in ScanTargets.GetUserProfiles())
        {
            string roaming = Path.Combine(profile.ProfilePath, "AppData", "Roaming");
            foreach (var (folder, label) in new[] { ("discord", "Discord"), ("discordptb", "Discord PTB"), ("discordcanary", "Discord Canary"), ("Lightcord", "Lightcord") })
            {
                string leveldb = Path.Combine(roaming, folder, "Local Storage", "leveldb");
                if (Directory.Exists(leveldb))
                    yield return (leveldb, label, true);
            }
        }

        if (SteamGames.FindSteamPath() is { } steam)
        {
            string config = Path.Combine(steam, "config");
            if (Directory.Exists(config))
                yield return (config, "Steam", true);
            foreach (var ssfn in Directory.EnumerateFiles(steam, "ssfn*"))
                yield return (ssfn, "Steam", false);
        }
    }

    /// <summary>Añade o quita una regla SACL "Todos: leer datos (éxito)" en el archivo/carpeta.</summary>
    private bool SetAuditRule(string path, bool isDirectory, bool add)
    {
        try
        {
            var everyone = new SecurityIdentifier(WellKnownSidType.WorldSid, null);
            var rule = new FileSystemAuditRule(everyone, FileSystemRights.ReadData,
                isDirectory ? InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit : InheritanceFlags.None,
                PropagationFlags.None, AuditFlags.Success);

            if (isDirectory)
            {
                var di = new DirectoryInfo(path);
                var sec = di.GetAccessControl(AccessControlSections.Audit);
                if (add) sec.AddAuditRule(rule); else sec.RemoveAuditRuleSpecific(rule);
                di.SetAccessControl(sec);
            }
            else
            {
                var fi = new FileInfo(path);
                var sec = fi.GetAccessControl(AccessControlSections.Audit);
                if (add) sec.AddAuditRule(rule); else sec.RemoveAuditRuleSpecific(rule);
                fi.SetAccessControl(sec);
            }
            return true;
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or PrivilegeNotHeldException or InvalidOperationException)
        {
            _logger.LogDebug("No se pudo {Action} la auditoría en {Path}: {Error}", add ? "poner" : "quitar", path, ex.Message);
            return false;
        }
    }

    // ---------------- Eventos 4663 ----------------

    private void StartWatcher()
    {
        var query = new EventLogQuery("Security", PathType.LogName, "*[System[(EventID=4663)]]");
        _watcher = new EventLogWatcher(query);
        _watcher.EventRecordWritten += (_, e) =>
        {
            try { if (e.EventRecord is { } r) using (r) Handle(r); }
            catch (Exception ex) { _logger.LogDebug(ex, "Error procesando un evento de auditoría"); }
        };
        _watcher.Enabled = true;
    }

    private void Handle(EventRecord record)
    {
        // Campos del 4663: [6] ObjectName, [10] ProcessId, [11] ProcessName
        if (record.Properties.Count < 12)
            return;
        string objectName = record.Properties[6].Value?.ToString() ?? "";
        string processName = record.Properties[11].Value?.ToString() ?? "";
        uint pid = record.Properties[10].Value switch
        {
            ulong u => (uint)u,
            long l => (uint)l,
            uint u32 => u32,
            _ => 0
        };

        var target = _targets.FirstOrDefault(t => objectName.StartsWith(t.Path, StringComparison.OrdinalIgnoreCase));
        if (target.Path is null || IsAllowedReader(processName, target.Label))
            return;

        // Un aviso por proceso y objetivo cada 10 minutos (un robo genera decenas de lecturas).
        string key = $"{pid}|{target.Label}";
        if (_recentAlerts.TryGetValue(key, out var last) && DateTime.UtcNow - last < TimeSpan.FromMinutes(10))
            return;
        _recentAlerts[key] = DateTime.UtcNow;

        string exe = Path.GetFileName(processName);
        bool killed = false;
        // Si el lector es un intérprete o un ejecutable no confiable en una carpeta de usuario, lo detenemos.
        if (pid > 4 && (IsScriptHost(exe) || (!ProcessGuard.IsTrustedImage(processName) && ProcessGuard.IsUserWritableLocation(processName))))
            killed = ProcessGuard.TryKill(pid, exe, _logger);

        string what = target.Label.StartsWith("Discord", StringComparison.OrdinalIgnoreCase) ? "los tokens de sesión de " + target.Label : "la sesión de Steam";
        _logger.LogCritical("Acceso sospechoso a {What}: {Process} (PID {Pid})", what, processName, pid);
        _responder.Report(new DetectionDto
        {
            ScanKind = ScanKind.Realtime,
            FilePath = processName,
            Verdict = FileVerdict.Malicious,
            Action = killed ? ThreatAction.ProcessTerminated : ThreatAction.Warned,
            DetectedUtc = DateTime.UtcNow,
            Threats = new List<ThreatInfo>
            {
                new()
                {
                    Name = target.Label.StartsWith("Discord", StringComparison.OrdinalIgnoreCase) ? "FG.Account.DiscordTokenAccess" : "FG.Account.SteamSessionAccess",
                    Category = "Robo de cuentas",
                    Severity = ThreatSeverity.Critical,
                    Source = DetectionSource.Behavior,
                    Description = $"{exe} ha leído {what}. Si no lo esperabas: cierra sesión en {(target.Label.StartsWith("Discord") ? "Discord (Ajustes → Cerrar sesión)" : "Steam (Ajustes → Seguridad → Desautorizar otros dispositivos)")} y cambia la contraseña."
                }
            }
        });
    }

    private static bool IsScriptHost(string exe) =>
        exe.ToLowerInvariant() is "powershell.exe" or "pwsh.exe" or "cmd.exe" or "python.exe" or "pythonw.exe" or "node.exe"
            or "wscript.exe" or "cscript.exe" or "mshta.exe" or "rundll32.exe";

    /// <summary>Quién puede leer esos archivos sin levantar sospechas.</summary>
    private static bool IsAllowedReader(string processPath, string label)
    {
        string exe = Path.GetFileName(processPath);
        // El propio FragGuard (escaneos), Defender y el Explorador.
        if (exe.Equals("FragGuard.Service.exe", StringComparison.OrdinalIgnoreCase) ||
            exe.ToLowerInvariant() is "msmpeng.exe" or "mpcopyaccelerator.exe" or "nissrv.exe" or "mpdefendercoreservice.exe" or "explorer.exe" or "searchprotocolhost.exe" or "searchindexer.exe")
            return true;

        if (label.StartsWith("Discord", StringComparison.OrdinalIgnoreCase) || label == "Lightcord")
            return exe.StartsWith("Discord", StringComparison.OrdinalIgnoreCase) || exe.StartsWith("Lightcord", StringComparison.OrdinalIgnoreCase)
                   ? IsSignedBy(processPath, "Discord Inc.") || label == "Lightcord"
                   : false;

        // Steam: sus propios procesos firmados por Valve.
        return exe.ToLowerInvariant() is "steam.exe" or "steamwebhelper.exe" or "steamservice.exe" or "steamerrorreporter.exe" or "steamerrorreporter64.exe" or "steamsysinfo.exe"
               && IsSignedBy(processPath, "Valve");
    }

    private static bool IsSignedBy(string path, string publisherStartsWith)
    {
        var sig = Authenticode.Verify(path);
        return sig.IsValid && sig.Publisher is not null && sig.Publisher.StartsWith(publisherStartsWith, StringComparison.OrdinalIgnoreCase);
    }

    // ---------------- auditpol ----------------

    private string OriginalSettingPath => Path.Combine(_paths.DataRoot, "audit-filesystem-original.txt");

    private void SaveOriginalAuditSetting()
    {
        if (File.Exists(OriginalSettingPath))
            return; // ya guardado en una activación anterior
        string? output = RunAuditpolOutput($"/get /subcategory:{FileSystemAuditSubcategory} /r");
        // CSV: Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting
        string? line = output?.Split('\n').Select(l => l.Trim()).FirstOrDefault(l => l.Contains(FileSystemAuditSubcategory, StringComparison.OrdinalIgnoreCase));
        string setting = line?.Split(',').ElementAtOrDefault(4)?.Trim() ?? "";
        File.WriteAllText(OriginalSettingPath, setting);
    }

    private void RestoreOriginalAuditSetting()
    {
        if (!File.Exists(OriginalSettingPath))
            return;
        string original = File.ReadAllText(OriginalSettingPath);
        // El texto depende del idioma; si la auditoría de éxitos NO estaba activa (o no se sabe), la desactivamos.
        bool successWasOn = new[] { "Success", "Acierto", "Correcto", "xito" }.Any(w => original.Contains(w, StringComparison.OrdinalIgnoreCase));
        if (!successWasOn)
            RunAuditpol($"/set /subcategory:{FileSystemAuditSubcategory} /success:disable");
        File.Delete(OriginalSettingPath);
    }

    private static bool RunAuditpol(string args) => RunAuditpolOutput(args) is not null;

    private static string? RunAuditpolOutput(string args)
    {
        try
        {
            using var p = Process.Start(new ProcessStartInfo("auditpol.exe", args)
            { CreateNoWindow = true, UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true });
            if (p is null) return null;
            string output = p.StandardOutput.ReadToEnd();
            p.WaitForExit(10000);
            return p.ExitCode == 0 ? output : null;
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            return null;
        }
    }
}
