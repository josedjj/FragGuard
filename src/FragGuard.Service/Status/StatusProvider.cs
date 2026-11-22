using FragGuard.Core.Configuration;
using FragGuard.Core.Data;
using FragGuard.Core.Detection;
using FragGuard.Service.GameMode;
using FragGuard.Service.Infrastructure;
using FragGuard.Service.Realtime;
using FragGuard.Service.Scanning;
using FragGuard.Shared.Models;

namespace FragGuard.Service.Status;

/// <summary>Compone el estado que muestra el panel principal.</summary>
public sealed class StatusProvider
{
    private readonly SettingsStore _settings;
    private readonly RealtimeProtectionService _realtime;
    private readonly GameModeService _gameMode;
    private readonly ScanCoordinator _scans;
    private readonly ScanHistoryRepository _history;
    private readonly DetectionRepository _detections;
    private readonly QuarantineRepository _quarantine;
    private readonly IYaraEngine _yara;
    private readonly VirusTotalClient _vt;
    private readonly ResourceMonitor _resources;
    private readonly AbuseChClient _abuse;
    private readonly Updates.RulesUpdateService _rulesUpdates;

    public StatusProvider(SettingsStore settings, RealtimeProtectionService realtime, GameModeService gameMode, ScanCoordinator scans,
        ScanHistoryRepository history, DetectionRepository detections, QuarantineRepository quarantine,
        IYaraEngine yara, VirusTotalClient vt, ResourceMonitor resources, AbuseChClient abuse, Updates.RulesUpdateService rulesUpdates)
    {
        _abuse = abuse;
        _rulesUpdates = rulesUpdates;
        _settings = settings;
        _realtime = realtime;
        _gameMode = gameMode;
        _scans = scans;
        _history = history;
        _detections = detections;
        _quarantine = quarantine;
        _yara = yara;
        _vt = vt;
        _resources = resources;
    }

    public StatusDto Get() => new()
    {
        RealtimeEnabled = _settings.Current.RealtimeEnabled,
        RealtimeHealthy = _realtime.IsHealthy,
        WatchedFolderCount = _realtime.WatchedFolderCount,
        GameModeActive = _gameMode.IsActive,
        GameModeReason = _gameMode.Reason,
        VirusTotalConfigured = _settings.Current.VirusTotalEnabled && _vt.IsConfigured,
        AbuseChConfigured = _settings.Current.AbuseChEnabled && _abuse.IsConfigured,
        YaraRuleCount = _yara.RuleCount,
        RulesUpdateVersion = _rulesUpdates.InstalledVersion,
        RulesUpdateStatus = _rulesUpdates.LastResult,
        LastScan = _history.GetLastCompleted(),
        ActiveScan = _scans.ActiveProgress,
        ThreatsBlockedTotal = _detections.CountBlocked(),
        QuarantineCount = _quarantine.Count(),
        ServiceRamMb = _resources.PrivateMb,
        ServiceCpuPercent = _resources.CpuPercent,
        ServiceStartedUtc = _resources.StartedUtc
    };
}
