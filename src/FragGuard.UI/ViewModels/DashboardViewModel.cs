using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using FragGuard.Shared.Models;
using FragGuard.UI.Infrastructure;
using FragGuard.UI.Views;

namespace FragGuard.UI.ViewModels;

public enum ProtectionLevel { Protected, Warning, Disconnected }
public enum AlertKind { Threat, Suspicious, Cheat }

/// <summary>Una entrada de "Actividad reciente" en el panel (amenazas y avisos de esta sesión).</summary>
public sealed partial class AlertItem : ObservableObject
{
    public required AlertKind Kind { get; init; }
    public required string Title { get; init; }
    public required string Detail { get; init; }
    public required string FilePath { get; init; }
    public DateTime TimeUtc { get; init; } = DateTime.UtcNow;
    public int? ProcessId { get; init; }

    [ObservableProperty]
    private bool _canKill;

    public string TimeText => Format.LocalDateTime(TimeUtc);
}

/// <summary>Panel principal: estado de protección, último escaneo, amenazas bloqueadas y consumo del antivirus.</summary>
public sealed partial class DashboardViewModel : PageViewModel
{
    private const double RamBudgetMb = 50; // objetivo de diseño del servicio

    private readonly Action<string> _navigate;

    public DashboardViewModel(ServiceClient client, Action<string> navigate) : base(client) => _navigate = navigate;

    public override string Key => "Dashboard";

    public ObservableCollection<AlertItem> Alerts { get; } = new();

    [ObservableProperty] private ProtectionLevel _level = ProtectionLevel.Disconnected;
    [ObservableProperty] private string _statusTitle = "Conectando…";
    [ObservableProperty] private string _statusDetail = "Buscando el servicio de FragGuard";
    [ObservableProperty] private string _realtimeText = "—";
    [ObservableProperty] private string _rulesText = "—";
    [ObservableProperty] private string _virusTotalText = "—";
    [ObservableProperty] private string _lastScanTitle = "Nunca";
    [ObservableProperty] private string _lastScanDetail = "Haz tu primer escaneo rápido";
    [ObservableProperty] private string _threatsBlocked = "0";
    [ObservableProperty] private string _quarantineCount = "0";
    [ObservableProperty] private string _ramText = "—";
    [ObservableProperty] private string _cpuText = "—";
    [ObservableProperty] private double _ramPercent;
    [ObservableProperty] private string _uptimeText = "";
    [ObservableProperty] private bool _hasAlerts;

    public override async Task RefreshAsync()
    {
        if (!Client.IsConnected)
        {
            ApplyDisconnected();
            return;
        }
        await RunAsync(async () => Apply(await Client.GetStatusAsync()), showErrors: false);
    }

    public void ApplyDisconnected()
    {
        Level = ProtectionLevel.Disconnected;
        StatusTitle = "Servicio no disponible";
        StatusDetail = "La protección no está activa. Comprueba que el servicio FragGuard está instalado e iniciado.";
        RamText = CpuText = "—";
        RamPercent = 0;
    }

    private void Apply(StatusDto s)
    {
        if (!s.RealtimeEnabled)
        {
            Level = ProtectionLevel.Warning;
            StatusTitle = "Protección reducida";
            StatusDetail = "La protección en tiempo real está desactivada en Ajustes.";
        }
        else if (!s.RealtimeHealthy)
        {
            Level = ProtectionLevel.Warning;
            StatusTitle = "Atención";
            StatusDetail = "La protección en tiempo real no está vigilando ninguna carpeta.";
        }
        else
        {
            Level = ProtectionLevel.Protected;
            StatusTitle = "Estás protegido";
            StatusDetail = s.GameModeActive
                ? "Modo juego activo: FragGuard trabaja en segundo plano sin molestarte."
                : "Todo en orden. FragGuard vigila tus descargas y carpetas de mods.";
        }

        RealtimeText = s.RealtimeEnabled ? $"Activa · {s.WatchedFolderCount} carpeta(s)" : "Desactivada";
        RulesText = $"{s.YaraRuleCount} reglas YARA";
        VirusTotalText = s.VirusTotalConfigured ? "VirusTotal conectado" : "VirusTotal sin configurar";

        if (s.LastScan is { } last)
        {
            LastScanTitle = Format.Relative(last.FinishedUtc ?? last.StartedUtc);
            LastScanDetail = $"{Format.ScanKind(last.Kind)} · {Format.Number(last.FilesScanned)} archivos · {last.ThreatsFound} amenaza(s)";
        }
        else
        {
            LastScanTitle = "Nunca";
            LastScanDetail = "Haz tu primer escaneo rápido";
        }

        ThreatsBlocked = Format.Number(s.ThreatsBlockedTotal);
        QuarantineCount = Format.Number(s.QuarantineCount);
        RamText = $"{s.ServiceRamMb:0.0} MB";
        CpuText = $"{s.ServiceCpuPercent:0.0#} %";
        RamPercent = Math.Clamp(s.ServiceRamMb / RamBudgetMb * 100, 0, 100);
        UptimeText = "Servicio activo " + Format.Relative(s.ServiceStartedUtc).Replace("hace", "desde hace");
    }

    // ---------------- Actividad reciente ----------------

    public void AddThreat(DetectionDto d)
    {
        bool malicious = d.Verdict == FileVerdict.Malicious;
        var primary = d.Threats.OrderByDescending(t => t.Severity).FirstOrDefault();
        AddAlert(new AlertItem
        {
            Kind = malicious ? AlertKind.Threat : AlertKind.Suspicious,
            Title = malicious ? $"Amenaza bloqueada: {d.PrimaryThreatName}" : $"Archivo sospechoso: {d.PrimaryThreatName}",
            Detail = $"{Format.Action(d.Action)} · {primary?.Description}",
            FilePath = d.FilePath,
            TimeUtc = d.DetectedUtc
        });
    }

    public void AddCheatWarning(CheatWarningDto w)
    {
        AddAlert(new AlertItem
        {
            Kind = AlertKind.Cheat,
            Title = w.Origin == "Process" ? "Posible cheat en ejecución" : "Archivo con nombre de cheat",
            Detail = w.Reason,
            FilePath = w.Path,
            TimeUtc = w.DetectedUtc,
            ProcessId = w.ProcessId,
            CanKill = w.ProcessId is not null
        });
    }

    private void AddAlert(AlertItem item)
    {
        Alerts.Insert(0, item);
        while (Alerts.Count > 50)
            Alerts.RemoveAt(Alerts.Count - 1);
        HasAlerts = Alerts.Count > 0;
    }

    [RelayCommand]
    private void ClearAlerts()
    {
        Alerts.Clear();
        HasAlerts = false;
    }

    [RelayCommand]
    private async Task KillProcessAsync(AlertItem? item)
    {
        if (item?.ProcessId is not { } pid)
            return;
        if (!NeonDialog.Confirm("Cerrar proceso", $"¿Cerrar \"{System.IO.Path.GetFileName(item.FilePath)}\" (PID {pid})?", "Cerrar proceso", "Cancelar", DialogKind.Danger))
            return;
        if (await RunAsync(() => Client.KillProcessAsync(pid)))
            item.CanKill = false;
    }

    [RelayCommand]
    private async Task QuickScanAsync()
    {
        if (await RunAsync(() => Client.StartScanAsync(new ScanRequest { Kind = ScanKind.Quick })))
            _navigate("Scan");
    }
}
