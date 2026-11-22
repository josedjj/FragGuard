using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using FragGuard.Shared.Models;
using FragGuard.UI.Infrastructure;
using Serilog;

namespace FragGuard.UI.ViewModels;

/// <summary>
/// ViewModel raíz: navegación, estado de conexión, modo juego y reparto de los eventos del servicio
/// a cada página. Vive mientras la app esté en la bandeja (la ventana puede cerrarse y recrearse).
/// </summary>
public sealed partial class MainViewModel : ObservableObject
{
    private readonly ServiceClient _client;
    private readonly FullscreenDetector _fullscreen;
    private readonly Dictionary<string, PageViewModel> _pages;

    public MainViewModel(ServiceClient client, FullscreenDetector fullscreen)
    {
        _client = client;
        _fullscreen = fullscreen;

        Dashboard = new DashboardViewModel(client, Navigate);
        Scan = new ScanViewModel(client);
        Quarantine = new QuarantineViewModel(client);
        History = new HistoryViewModel(client);
        Settings = new SettingsViewModel(client, s => CurrentSettings = s);
        _pages = new() { ["Dashboard"] = Dashboard, ["Scan"] = Scan, ["Quarantine"] = Quarantine, ["History"] = History, ["Settings"] = Settings };
        _currentPage = Dashboard;

        // Eventos del servicio (llegan en hilos de fondo → pasamos al hilo de UI)
        client.ConnectionChanged += connected => OnUi(() => _ = OnConnectionChangedAsync(connected));
        client.ScanProgress += p => OnUi(() => Scan.ApplyProgress(p));
        client.ScanCompleted += s => OnUi(() => { Scan.ApplyCompleted(s); _ = Dashboard.RefreshAsync(); });
        client.ThreatDetected += d => OnUi(() => { Dashboard.AddThreat(d); _ = Dashboard.RefreshAsync(); });
        client.CheatWarning += w => OnUi(() => Dashboard.AddCheatWarning(w));
        client.GameModeChanged += g => OnUi(() => { GameModeActive = g.Active; GameModeReason = g.Reason; _ = Dashboard.RefreshAsync(); });

        // Pantalla completa detectada en la sesión del usuario → se lo contamos al servicio
        fullscreen.Changed += (isFull, process) => _ = ReportFullscreenAsync(isFull, process);
    }

    public DashboardViewModel Dashboard { get; }
    public ScanViewModel Scan { get; }
    public QuarantineViewModel Quarantine { get; }
    public HistoryViewModel History { get; }
    public SettingsViewModel Settings { get; }

    public bool IsElevated => Elevation.IsElevated;

    [ObservableProperty] private PageViewModel _currentPage;
    [ObservableProperty] private bool _isConnected;
    [ObservableProperty] private bool _gameModeActive;
    [ObservableProperty] private string? _gameModeReason;

    /// <summary>Última configuración conocida (la usa la política de notificaciones).</summary>
    public FragGuardSettings? CurrentSettings { get; private set; }

    public string CurrentPageKey => CurrentPage.Key;

    partial void OnCurrentPageChanged(PageViewModel value)
    {
        OnPropertyChanged(nameof(CurrentPageKey));
        _ = value.RefreshAsync();
    }

    [RelayCommand]
    public void Navigate(string key)
    {
        if (_pages.TryGetValue(key, out var page))
            CurrentPage = page;
    }

    /// <summary>Refresco periódico (solo mientras la ventana está visible): estado del panel / progreso.</summary>
    public Task PollAsync() => CurrentPage is DashboardViewModel or ScanViewModel ? CurrentPage.RefreshAsync() : Task.CompletedTask;

    private async Task OnConnectionChangedAsync(bool connected)
    {
        IsConnected = connected;
        if (!connected)
        {
            Dashboard.ApplyDisconnected();
            GameModeActive = false;
            return;
        }

        try
        {
            // Al (re)conectar: contamos al servicio nuestras carpetas y el estado de pantalla completa,
            // y recargamos configuración y estado.
            await _client.RegisterUserFoldersAsync(KnownFolders.Downloads, KnownFolders.Desktop);
            if (_fullscreen.IsFullscreen)
                await _client.ReportFullscreenAsync(true, _fullscreen.ProcessName);

            CurrentSettings = await _client.GetSettingsAsync();
            var status = await _client.GetStatusAsync();
            GameModeActive = status.GameModeActive;
            GameModeReason = status.GameModeReason;
        }
        catch (Exception ex)
        {
            Log.Warning(ex, "Error inicializando la sesión con el servicio");
        }

        await Dashboard.RefreshAsync();
        if (!ReferenceEquals(CurrentPage, Dashboard))
            await CurrentPage.RefreshAsync();
    }

    private async Task ReportFullscreenAsync(bool isFullscreen, string? process)
    {
        if (!_client.IsConnected)
            return;
        try { await _client.ReportFullscreenAsync(isFullscreen, process); }
        catch (Exception ex) { Log.Debug(ex, "No se pudo informar de pantalla completa"); }
    }

    private static void OnUi(Action action)
    {
        var dispatcher = System.Windows.Application.Current?.Dispatcher;
        if (dispatcher is null) return;
        dispatcher.BeginInvoke(action);
    }
}
