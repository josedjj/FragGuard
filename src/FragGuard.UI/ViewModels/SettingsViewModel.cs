using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using FragGuard.Shared.Models;
using FragGuard.UI.Infrastructure;
using FragGuard.UI.Views;
using Microsoft.Win32;

namespace FragGuard.UI.ViewModels;

/// <summary>
/// Ajustes. Los del servicio se guardan con un único "Guardar cambios" (requiere administrador);
/// "Iniciar con Windows" es local de la UI y se aplica al momento.
/// </summary>
public sealed partial class SettingsViewModel : PageViewModel
{
    private FragGuardSettings? _loaded;
    private readonly Action<FragGuardSettings> _onSaved;

    public SettingsViewModel(ServiceClient client, Action<FragGuardSettings> onSaved) : base(client) => _onSaved = onSaved;

    public override string Key => "Settings";

    public bool IsElevated => Elevation.IsElevated;

    [ObservableProperty] private bool _isLoaded;

    // Protección en tiempo real
    [ObservableProperty] private bool _realtimeEnabled;
    [ObservableProperty] private string _realtimeExtensions = "";
    public ObservableCollection<string> WatchedFolders { get; } = new();

    // Detección
    [ObservableProperty] private bool _autoQuarantine;
    [ObservableProperty] private string _maxFileSizeMb = "200";
    public ObservableCollection<string> Exclusions { get; } = new();

    // VirusTotal
    [ObservableProperty] private bool _virusTotalEnabled;
    [ObservableProperty] private bool _hasVirusTotalKey;
    /// <summary>Lo rellena la vista desde el PasswordBox (PasswordBox.Password no admite binding por seguridad).</summary>
    public string VirusTotalKeyInput { get; set; } = "";

    // Modo juego
    [ObservableProperty] private bool _gameModeAuto;
    [ObservableProperty] private bool _gameModeOnFullscreen;
    [ObservableProperty] private string _gameProcesses = "";
    [ObservableProperty] private string _launcherProcesses = "";

    // Escaneo programado y notificaciones
    [ObservableProperty] private bool _scheduledScanEnabled;
    [ObservableProperty] private string _scheduledScanTime = "13:00";
    [ObservableProperty] private bool _silenceNonCriticalInGameMode;

    // Local (UI)
    [ObservableProperty] private bool _startWithWindows = AutoStart.IsEnabled;

    [ObservableProperty] private string? _saveMessage;
    [ObservableProperty] private bool _saveOk;

    partial void OnStartWithWindowsChanged(bool value) => AutoStart.Set(value);

    public override async Task RefreshAsync()
    {
        if (!Client.IsConnected)
            return;
        await RunAsync(async () => Load(await Client.GetSettingsAsync()), showErrors: false);
    }

    private void Load(FragGuardSettings s)
    {
        _loaded = s;
        RealtimeEnabled = s.RealtimeEnabled;
        RealtimeExtensions = string.Join(", ", s.RealtimeExtensions);
        Replace(WatchedFolders, s.WatchedFolders);
        AutoQuarantine = s.AutoQuarantine;
        MaxFileSizeMb = s.MaxFileSizeMb.ToString();
        Replace(Exclusions, s.Exclusions);
        VirusTotalEnabled = s.VirusTotalEnabled;
        HasVirusTotalKey = s.HasVirusTotalKey;
        GameModeAuto = s.GameModeAuto;
        GameModeOnFullscreen = s.GameModeOnFullscreen;
        GameProcesses = string.Join(Environment.NewLine, s.GameProcesses);
        LauncherProcesses = string.Join(Environment.NewLine, s.LauncherProcesses);
        ScheduledScanEnabled = s.ScheduledScanEnabled;
        ScheduledScanTime = s.ScheduledScanTime;
        SilenceNonCriticalInGameMode = s.SilenceNonCriticalInGameMode;
        IsLoaded = true;
    }

    private static void Replace(ObservableCollection<string> target, IEnumerable<string> items)
    {
        target.Clear();
        foreach (var i in items) target.Add(i);
    }

    private static List<string> SplitList(string text) =>
        text.Split(new[] { ',', ';', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

    // ---------------- Carpetas ----------------

    [RelayCommand]
    private void AddWatchedFolder() => AddFolder(WatchedFolders, "Carpeta a vigilar (p. ej. mods de Minecraft, Skyrim...)");

    [RelayCommand]
    private void RemoveWatchedFolder(string? folder) { if (folder is not null) WatchedFolders.Remove(folder); }

    [RelayCommand]
    private void AddExclusion() => AddFolder(Exclusions, "Carpeta a excluir del análisis");

    [RelayCommand]
    private void RemoveExclusion(string? folder) { if (folder is not null) Exclusions.Remove(folder); }

    private static void AddFolder(ObservableCollection<string> target, string title)
    {
        var dialog = new OpenFolderDialog { Title = title };
        if (dialog.ShowDialog() == true && !target.Contains(dialog.FolderName, StringComparer.OrdinalIgnoreCase))
            target.Add(dialog.FolderName);
    }

    // ---------------- Guardar ----------------

    [RelayCommand]
    private async Task SaveAsync()
    {
        if (_loaded is null)
            return;

        if (!int.TryParse(MaxFileSizeMb, out int maxMb) || maxMb < 1)
        {
            ShowSaveMessage("El tamaño máximo debe ser un número de MB mayor que 0.", ok: false);
            return;
        }
        if (!TimeOnly.TryParseExact(ScheduledScanTime, "HH:mm", out _))
        {
            ShowSaveMessage("La hora del escaneo programado debe tener formato HH:mm (p. ej. 13:00).", ok: false);
            return;
        }
        if (!RealtimeEnabled && !NeonDialog.Confirm("Desactivar protección en tiempo real",
                "Los archivos nuevos que descargues no se analizarán. ¿Seguro?", "Desactivar", "Cancelar", DialogKind.Danger))
            return;

        // Partimos de lo cargado para conservar los campos que esta pantalla no edita (p. ej. procesos auxiliares).
        var s = _loaded;
        s.RealtimeEnabled = RealtimeEnabled;
        s.RealtimeExtensions = SplitList(RealtimeExtensions);
        s.WatchedFolders = WatchedFolders.ToList();
        s.AutoQuarantine = AutoQuarantine;
        s.MaxFileSizeMb = maxMb;
        s.Exclusions = Exclusions.ToList();
        s.VirusTotalEnabled = VirusTotalEnabled;
        s.GameModeAuto = GameModeAuto;
        s.GameModeOnFullscreen = GameModeOnFullscreen;
        s.GameProcesses = SplitList(GameProcesses);
        s.LauncherProcesses = SplitList(LauncherProcesses);
        s.ScheduledScanEnabled = ScheduledScanEnabled;
        s.ScheduledScanTime = ScheduledScanTime;
        s.SilenceNonCriticalInGameMode = SilenceNonCriticalInGameMode;

        if (await RunAsync(() => Client.UpdateSettingsAsync(s)))
        {
            ShowSaveMessage("Cambios guardados.", ok: true);
            _onSaved(s);
            await RefreshAsync();
        }
    }

    [RelayCommand]
    private async Task SaveVirusTotalKeyAsync()
    {
        string key = VirusTotalKeyInput.Trim();
        if (key.Length < 32)
        {
            ShowSaveMessage("La clave de VirusTotal parece incompleta (son 64 caracteres).", ok: false);
            return;
        }
        if (await RunAsync(() => Client.SetVirusTotalKeyAsync(key)))
        {
            HasVirusTotalKey = true;
            ShowSaveMessage("Clave de VirusTotal guardada (cifrada en el equipo).", ok: true);
        }
    }

    [RelayCommand]
    private async Task ClearVirusTotalKeyAsync()
    {
        if (await RunAsync(() => Client.SetVirusTotalKeyAsync(null)))
        {
            HasVirusTotalKey = false;
            ShowSaveMessage("Clave de VirusTotal eliminada.", ok: true);
        }
    }

    [RelayCommand]
    private void ElevateNow() => Elevation.RestartElevated(Key);

    private void ShowSaveMessage(string message, bool ok)
    {
        SaveOk = ok;
        SaveMessage = message;
    }
}
