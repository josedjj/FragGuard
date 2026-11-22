using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using FragGuard.Shared.Models;
using FragGuard.UI.Infrastructure;
using Microsoft.Win32;

namespace FragGuard.UI.ViewModels;

/// <summary>Página de escaneo: rápido, completo y personalizado, con progreso en vivo.</summary>
public sealed partial class ScanViewModel : PageViewModel
{
    public ScanViewModel(ServiceClient client) : base(client) { }

    public override string Key => "Scan";

    [ObservableProperty] private bool _isScanning;
    [ObservableProperty] private bool _isPaused;
    [ObservableProperty] private string _scanTitle = "";
    [ObservableProperty] private string _filesScanned = "0";
    [ObservableProperty] private string _filesSkipped = "0";
    [ObservableProperty] private long _threatsFound;
    [ObservableProperty] private string _elapsed = "00:00";
    [ObservableProperty] private string? _currentFile;

    [ObservableProperty] private bool _hasResult;
    [ObservableProperty] private string _resultTitle = "";
    [ObservableProperty] private string _resultDetail = "";
    [ObservableProperty] private bool _resultHasThreats;

    public override async Task RefreshAsync()
    {
        if (!Client.IsConnected)
            return;
        await RunAsync(async () =>
        {
            var status = await Client.GetStatusAsync();
            if (status.ActiveScan is { } active)
                ApplyProgress(active);
            else
                IsScanning = false;
        }, showErrors: false);
    }

    // ---------------- Eventos del servicio ----------------

    public void ApplyProgress(ScanProgressDto p)
    {
        if (p.State is ScanState.Completed or ScanState.Cancelled or ScanState.Failed)
            return; // el resumen llega con ScanCompleted
        IsScanning = true;
        IsPaused = p.State == ScanState.Paused;
        ScanTitle = $"Escaneo {Format.ScanKind(p.Kind).ToLowerInvariant()}";
        FilesScanned = Format.Number(p.FilesScanned);
        FilesSkipped = Format.Number(p.FilesSkipped);
        ThreatsFound = p.ThreatsFound;
        Elapsed = Format.Duration(p.ElapsedMs);
        CurrentFile = p.CurrentFile;
    }

    public void ApplyCompleted(ScanSummaryDto s)
    {
        IsScanning = false;
        IsPaused = false;
        CurrentFile = null;
        HasResult = true;
        ResultHasThreats = s.ThreatsFound > 0;
        ResultTitle = s.State switch
        {
            ScanState.Cancelled => "Escaneo cancelado",
            ScanState.Failed => "El escaneo se interrumpió",
            _ when s.ThreatsFound > 0 => $"{s.ThreatsFound} amenaza(s) encontrada(s)",
            _ => "Sin amenazas. Todo limpio."
        };
        var duration = s.FinishedUtc is { } f ? Format.Duration((long)(f - s.StartedUtc).TotalMilliseconds) : "";
        ResultDetail = $"{Format.ScanKind(s.Kind)} · {Format.Number(s.FilesScanned)} archivos analizados · {Format.Number(s.FilesSkipped)} omitidos · {duration}";
    }

    // ---------------- Comandos ----------------

    [RelayCommand]
    private Task QuickScanAsync() => StartAsync(new ScanRequest { Kind = ScanKind.Quick });

    [RelayCommand]
    private Task FullScanAsync() => StartAsync(new ScanRequest { Kind = ScanKind.Full });

    [RelayCommand]
    private async Task CustomScanAsync()
    {
        var dialog = new OpenFolderDialog { Title = "Elige la carpeta a analizar (p. ej. tu carpeta de mods)" };
        if (dialog.ShowDialog() == true)
            await StartAsync(new ScanRequest { Kind = ScanKind.Custom, CustomPath = dialog.FolderName });
    }

    private async Task StartAsync(ScanRequest request)
    {
        HasResult = false;
        if (await RunAsync(() => Client.StartScanAsync(request)))
        {
            // Mostramos el panel de progreso al instante; los números llegan con los eventos.
            ApplyProgress(new ScanProgressDto { Kind = request.Kind, State = ScanState.Running });
        }
    }

    [RelayCommand]
    private Task PauseAsync() => RunAsync(async () => { await Client.PauseScanAsync(); IsPaused = true; });

    [RelayCommand]
    private Task ResumeAsync() => RunAsync(async () => { await Client.ResumeScanAsync(); IsPaused = false; });

    [RelayCommand]
    private Task CancelAsync() => RunAsync(() => Client.CancelScanAsync());
}
