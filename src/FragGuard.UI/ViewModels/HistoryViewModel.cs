using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using FragGuard.Shared.Models;
using FragGuard.UI.Infrastructure;

namespace FragGuard.UI.ViewModels;

/// <summary>Historial de detecciones y de escaneos.</summary>
public sealed partial class HistoryViewModel : PageViewModel
{
    public HistoryViewModel(ServiceClient client) : base(client) { }

    public override string Key => "History";

    public ObservableCollection<DetectionDto> Detections { get; } = new();
    public ObservableCollection<ScanSummaryDto> Scans { get; } = new();

    [ObservableProperty] private bool _noDetections = true;
    [ObservableProperty] private bool _noScans = true;

    public override async Task RefreshAsync()
    {
        if (!Client.IsConnected)
            return;
        await RunAsync(async () =>
        {
            var detections = await Client.GetDetectionsAsync(100);
            var scans = await Client.GetHistoryAsync(30);

            Detections.Clear();
            foreach (var d in detections) Detections.Add(d);
            Scans.Clear();
            foreach (var s in scans.Where(s => s.Kind != ScanKind.Realtime)) Scans.Add(s);

            NoDetections = Detections.Count == 0;
            NoScans = Scans.Count == 0;
        }, showErrors: false);
    }

    [RelayCommand]
    private Task ReloadAsync() => RefreshAsync();
}
