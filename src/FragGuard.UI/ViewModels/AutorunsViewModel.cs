using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Windows.Data;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using FragGuard.Shared.Models;
using FragGuard.UI.Infrastructure;
using FragGuard.UI.Views;

namespace FragGuard.UI.ViewModels;

/// <summary>Página "Programas de inicio": lo que arranca solo con Windows, con desactivar/restaurar.</summary>
public sealed partial class AutorunsViewModel : PageViewModel
{
    public AutorunsViewModel(ServiceClient client) : base(client)
    {
        View = CollectionViewSource.GetDefaultView(Items);
        View.Filter = o => o is AutorunEntryDto e &&
                           (ShowMicrosoft || !e.IsMicrosoft) &&
                           (!OnlySuspicious || e.IsSuspicious || !e.IsTrusted);
        View.SortDescriptions.Add(new SortDescription(nameof(AutorunEntryDto.IsSuspicious), ListSortDirection.Descending));
        View.SortDescriptions.Add(new SortDescription(nameof(AutorunEntryDto.IsTrusted), ListSortDirection.Ascending));
        View.SortDescriptions.Add(new SortDescription(nameof(AutorunEntryDto.Name), ListSortDirection.Ascending));
    }

    public override string Key => "Autoruns";

    public ObservableCollection<AutorunEntryDto> Items { get; } = new();
    public ICollectionView View { get; }
    public bool IsElevated => Elevation.IsElevated;

    [ObservableProperty] private bool _showMicrosoft;
    [ObservableProperty] private bool _onlySuspicious;
    [ObservableProperty] private string _summary = "";
    [ObservableProperty] private bool _loaded;

    partial void OnShowMicrosoftChanged(bool value) { View.Refresh(); UpdateSummary(); }
    partial void OnOnlySuspiciousChanged(bool value) { View.Refresh(); UpdateSummary(); }

    public override async Task RefreshAsync()
    {
        if (!Client.IsConnected)
            return;
        await RunAsync(async () =>
        {
            var list = await Client.ListAutorunsAsync();
            Items.Clear();
            foreach (var e in list)
                Items.Add(e);
            Loaded = true;
            UpdateSummary();
        }, showErrors: false);
    }

    private void UpdateSummary()
    {
        int visible = View.Cast<object>().Count();
        int suspicious = Items.Count(e => e.IsSuspicious);
        int untrusted = Items.Count(e => !e.IsTrusted && !e.IsSuspicious);
        Summary = $"{visible} de {Items.Count} entradas · {suspicious} sospechosas · {untrusted} sin firma de confianza";
    }

    [RelayCommand]
    private async Task DisableAsync(AutorunEntryDto? entry)
    {
        if (entry is null)
            return;
        if (!NeonDialog.Confirm("Desactivar programa de inicio",
                $"«{entry.Name}» dejará de arrancar con Windows.\n\nFragGuard guarda una copia: podrás restaurarlo desde esta misma página.",
                "Desactivar", "Cancelar", DialogKind.Warning))
            return;
        if (await RunAsync(() => Client.DisableAutorunAsync(entry.Id)))
            await RefreshAsync();
    }

    [RelayCommand]
    private async Task RestoreAsync(AutorunEntryDto? entry)
    {
        if (entry is null)
            return;
        if (await RunAsync(() => Client.RestoreAutorunAsync(entry.Id)))
            await RefreshAsync();
    }

    [RelayCommand]
    private Task ReloadAsync() => RefreshAsync();

    [RelayCommand]
    private void ElevateNow() => Elevation.RestartElevated(Key);
}
