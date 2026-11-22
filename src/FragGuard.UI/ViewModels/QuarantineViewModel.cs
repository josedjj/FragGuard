using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using FragGuard.Shared.Models;
using FragGuard.UI.Infrastructure;
using FragGuard.UI.Views;

namespace FragGuard.UI.ViewModels;

/// <summary>Página de cuarentena: lista, restaurar y eliminar definitivamente.</summary>
public sealed partial class QuarantineViewModel : PageViewModel
{
    public QuarantineViewModel(ServiceClient client) : base(client) { }

    public override string Key => "Quarantine";

    public ObservableCollection<QuarantineItemDto> Items { get; } = new();

    [ObservableProperty] private bool _isEmpty = true;

    public bool IsElevated => Elevation.IsElevated;

    public override async Task RefreshAsync()
    {
        if (!Client.IsConnected)
            return;
        await RunAsync(async () =>
        {
            var items = await Client.ListQuarantineAsync();
            Items.Clear();
            foreach (var i in items)
                Items.Add(i);
            IsEmpty = Items.Count == 0;
        }, showErrors: false);
    }

    [RelayCommand]
    private async Task RestoreAsync(QuarantineItemDto? item)
    {
        if (item is null)
            return;
        if (!NeonDialog.Confirm("Restaurar archivo",
                $"\"{System.IO.Path.GetFileName(item.OriginalPath)}\" fue detectado como {item.ThreatName}.\n\n" +
                "Si lo restauras, FragGuard dejará de detectarlo. Hazlo solo si estás seguro de que es un falso positivo.",
                "Restaurar", "Cancelar", DialogKind.Danger))
            return;

        string? restoredTo = null;
        if (await RunAsync(async () => restoredTo = (await Client.RestoreQuarantineAsync(item.Id)).Message))
        {
            NeonDialog.Show("Archivo restaurado", $"Restaurado en:\n{restoredTo}");
            await RefreshAsync();
        }
    }

    [RelayCommand]
    private async Task DeleteAsync(QuarantineItemDto? item)
    {
        if (item is null)
            return;
        if (!NeonDialog.Confirm("Eliminar definitivamente",
                $"Se borrará para siempre \"{System.IO.Path.GetFileName(item.OriginalPath)}\". Esta acción no se puede deshacer.",
                "Eliminar", "Cancelar", DialogKind.Danger))
            return;

        if (await RunAsync(() => Client.DeleteQuarantineAsync(item.Id)))
            await RefreshAsync();
    }

    [RelayCommand]
    private Task ReloadAsync() => RefreshAsync();

    [RelayCommand]
    private void ElevateNow() => Elevation.RestartElevated(Key);
}
