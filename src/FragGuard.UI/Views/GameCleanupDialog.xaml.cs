using System.Windows;
using FragGuard.Shared.Models;
using FragGuard.UI.Infrastructure;
using Serilog;

namespace FragGuard.UI.Views;

/// <summary>
/// Muestra los restos encontrados de un juego desinstalado y los envía a la Papelera
/// SOLO tras la confirmación del usuario, con sus propios permisos.
/// </summary>
public partial class GameCleanupDialog : Window
{
    private readonly GameDto _game;
    private readonly List<LeftoverItem> _items;

    public GameCleanupDialog(GameDto game, List<LeftoverItem> items, bool stillInstalled)
    {
        InitializeComponent();
        _game = game;
        _items = items;

        TitleText.Text = $"Restos de {game.Name}";
        StillInstalledBanner.Visibility = stillInstalled ? Visibility.Visible : Visibility.Collapsed;
        ItemsList.ItemsSource = items;
        bool empty = items.Count == 0;
        EmptyText.Visibility = empty ? Visibility.Visible : Visibility.Collapsed;
        DeleteButton.IsEnabled = !empty;
        SelectAllButton.IsEnabled = !empty;

        if (Application.Current.MainWindow is { IsVisible: true } main && !ReferenceEquals(main, this))
            Owner = main;
        else
            WindowStartupLocation = WindowStartupLocation.CenterScreen;

        UpdateTotal();
        _ = ComputeSizesAsync();
    }

    private async Task ComputeSizesAsync()
    {
        foreach (var item in _items)
        {
            long size = await Task.Run(() => LeftoverFinder.DirectorySize(item.Path));
            item.SizeBytes = size;
            item.SizeText = Format.Bytes(size);
            UpdateTotal();
        }
    }

    private void UpdateTotal()
    {
        var selected = _items.Where(i => i.IsSelected).ToList();
        long bytes = selected.Where(i => i.SizeBytes > 0).Sum(i => i.SizeBytes);
        TotalText.Text = selected.Count == 0 ? "Nada seleccionado" : $"{selected.Count} carpeta(s) · {Format.Bytes(bytes)}";
        DeleteButton.IsEnabled = selected.Count > 0;
    }

    private void Selection_Changed(object sender, RoutedEventArgs e) => UpdateTotal();

    private void SelectAll_Click(object sender, RoutedEventArgs e)
    {
        bool anySaves = _items.Any(i => i.MayContainSaves && !i.IsSelected);
        if (anySaves && !NeonDialog.Confirm("Incluir posibles partidas guardadas",
                "Algunas carpetas pueden contener tus partidas guardadas. Si el juego no tiene guardado en la nube, se perderán al vaciar la Papelera.\n\n¿Seleccionarlas igualmente?",
                "Seleccionar todo", "Cancelar", DialogKind.Warning))
            return;
        foreach (var i in _items)
            i.IsSelected = true;
        UpdateTotal();
    }

    private void Delete_Click(object sender, RoutedEventArgs e)
    {
        var selected = _items.Where(i => i.IsSelected).ToList();
        if (selected.Count == 0)
            return;

        int ok = 0;
        var failures = new List<string>();
        foreach (var item in selected)
        {
            var (success, error) = RecycleBin.Send(item.Path);
            if (success)
            {
                ok++;
                Log.Information("Restos de {Game} enviados a la Papelera: {Path}", _game.Name, item.Path);
            }
            else
            {
                failures.Add($"• {item.Path}\n   {error}");
                Log.Warning("No se pudo enviar a la Papelera {Path}: {Error}", item.Path, error);
            }
        }

        if (failures.Count == 0)
            NeonDialog.Show("Limpieza completada", $"{ok} carpeta(s) de {_game.Name} enviadas a la Papelera de reciclaje.");
        else
            NeonDialog.Show("Limpieza parcial", $"{ok} carpeta(s) enviadas a la Papelera. No se pudieron borrar:\n\n{string.Join("\n", failures)}", DialogKind.Warning);
        DialogResult = true;
    }

    private void Cancel_Click(object sender, RoutedEventArgs e) => DialogResult = false;
}
