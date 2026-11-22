using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Drawing;
using System.IO;
using System.Windows;
using System.Windows.Data;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using FragGuard.Shared.Models;
using FragGuard.UI.Infrastructure;
using FragGuard.UI.Views;
using Serilog;

namespace FragGuard.UI.ViewModels;

/// <summary>Un juego en la lista, con los textos e imágenes ya preparados para la vista.</summary>
public sealed partial class GameItem : ObservableObject
{
    /// <summary>Juegos sin abrir en más de este tiempo se marcan como candidatos a liberar espacio.</summary>
    public static readonly TimeSpan StaleAfter = TimeSpan.FromDays(90);

    public GameItem(GameDto dto) => Dto = dto;

    public GameDto Dto { get; }
    public string Name => Dto.Name;
    public string Launcher => Dto.Launcher;
    public string Initial => string.IsNullOrEmpty(Dto.Name) ? "?" : Dto.Name[..1].ToUpperInvariant();
    public long SizeBytes => Dto.SizeBytes ?? 0;
    public string SizeText => Dto.SizeBytes is { } s ? Format.Bytes(s) : "—";
    public bool CanPlay => !string.IsNullOrWhiteSpace(Dto.LaunchTarget);
    public bool CanUninstall => !string.IsNullOrWhiteSpace(Dto.UninstallCommand);

    public string LastPlayedText => Dto.LastPlayedUtc is { } t ? "Jugado " + Format.Relative(t) : "Sin datos de uso";
    public string LastPlayedTooltip => Dto.LastPlayedUtc is { } t
        ? $"{Format.LocalDateTime(t)} (según {(Dto.LastPlayedSource == "Steam" ? "Steam" : "Windows")})"
        : "Ni la plataforma ni Windows tienen registrada ninguna ejecución.";
    public bool IsStale => Dto.LastPlayedUtc is { } t && DateTime.UtcNow - t > StaleAfter;

    [ObservableProperty] private ImageSource? _cover;
    [ObservableProperty] private ImageSource? _icon;
}

/// <summary>Página "Juegos": juegos instalados, última vez jugado, jugar, desinstalar sin dejar restos.</summary>
public sealed partial class GamesViewModel : PageViewModel
{
    public GamesViewModel(ServiceClient client) : base(client)
    {
        View = CollectionViewSource.GetDefaultView(Items);
        View.Filter = o => o is GameItem g && (string.IsNullOrWhiteSpace(SearchText) ||
            g.Name.Contains(SearchText, StringComparison.CurrentCultureIgnoreCase) ||
            g.Launcher.Contains(SearchText, StringComparison.CurrentCultureIgnoreCase));
        ApplySort();
    }

    public override string Key => "Games";

    public ObservableCollection<GameItem> Items { get; } = new();
    public ICollectionView View { get; }

    [ObservableProperty] private string _searchText = "";
    [ObservableProperty] private string _sortMode = "Recent";
    [ObservableProperty] private string _summary = "";
    [ObservableProperty] private bool _hasGames;
    [ObservableProperty] private bool _loadedOnce;

    [RelayCommand]
    private void SetSort(string mode) => SortMode = mode;

    partial void OnSearchTextChanged(string value) => View.Refresh();
    partial void OnSortModeChanged(string value) => ApplySort();

    private void ApplySort()
    {
        using (View.DeferRefresh())
        {
            View.SortDescriptions.Clear();
            switch (SortMode)
            {
                case "Name":
                    View.SortDescriptions.Add(new SortDescription(nameof(GameItem.Name), ListSortDirection.Ascending));
                    break;
                case "Size":
                    View.SortDescriptions.Add(new SortDescription(nameof(GameItem.SizeBytes), ListSortDirection.Descending));
                    break;
                // "Recent": el orden del servicio (último jugado primero)
            }
        }
    }

    public override Task RefreshAsync() => LoadAsync(force: false);

    [RelayCommand]
    private Task ReloadAsync() => LoadAsync(force: true);

    private async Task LoadAsync(bool force)
    {
        if (!Client.IsConnected)
            return;
        await RunAsync(async () =>
        {
            var games = await Client.ListGamesAsync(force);
            Items.Clear();
            foreach (var g in games)
                Items.Add(new GameItem(g));
            HasGames = Items.Count > 0;
            LoadedOnce = true;
            UpdateSummary();
            _ = LoadImagesAsync(Items.ToList());
        }, showErrors: false);
    }

    private void UpdateSummary()
    {
        long total = Items.Sum(i => i.SizeBytes);
        var stale = Items.Where(i => i.IsStale).ToList();
        Summary = $"{Items.Count} juegos · {Format.Bytes(total)}"
                  + (stale.Count > 0 ? $" · {stale.Count} sin abrir en más de 90 días ({Format.Bytes(stale.Sum(i => i.SizeBytes))} que podrías liberar)" : "");
    }

    /// <summary>Portadas e iconos se cargan en segundo plano (reducidos y congelados) para no bloquear la UI.</summary>
    private static async Task LoadImagesAsync(List<GameItem> items)
    {
        foreach (var item in items)
        {
            var (cover, icon) = await Task.Run(() => (LoadCover(item.Dto.CoverPath), item.Dto.CoverPath is null ? LoadIcon(item.Dto.IconPath) : null));
            item.Cover = cover;
            item.Icon = icon;
        }
    }

    private static ImageSource? LoadCover(string? path)
    {
        if (path is null || !File.Exists(path))
            return null;
        try
        {
            var bmp = new BitmapImage();
            bmp.BeginInit();
            bmp.UriSource = new Uri(path);
            bmp.DecodePixelWidth = 120;                 // miniatura: poca memoria
            bmp.CacheOption = BitmapCacheOption.OnLoad; // no deja el archivo bloqueado
            bmp.EndInit();
            bmp.Freeze();
            return bmp;
        }
        catch (Exception ex)
        {
            Log.Debug(ex, "No se pudo cargar la portada {Path}", path);
            return null;
        }
    }

    private static ImageSource? LoadIcon(string? path)
    {
        if (path is null || !File.Exists(path))
            return null;
        try
        {
            using var icon = path.EndsWith(".ico", StringComparison.OrdinalIgnoreCase) ? new Icon(path, 64, 64) : System.Drawing.Icon.ExtractAssociatedIcon(path);
            if (icon is null)
                return null;
            var src = Imaging.CreateBitmapSourceFromHIcon(icon.Handle, Int32Rect.Empty, BitmapSizeOptions.FromEmptyOptions());
            src.Freeze();
            return src;
        }
        catch (Exception ex)
        {
            Log.Debug(ex, "No se pudo extraer el icono de {Path}", path);
            return null;
        }
    }

    // ---------------- Acciones ----------------

    [RelayCommand]
    private void Play(GameItem? item)
    {
        if (item is null)
            return;
        try
        {
            GameActions.Launch(item.Dto);
        }
        catch (Exception ex)
        {
            NeonDialog.Show("No se pudo abrir", ex.Message, DialogKind.Warning);
        }
    }

    [RelayCommand]
    private void OpenFolder(GameItem? item)
    {
        if (item is not null)
            GameActions.OpenFolder(item.Dto);
    }

    [RelayCommand]
    private async Task UninstallAsync(GameItem? item)
    {
        if (item is null)
            return;
        var game = item.Dto;

        string how = game.UninstallViaLauncher
            ? $"Se abrirá {game.Launcher}: desinstálalo desde tu biblioteca (menú ⋯ → Desinstalar)."
            : $"Se abrirá el desinstalador oficial de {game.Launcher}.";
        if (!NeonDialog.Confirm($"Desinstalar {game.Name}",
                $"{how}\n\nCuando termine, FragGuard buscará los restos que queden (configuración, cachés, partidas) y te dejará elegir qué borrar.",
                "Desinstalar", "Cancelar", DialogKind.Danger))
            return;

        try
        {
            if (!GameActions.StartUninstall(game))
            {
                NeonDialog.Show("Cancelado", "No se concedieron los permisos que pide el desinstalador.", DialogKind.Warning);
                return;
            }
        }
        catch (Exception ex)
        {
            NeonDialog.Show("No se pudo desinstalar", ex.Message, DialogKind.Warning);
            return;
        }

        // El desinstalador va a su ritmo (y Steam/Epic piden confirmación en su propia ventana).
        if (!NeonDialog.Confirm("Buscar restos",
                $"Termina la desinstalación de {game.Name} en la ventana de {game.Launcher}.\n\nCuando haya acabado, pulsa «Buscar restos».",
                "Buscar restos", "Más tarde", DialogKind.Info))
            return;

        await CleanLeftoversAsync(game);
    }

    private async Task CleanLeftoversAsync(GameDto game)
    {
        // ¿Sigue instalado? Preguntamos al servicio con la lista recién escaneada.
        List<GameDto> current = new();
        await RunAsync(async () => current = await Client.ListGamesAsync(forceRefresh: true), showErrors: false);
        bool stillInstalled = current.Any(g => g.Id == game.Id);

        var leftovers = await Task.Run(() => LeftoverFinder.Find(game, stillInstalled, current));
        new GameCleanupDialog(game, leftovers, stillInstalled).ShowDialog();
        await LoadAsync(force: false);
    }
}
