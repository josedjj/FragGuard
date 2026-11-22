using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using FragGuard.UI.Infrastructure;
using FragGuard.UI.Views;
using Serilog;

namespace FragGuard.UI.ViewModels;

/// <summary>Base de las páginas: acceso al servicio y gestión uniforme de errores.</summary>
public abstract partial class PageViewModel : ObservableObject
{
    protected PageViewModel(ServiceClient client) => Client = client;

    protected ServiceClient Client { get; }

    /// <summary>Clave de la página (Dashboard, Scan, ...): se usa para navegar y para reabrir elevado.</summary>
    public abstract string Key { get; }

    [ObservableProperty]
    private bool _isBusy;

    /// <summary>Se llama al mostrar la página o al reconectar con el servicio.</summary>
    public virtual Task RefreshAsync() => Task.CompletedTask;

    /// <summary>
    /// Ejecuta una operación contra el servicio mostrando errores al usuario de forma amigable.
    /// Si el servicio exige administrador, ofrece reabrir FragGuard elevado en esta misma página.
    /// </summary>
    protected async Task<bool> RunAsync(Func<Task> action, bool showErrors = true)
    {
        try
        {
            IsBusy = true;
            await action();
            return true;
        }
        catch (ElevationRequiredException)
        {
            if (NeonDialog.Confirm("Permisos de administrador",
                    "Esta acción puede desactivar o debilitar la protección, por eso Windows pedirá confirmación (UAC).\n\n¿Reabrir FragGuard como administrador?",
                    "Reabrir como admin", "Cancelar"))
            {
                if (!Elevation.RestartElevated(Key))
                    NeonDialog.Show("Cancelado", "No se concedieron permisos de administrador.", DialogKind.Warning);
            }
        }
        catch (ServiceUnavailableException ex)
        {
            if (showErrors)
                NeonDialog.Show("Servicio no disponible", ex.Message + "\n\nComprueba que el servicio \"FragGuard Protection Service\" está instalado e iniciado.", DialogKind.Danger);
        }
        catch (ServiceErrorException ex)
        {
            if (showErrors)
                NeonDialog.Show("No se pudo completar", ex.Message, DialogKind.Warning);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Error inesperado en {Page}", Key);
            if (showErrors)
                NeonDialog.Show("Error inesperado", ex.Message, DialogKind.Danger);
        }
        finally
        {
            IsBusy = false;
        }
        return false;
    }

    protected static void OnUi(Action action)
    {
        var dispatcher = Application.Current?.Dispatcher;
        if (dispatcher is null) return;
        if (dispatcher.CheckAccess()) action();
        else dispatcher.BeginInvoke(action);
    }
}
