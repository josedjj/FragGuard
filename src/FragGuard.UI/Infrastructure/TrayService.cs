using System.Windows;
using System.Windows.Controls;
using FragGuard.Shared.Models;
using FragGuard.UI.ViewModels;
using H.NotifyIcon;
using H.NotifyIcon.Core;

namespace FragGuard.UI.Infrastructure;

/// <summary>
/// Icono de la bandeja + notificaciones.
///
/// Política de notificaciones (requisito del modo juego):
///  - Amenaza MALICIOSA bloqueada → siempre (es crítica).
///  - Cheat en ejecución → siempre (riesgo de robo de cuenta y de baneo).
///  - Archivo sospechoso / escaneo terminado → se silencian durante el modo juego si así está configurado.
/// Además, Windows suprime por sí mismo los toasts mientras hay un juego en pantalla completa exclusiva.
/// </summary>
public sealed class TrayService : IDisposable
{
    private readonly TaskbarIcon _icon;
    private readonly MainViewModel _vm;

    public TrayService(MainViewModel vm, Action showWindow, Action quickScan, Action exit)
    {
        _vm = vm;

        var menu = new ContextMenu();
        menu.Items.Add(MenuItem("Abrir FragGuard", showWindow));
        menu.Items.Add(MenuItem("Escaneo rápido", quickScan));
        menu.Items.Add(new Separator());
        menu.Items.Add(MenuItem("Salir (la protección sigue activa)", exit));

        _icon = new TaskbarIcon
        {
            ToolTipText = "FragGuard",
            IconSource = new System.Windows.Media.Imaging.BitmapImage(new Uri("pack://application:,,,/Assets/fragguard.ico")),
            ContextMenu = menu,
            NoLeftClickDelay = true
        };
        _icon.TrayLeftMouseUp += (_, _) => showWindow();
        // Sin "efficiency mode" global: lo gestionamos nosotros al ocultar/mostrar la ventana.
        _icon.ForceCreate(enablesEfficiencyMode: false);

        vm.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName is nameof(MainViewModel.GameModeActive) or nameof(MainViewModel.IsConnected))
                UpdateTooltip();
        };
        UpdateTooltip();
    }

    private static MenuItem MenuItem(string header, Action action)
    {
        var item = new MenuItem { Header = header };
        item.Click += (_, _) => action();
        return item;
    }

    private void UpdateTooltip()
    {
        _icon.ToolTipText = !_vm.IsConnected ? "FragGuard · servicio no disponible"
            : _vm.GameModeActive ? "FragGuard · modo juego activo"
            : "FragGuard · protegido";
    }

    private bool Silenced => _vm.GameModeActive && (_vm.CurrentSettings?.SilenceNonCriticalInGameMode ?? true);

    public void NotifyThreat(DetectionDto d)
    {
        bool critical = d.Verdict == FileVerdict.Malicious;
        if (!critical && Silenced)
            return;

        string file = System.IO.Path.GetFileName(d.FilePath);
        string title = critical ? "Amenaza bloqueada" : "Archivo sospechoso";
        string action = d.Action switch
        {
            ThreatAction.Quarantined => "Movido a cuarentena.",
            ThreatAction.QuarantinePendingReboot => "Se eliminará al reiniciar (estaba en uso).",
            ThreatAction.QuarantineFailed => "¡No se pudo aislar! Revísalo en FragGuard.",
            _ => "Revísalo antes de abrirlo."
        };
        Show(title, $"{file}\n{d.PrimaryThreatName} · {action}", critical ? NotificationIcon.Error : NotificationIcon.Warning);
    }

    public void NotifyCheat(CheatWarningDto w)
    {
        string file = System.IO.Path.GetFileName(w.Path);
        Show(w.Origin == "Process" ? "Posible cheat en ejecución" : "Archivo con nombre de cheat",
            $"{file}\nPuede ser malware que roba cuentas y provocar baneos. Ábrelo en FragGuard para cerrarlo.",
            NotificationIcon.Warning);
    }

    public void NotifyScanCompleted(ScanSummaryDto s)
    {
        if (Silenced || s.Kind == ScanKind.Realtime)
            return;
        Show("Escaneo terminado",
            s.ThreatsFound > 0 ? $"{s.ThreatsFound} amenaza(s) en {s.FilesScanned:N0} archivos." : $"Sin amenazas en {s.FilesScanned:N0} archivos.",
            s.ThreatsFound > 0 ? NotificationIcon.Warning : NotificationIcon.Info);
    }

    public void Show(string title, string message, NotificationIcon icon = NotificationIcon.Info)
    {
        Application.Current.Dispatcher.BeginInvoke(() =>
        {
            try { _icon.ShowNotification(title, message, icon); }
            catch { /* el shell puede no estar disponible (p. ej. al cerrar sesión) */ }
        });
    }

    public void Dispose() => _icon.Dispose();
}
