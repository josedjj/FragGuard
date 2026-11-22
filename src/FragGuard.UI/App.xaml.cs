using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Threading;
using FragGuard.UI.Infrastructure;
using FragGuard.UI.ViewModels;
using FragGuard.UI.Views;
using Serilog;

namespace FragGuard.UI;

/// <summary>
/// Arranque de la UI:
///  - Instancia única por sesión (si ya hay una, se le pide que muestre su ventana y salimos).
///  - Vive en la bandeja: cerrar la ventana NO cierra la app ni la protección (que es el servicio).
///  - La ventana se destruye al cerrarla y se recrea al abrirla, para que en reposo la UI ocupe poca RAM.
/// Argumentos: --tray (arrancar oculta), --page X (abrir en una página), --wait-for-pid N (reapertura elevada).
/// </summary>
public partial class App : Application
{
    private const string MutexName = @"Local\FragGuard.UI";
    private const string ShowEventName = @"Local\FragGuard.UI.Show";

    private Mutex? _mutex;
    private EventWaitHandle? _showSignal;
    private ServiceClient? _client;
    private FullscreenDetector? _fullscreen;
    private MainViewModel? _vm;
    private TrayService? _tray;
    private MainWindow? _window;
    private DispatcherTimer? _poll;
    private bool _trayHintShown;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        ConfigureLogging();

        var args = e.Args;
        bool startInTray = args.Contains("--tray");
        string? page = ArgValue(args, "--page");

        // Reapertura como administrador: esperamos a que la instancia anterior termine.
        if (int.TryParse(ArgValue(args, "--wait-for-pid"), out int oldPid))
        {
            try { using var old = Process.GetProcessById(oldPid); old.WaitForExit(10_000); }
            catch (ArgumentException) { /* ya terminó */ }
        }

        // ---- Instancia única ----
        _mutex = new Mutex(initiallyOwned: true, MutexName, out bool isFirst);
        if (!isFirst)
        {
            try { EventWaitHandle.OpenExisting(ShowEventName).Set(); } catch { /* la otra instancia está cerrándose */ }
            Shutdown();
            return;
        }
        _showSignal = new EventWaitHandle(false, EventResetMode.AutoReset, ShowEventName);
        new Thread(() =>
        {
            while (_showSignal.WaitOne())
                Dispatcher.BeginInvoke(ShowMainWindow);
        }) { IsBackground = true, Name = "FragGuard.ShowSignal" }.Start();

        // ---- Errores no controlados: se registran y se muestran, pero la app sigue viva ----
        DispatcherUnhandledException += (_, ex) =>
        {
            Log.Error(ex.Exception, "Excepción no controlada en la UI");
            NeonDialog.Show("Error inesperado", ex.Exception.Message, DialogKind.Danger);
            ex.Handled = true;
        };
        TaskScheduler.UnobservedTaskException += (_, ex) =>
        {
            Log.Warning(ex.Exception, "Tarea con excepción no observada");
            ex.SetObserved();
        };

        // ---- Composición ----
        _client = new ServiceClient();
        _fullscreen = new FullscreenDetector();
        _vm = new MainViewModel(_client, _fullscreen);
        _tray = new TrayService(_vm, ShowMainWindow, QuickScanFromTray, ExitApp);

        _client.ThreatDetected += _tray.NotifyThreat;
        _client.CheatWarning += _tray.NotifyCheat;
        _client.ScanCompleted += _tray.NotifyScanCompleted;
        _vm.ServiceDown += () => _tray.Show("Protección desactivada",
            "El servicio de FragGuard no responde. Si no lo has detenido tú, reinicia el equipo o reinstala FragGuard.",
            H.NotifyIcon.Core.NotificationIcon.Error);

        _client.Start();
        _fullscreen.Start();

        // Refresco periódico SOLO con la ventana visible (en la bandeja no se consulta nada).
        _poll = new DispatcherTimer(DispatcherPriority.Background) { Interval = TimeSpan.FromSeconds(3) };
        _poll.Tick += async (_, _) =>
        {
            if (_window is { IsVisible: true, WindowState: not WindowState.Minimized } && _client.IsConnected)
                await _vm.PollAsync();
        };
        _poll.Start();

        if (page is not null)
            _vm.Navigate(page);
        if (!startInTray)
            ShowMainWindow();

        Log.Information("FragGuard UI iniciada (elevada: {Elevated}, bandeja: {Tray})", Elevation.IsElevated, startInTray);
    }

    private void ShowMainWindow()
    {
        if (_vm is null)
            return;
        if (_window is null)
        {
            _window = new MainWindow(_vm);
            _window.Closed += (_, _) =>
            {
                _window = null;
                MainWindow = null;
                if (!_trayHintShown)
                {
                    _trayHintShown = true;
                    _tray?.Show("FragGuard sigue protegiéndote", "La protección continúa en segundo plano. Abre FragGuard desde el icono de la bandeja.");
                }
                // Sin ventana, liberamos la memoria del árbol visual.
                Dispatcher.BeginInvoke(MemoryTrim.Trim, DispatcherPriority.ApplicationIdle);
            };
            MainWindow = _window;
            _window.Show();
        }
        if (_window.WindowState == WindowState.Minimized)
            _window.WindowState = WindowState.Normal;
        _window.Activate();
        _ = _vm.CurrentPage.RefreshAsync();
    }

    private void QuickScanFromTray()
    {
        if (_vm is null)
            return;
        _vm.Navigate("Scan");
        ShowMainWindow();
        _vm.Scan.QuickScanCommand.Execute(null);
    }

    private void ExitApp()
    {
        Log.Information("UI cerrada por el usuario (el servicio sigue protegiendo)");
        Shutdown();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _poll?.Stop();
        _tray?.Dispose();
        _fullscreen?.Dispose();
        _client?.Dispose();
        try { _mutex?.ReleaseMutex(); } catch { }
        _mutex?.Dispose();
        Log.CloseAndFlush();
        base.OnExit(e);
    }

    private static string? ArgValue(string[] args, string name)
    {
        int i = Array.IndexOf(args, name);
        return i >= 0 && i + 1 < args.Length ? args[i + 1] : null;
    }

    private static void ConfigureLogging()
    {
        string dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "FragGuard", "logs");
        Log.Logger = new LoggerConfiguration()
            .MinimumLevel.Information()
            .WriteTo.File(Path.Combine(dir, "ui-.log"), rollingInterval: RollingInterval.Day, retainedFileCountLimit: 7,
                outputTemplate: "{Timestamp:yyyy-MM-dd HH:mm:ss.fff} [{Level:u3}] {Message:lj}{NewLine}{Exception}")
            .CreateLogger();
    }
}
