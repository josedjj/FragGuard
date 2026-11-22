using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace FragGuard.UI.Infrastructure;

/// <summary>
/// Detecta aplicaciones a pantalla completa en la sesión del usuario (el servicio, en la sesión 0, no puede verlas).
///
/// Dos señales, ambas de SOLO LECTURA (nada de hooks ni inyección, compatible con anti-cheats):
///  1) SHQueryUserNotificationState: Windows informa de juegos D3D en pantalla completa exclusiva / modo presentación.
///  2) Ventana en primer plano sin barra de título que cubre todo el monitor: juegos en "ventana sin bordes".
/// Se consulta cada 2 s con un temporizador de fondo (coste despreciable) y solo avisa cuando cambia el estado.
/// </summary>
public sealed class FullscreenDetector : IDisposable
{
    private readonly Timer _timer;
    private readonly int _selfPid = Environment.ProcessId;
    private bool _lastState;
    private string? _lastProcess;

    /// <summary>(estáPantallaCompleta, nombreProceso)</summary>
    public event Action<bool, string?>? Changed;

    public bool IsFullscreen => _lastState;
    public string? ProcessName => _lastProcess;

    public FullscreenDetector()
    {
        _timer = new Timer(_ => Check(), null, Timeout.Infinite, Timeout.Infinite);
    }

    public void Start() => _timer.Change(TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(2));

    private void Check()
    {
        try
        {
            var (fullscreen, process) = Detect();
            if (fullscreen != _lastState || (fullscreen && process != _lastProcess))
            {
                _lastState = fullscreen;
                _lastProcess = fullscreen ? process : null;
                Changed?.Invoke(fullscreen, _lastProcess);
            }
        }
        catch
        {
            // Nunca dejar que un fallo puntual de Win32 tumbe la UI.
        }
    }

    private (bool, string?) Detect()
    {
        IntPtr hwnd = GetForegroundWindow();
        string? processName = hwnd != IntPtr.Zero ? GetProcessName(hwnd, out int pid) : null;

        if (hwnd != IntPtr.Zero && GetProcessId(hwnd) == _selfPid)
            return (false, null);

        // 1) Lo que dice Windows
        if (SHQueryUserNotificationState(out var state) == 0 &&
            state is QUNS.RunningD3DFullScreen or QUNS.Busy or QUNS.PresentationMode)
            return (true, processName ?? "juego");

        // 2) Ventana sin bordes que cubre el monitor completo
        if (hwnd == IntPtr.Zero || IsShellWindow(hwnd))
            return (false, null);

        long style = GetWindowLongPtr(hwnd, GWL_STYLE).ToInt64();
        if ((style & WS_CAPTION) == WS_CAPTION)
            return (false, null); // ventana normal/maximizada con barra de título: no es un juego a pantalla completa

        if (!GetWindowRect(hwnd, out RECT r))
            return (false, null);

        IntPtr monitor = MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST);
        var info = new MONITORINFO { cbSize = Marshal.SizeOf<MONITORINFO>() };
        if (!GetMonitorInfo(monitor, ref info))
            return (false, null);

        bool coversMonitor = r.Left <= info.rcMonitor.Left && r.Top <= info.rcMonitor.Top &&
                             r.Right >= info.rcMonitor.Right && r.Bottom >= info.rcMonitor.Bottom;
        return coversMonitor ? (true, processName) : (false, null);
    }

    private static bool IsShellWindow(IntPtr hwnd)
    {
        var sb = new StringBuilder(64);
        GetClassName(hwnd, sb, sb.Capacity);
        string cls = sb.ToString();
        return cls is "Progman" or "WorkerW" or "Shell_TrayWnd" or "Shell_SecondaryTrayWnd";
    }

    private static int GetProcessId(IntPtr hwnd)
    {
        GetWindowThreadProcessId(hwnd, out uint pid);
        return (int)pid;
    }

    private static string? GetProcessName(IntPtr hwnd, out int pid)
    {
        pid = GetProcessId(hwnd);
        try
        {
            using var p = Process.GetProcessById(pid);
            return p.ProcessName + ".exe";
        }
        catch
        {
            return null;
        }
    }

    public void Dispose() => _timer.Dispose();

    // ---------------- Win32 ----------------

    private enum QUNS
    {
        NotPresent = 1,
        Busy = 2,
        RunningD3DFullScreen = 3,
        PresentationMode = 4,
        AcceptsNotifications = 5,
        QuietTime = 6,
        App = 7
    }

    private const int GWL_STYLE = -16;
    private const long WS_CAPTION = 0x00C00000L;
    private const uint MONITOR_DEFAULTTONEAREST = 2;

    [StructLayout(LayoutKind.Sequential)]
    private struct RECT { public int Left, Top, Right, Bottom; }

    [StructLayout(LayoutKind.Sequential)]
    private struct MONITORINFO
    {
        public int cbSize;
        public RECT rcMonitor;
        public RECT rcWork;
        public uint dwFlags;
    }

    [DllImport("shell32.dll")]
    private static extern int SHQueryUserNotificationState(out QUNS state);

    [DllImport("user32.dll")]
    private static extern IntPtr GetForegroundWindow();

    [DllImport("user32.dll")]
    private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint processId);

    [DllImport("user32.dll", EntryPoint = "GetWindowLongPtrW")]
    private static extern IntPtr GetWindowLongPtr(IntPtr hWnd, int nIndex);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetWindowRect(IntPtr hWnd, out RECT rect);

    [DllImport("user32.dll")]
    private static extern IntPtr MonitorFromWindow(IntPtr hwnd, uint flags);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetMonitorInfo(IntPtr hMonitor, ref MONITORINFO info);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int GetClassName(IntPtr hWnd, StringBuilder className, int maxCount);
}
