using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32;
using Serilog;

namespace FragGuard.UI.Infrastructure;

/// <summary>Elevación (UAC) bajo demanda.</summary>
public static class Elevation
{
    public static bool IsElevated { get; } = CheckElevated();

    private static bool CheckElevated()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    /// <summary>
    /// Relanza FragGuard como administrador (aparece el aviso de UAC) abriendo la página indicada,
    /// y cierra esta instancia. Devuelve false si el usuario cancela el UAC.
    /// </summary>
    public static bool RestartElevated(string page)
    {
        try
        {
            Process.Start(new ProcessStartInfo(Environment.ProcessPath!, $"--wait-for-pid {Environment.ProcessId} --page {page}")
            {
                UseShellExecute = true,
                Verb = "runas"
            });
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 1223) // ERROR_CANCELLED: el usuario dijo "No" en UAC
        {
            return false;
        }
        System.Windows.Application.Current.Shutdown();
        return true;
    }
}

/// <summary>Carpetas conocidas del usuario (resueltas en SU sesión, para enviarlas al servicio).</summary>
public static class KnownFolders
{
    private static readonly Guid DownloadsId = new("374DE290-123F-4565-9164-39C4925E467B");

    [DllImport("shell32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int SHGetKnownFolderPath([MarshalAs(UnmanagedType.LPStruct)] Guid rfid, uint dwFlags, IntPtr hToken, out IntPtr ppszPath);

    public static string? Downloads
    {
        get
        {
            if (SHGetKnownFolderPath(DownloadsId, 0, IntPtr.Zero, out IntPtr ptr) != 0)
                return null;
            try { return Marshal.PtrToStringUni(ptr); }
            finally { Marshal.FreeCoTaskMem(ptr); }
        }
    }

    public static string Desktop => Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
}

/// <summary>Arranque de la UI con Windows (clave Run del usuario, en la bandeja y sin ventana).</summary>
public static class AutoStart
{
    private const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string ValueName = "FragGuard";

    public static bool IsEnabled
    {
        get
        {
            using var key = Registry.CurrentUser.OpenSubKey(RunKey);
            return key?.GetValue(ValueName) is string;
        }
    }

    public static void Set(bool enabled)
    {
        try
        {
            using var key = Registry.CurrentUser.CreateSubKey(RunKey);
            if (enabled)
                key.SetValue(ValueName, $"\"{Environment.ProcessPath}\" --tray");
            else
                key.DeleteValue(ValueName, throwOnMissingValue: false);
        }
        catch (Exception ex)
        {
            Log.Warning(ex, "No se pudo cambiar el inicio automático");
        }
    }
}

/// <summary>Recorta el working set de la UI cuando se oculta en la bandeja.</summary>
public static class MemoryTrim
{
    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetProcessWorkingSetSize(IntPtr process, nint min, nint max);

    public static void Trim()
    {
        GC.Collect(GC.MaxGeneration, GCCollectionMode.Aggressive, blocking: true, compacting: true);
        GC.WaitForPendingFinalizers();
        SetProcessWorkingSetSize(GetCurrentProcess(), -1, -1);
    }
}
