using System.Runtime.InteropServices;
using System.Text;

namespace FragGuard.Service.Infrastructure;

/// <summary>
/// Llamadas Win32 usadas por el servicio. Todas son de modo usuario y solo actúan sobre el propio proceso
/// o LEEN información de otros (lista de procesos, ruta del ejecutable): nada de inyección ni hooks,
/// para no chocar con anti-cheats como Vanguard, Easy Anti-Cheat o BattlEye.
/// </summary>
internal static class NativeMethods
{
    // ---------- Prioridad del propio proceso ----------
    internal const uint BELOW_NORMAL_PRIORITY_CLASS = 0x00004000;
    /// <summary>Modo "background": baja a la vez la prioridad de CPU, de E/S y de memoria del proceso.</summary>
    internal const uint PROCESS_MODE_BACKGROUND_BEGIN = 0x00100000;
    internal const uint PROCESS_MODE_BACKGROUND_END = 0x00200000;

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool SetPriorityClass(IntPtr hProcess, uint dwPriorityClass);

    [DllImport("kernel32.dll")]
    internal static extern IntPtr GetCurrentProcess();

    /// <summary>Con (-1, -1) pide a Windows que recorte el working set del proceso.</summary>
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool SetProcessWorkingSetSize(IntPtr hProcess, nint dwMinimumWorkingSetSize, nint dwMaximumWorkingSetSize);

    // ---------- Instantánea de procesos (Toolhelp) ----------
    internal const uint TH32CS_SNAPPROCESS = 0x00000002;
    internal static readonly IntPtr INVALID_HANDLE_VALUE = new(-1);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct PROCESSENTRY32W
    {
        public uint dwSize;
        public uint cntUsage;
        public uint th32ProcessID;
        public IntPtr th32DefaultHeapID;
        public uint th32ModuleID;
        public uint cntThreads;
        public uint th32ParentProcessID;
        public int pcPriClassBase;
        public uint dwFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string szExeFile;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool Process32FirstW(IntPtr hSnapshot, ref PROCESSENTRY32W lppe);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool Process32NextW(IntPtr hSnapshot, ref PROCESSENTRY32W lppe);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CloseHandle(IntPtr hObject);

    // ---------- Ruta del ejecutable de otro proceso (solo lectura) ----------
    internal const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern IntPtr OpenProcess(uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwProcessId);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool QueryFullProcessImageNameW(IntPtr hProcess, uint dwFlags, StringBuilder lpExeName, ref uint lpdwSize);

    /// <summary>Ruta completa del ejecutable de un proceso, o null si no se puede consultar (proceso protegido, ya cerrado...).</summary>
    internal static string? TryGetProcessPath(uint pid)
    {
        IntPtr h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (h == IntPtr.Zero)
            return null;
        try
        {
            var sb = new StringBuilder(1024);
            uint size = (uint)sb.Capacity;
            return QueryFullProcessImageNameW(h, 0, sb, ref size) ? sb.ToString() : null;
        }
        finally
        {
            CloseHandle(h);
        }
    }
}
