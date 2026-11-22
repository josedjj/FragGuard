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

    // ---------- Línea de comandos de otro proceso (solo lectura, Windows 8.1+) ----------
    private const int ProcessCommandLineInformation = 60;

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(IntPtr processHandle, int processInformationClass, IntPtr processInformation, int processInformationLength, out int returnLength);

    /// <summary>
    /// Línea de comandos de un proceso con PROCESS_QUERY_LIMITED_INFORMATION (no lee su memoria ni se
    /// inyecta en él). Devuelve null si no se puede (proceso protegido o ya terminado).
    /// </summary>
    internal static string? TryGetCommandLine(uint pid)
    {
        IntPtr h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (h == IntPtr.Zero)
            return null;
        IntPtr buffer = IntPtr.Zero;
        try
        {
            NtQueryInformationProcess(h, ProcessCommandLineInformation, IntPtr.Zero, 0, out int needed);
            if (needed <= 0 || needed > 64 * 1024)
                return null;
            buffer = Marshal.AllocHGlobal(needed);
            if (NtQueryInformationProcess(h, ProcessCommandLineInformation, buffer, needed, out _) != 0)
                return null;
            // El resultado es un UNICODE_STRING: Length (ushort), MaximumLength (ushort), [relleno], Buffer (puntero)
            ushort length = (ushort)Marshal.ReadInt16(buffer);
            IntPtr text = Marshal.ReadIntPtr(buffer, IntPtr.Size);
            return length == 0 || text == IntPtr.Zero ? null : Marshal.PtrToStringUni(text, length / 2);
        }
        finally
        {
            if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer);
            CloseHandle(h);
        }
    }

    // ---------- Contadores de E/S (para identificar al proceso que cifra archivos) ----------
    [StructLayout(LayoutKind.Sequential)]
    internal struct IO_COUNTERS
    {
        public ulong ReadOperationCount, WriteOperationCount, OtherOperationCount;
        public ulong ReadTransferCount, WriteTransferCount, OtherTransferCount;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetProcessIoCounters(IntPtr hProcess, out IO_COUNTERS counters);

    internal static IO_COUNTERS? TryGetIoCounters(uint pid)
    {
        IntPtr h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (h == IntPtr.Zero)
            return null;
        try { return GetProcessIoCounters(h, out var c) ? c : null; }
        finally { CloseHandle(h); }
    }

    // ---------- Privilegios del propio proceso (SeSecurityPrivilege para configurar auditoría) ----------
    private const uint TOKEN_ADJUST_PRIVILEGES = 0x20, TOKEN_QUERY = 0x8, SE_PRIVILEGE_ENABLED = 0x2;

    [StructLayout(LayoutKind.Sequential)]
    private struct LUID { public uint LowPart; public int HighPart; }

    [StructLayout(LayoutKind.Sequential)]
    private struct TOKEN_PRIVILEGES { public uint PrivilegeCount; public LUID Luid; public uint Attributes; }

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool LookupPrivilegeValue(string? systemName, string name, out LUID luid);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AdjustTokenPrivileges(IntPtr tokenHandle, bool disableAll, ref TOKEN_PRIVILEGES newState, uint bufferLength, IntPtr previousState, IntPtr returnLength);

    /// <summary>Habilita un privilegio que el token YA posee (p. ej. SeSecurityPrivilege en SYSTEM). No concede nada nuevo.</summary>
    internal static bool EnablePrivilege(string name)
    {
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out IntPtr token))
            return false;
        try
        {
            if (!LookupPrivilegeValue(null, name, out var luid))
                return false;
            var tp = new TOKEN_PRIVILEGES { PrivilegeCount = 1, Luid = luid, Attributes = SE_PRIVILEGE_ENABLED };
            return AdjustTokenPrivileges(token, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero) && Marshal.GetLastWin32Error() == 0;
        }
        finally
        {
            CloseHandle(token);
        }
    }

    // ---------- Política de auditoría del sistema (sin auditpol.exe: independiente del idioma) ----------
    internal const uint POLICY_AUDIT_EVENT_SUCCESS = 0x1, POLICY_AUDIT_EVENT_FAILURE = 0x2, POLICY_AUDIT_EVENT_NONE = 0x4;

    [StructLayout(LayoutKind.Sequential)]
    private struct AUDIT_POLICY_INFORMATION
    {
        public Guid AuditSubCategoryGuid;
        public uint AuditingInformation;
        public Guid AuditCategoryGuid;
    }

    // OJO: estas funciones devuelven BOOLEAN (1 byte), no BOOL (4 bytes). Con el tipo equivocado,
    // un fallo podía leerse como éxito (pasó de verdad: NullReferenceException al leer un puntero nulo).
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.U1)]
    private static extern bool AuditSetSystemPolicy([In] AUDIT_POLICY_INFORMATION[] policy, uint count);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.U1)]
    private static extern bool AuditQuerySystemPolicy([In] Guid[] subCategoryGuids, uint count, out IntPtr policy);

    [DllImport("advapi32.dll")]
    private static extern void AuditFree(IntPtr buffer);

    /// <summary>Valor actual de auditoría (éxito/error) de una subcategoría, o null si no se puede leer.</summary>
    internal static uint? QueryAuditPolicy(Guid subcategory)
    {
        if (!AuditQuerySystemPolicy(new[] { subcategory }, 1, out IntPtr buffer) || buffer == IntPtr.Zero)
            return null;
        try { return Marshal.PtrToStructure<AUDIT_POLICY_INFORMATION>(buffer).AuditingInformation; }
        finally { AuditFree(buffer); }
    }

    /// <summary>Fija la auditoría de una subcategoría. Devuelve el código de error de Win32 (0 = correcto).</summary>
    internal static int SetAuditPolicy(Guid subcategory, uint auditing)
    {
        var info = new[] { new AUDIT_POLICY_INFORMATION { AuditSubCategoryGuid = subcategory, AuditingInformation = auditing } };
        return AuditSetSystemPolicy(info, 1) ? 0 : Marshal.GetLastWin32Error();
    }

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
