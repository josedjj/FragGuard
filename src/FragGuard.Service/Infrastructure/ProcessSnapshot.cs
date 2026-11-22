using System.Runtime.InteropServices;
using static FragGuard.Service.Infrastructure.NativeMethods;

namespace FragGuard.Service.Infrastructure;

public readonly record struct ProcessEntry(uint Pid, uint ParentPid, string Name);

/// <summary>
/// Lista de procesos con PID del padre usando CreateToolhelp32Snapshot.
/// Es mucho más barato que Process.GetProcesses() (no abre un handle por proceso ni carga contadores)
/// y no usa WMI, así que se puede consultar cada pocos segundos sin coste apreciable.
/// </summary>
public static class ProcessSnapshot
{
    public static List<ProcessEntry> Take()
    {
        var result = new List<ProcessEntry>(256);
        IntPtr snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE || snapshot == IntPtr.Zero)
            return result;

        try
        {
            var entry = new PROCESSENTRY32W { dwSize = (uint)Marshal.SizeOf<PROCESSENTRY32W>() };
            if (!Process32FirstW(snapshot, ref entry))
                return result;
            do
            {
                result.Add(new ProcessEntry(entry.th32ProcessID, entry.th32ParentProcessID, entry.szExeFile));
            }
            while (Process32NextW(snapshot, ref entry));
        }
        finally
        {
            CloseHandle(snapshot);
        }
        return result;
    }
}
