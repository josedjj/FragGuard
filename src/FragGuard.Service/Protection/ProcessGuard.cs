using System.Diagnostics;
using FragGuard.Core.Behavior;
using FragGuard.Core.Security;
using FragGuard.Service.Infrastructure;

namespace FragGuard.Service.Protection;

/// <summary>
/// Utilidades compartidas por los módulos de protección en ejecución: confianza de un ejecutable,
/// búsqueda del "origen real" de un proceso y cierre seguro de procesos.
/// </summary>
public static class ProcessGuard
{
    private static readonly string WindowsDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows).TrimEnd('\\') + "\\";
    private static readonly string[] ProgramFilesDirs =
    {
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles).TrimEnd('\\') + "\\",
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86).TrimEnd('\\') + "\\"
    };

    /// <summary>
    /// Intérpretes y lanzadores genéricos: el malware los usa de intermediarios (malware.exe → cmd.exe → vssadmin),
    /// así que no deciden la confianza; se sigue subiendo hasta el proceso que los lanzó.
    /// </summary>
    private static readonly HashSet<string> Intermediaries = new(StringComparer.OrdinalIgnoreCase)
    {
        "cmd.exe", "powershell.exe", "pwsh.exe", "conhost.exe", "wscript.exe", "cscript.exe", "mshta.exe",
        "rundll32.exe", "regsvr32.exe", "wmic.exe", "schtasks.exe", "reg.exe", "certutil.exe", "bitsadmin.exe"
    };

    /// <summary>Carpetas en las que un usuario normal puede escribir: el sitio típico del malware.</summary>
    public static bool IsUserWritableLocation(string? path)
    {
        if (string.IsNullOrEmpty(path))
            return false;
        return path.Contains(@"\Users\", StringComparison.OrdinalIgnoreCase) ||
               path.Contains(@"\ProgramData\", StringComparison.OrdinalIgnoreCase) ||
               path.Contains(@"\Temp\", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// ¿Es de confianza este ejecutable?
    ///  - Dentro de C:\Windows (solo un administrador puede escribir ahí; muchos binarios de Windows están
    ///    firmados por catálogo, no con firma embebida).
    ///  - Firma válida de un editor de la lista de confianza.
    ///  - Dentro de Program Files Y con cualquier firma válida.
    /// </summary>
    public static bool IsTrustedImage(string? path)
    {
        if (string.IsNullOrEmpty(path))
            return false;
        if (path.StartsWith(WindowsDir, StringComparison.OrdinalIgnoreCase))
            return true;
        var sig = Authenticode.Verify(path);
        if (sig.IsTrustedPublisher)
            return true;
        return sig.IsValid && ProgramFilesDirs.Any(p => path.StartsWith(p, StringComparison.OrdinalIgnoreCase));
    }

    public static bool IsSystemImage(string? path) =>
        path is not null && path.StartsWith(WindowsDir, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Construye los datos del proceso para las reglas de comportamiento: su línea de comandos y su ORIGEN
    /// (primer antecesor que no es un intérprete genérico).
    /// </summary>
    public static ProcessFacts Describe(ProcessEntry process, string? imagePath, IReadOnlyDictionary<uint, ProcessEntry> snapshot)
    {
        string? cmd = NativeMethods.TryGetCommandLine(process.Pid);

        uint originPid = process.ParentPid;
        string? originName = null, originPath = null;
        for (int depth = 0; depth < 6 && snapshot.TryGetValue(originPid, out var parent); depth++)
        {
            originName = parent.Name;
            originPath = NativeMethods.TryGetProcessPath(parent.Pid);
            if (!Intermediaries.Contains(parent.Name))
                break;
            if (parent.ParentPid == parent.Pid)
                break;
            originPid = parent.ParentPid;
        }

        bool trusted = originPath is not null && IsTrustedImage(originPath);
        return new ProcessFacts(process.Pid, process.Name, imagePath, cmd, originPid, originName, originPath, trusted);
    }

    /// <summary>Detiene un proceso comprobando antes que sigue siendo el mismo (los PID se reutilizan).</summary>
    public static bool TryKill(uint pid, string expectedName, ILogger logger)
    {
        if (pid <= 4 || pid == (uint)Environment.ProcessId)
            return false;
        try
        {
            using var p = Process.GetProcessById((int)pid);
            if (!string.Equals(p.ProcessName + ".exe", expectedName, StringComparison.OrdinalIgnoreCase))
                return false;
            p.Kill(entireProcessTree: false);
            logger.LogWarning("Proceso detenido por FragGuard: {Name} (PID {Pid})", expectedName, pid);
            return true;
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            return false;
        }
    }
}
