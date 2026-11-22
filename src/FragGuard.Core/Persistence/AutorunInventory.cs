using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;
using FragGuard.Core.Scanning;
using FragGuard.Core.Security;
using FragGuard.Shared;
using FragGuard.Shared.Models;
using Microsoft.Win32;

namespace FragGuard.Core.Persistence;

/// <summary>
/// Inventario de persistencia (lo que arranca solo con Windows), al estilo de Autoruns:
///  - Registro: Run / RunOnce del equipo (64 y 32 bits) y de cada usuario con sesión iniciada.
///  - Carpetas Inicio: la común y la de cada usuario.
///  - Tareas programadas: XML de C:\Windows\System32\Tasks (comando + argumentos).
///  - Servicios de inicio automático (solo consulta; desactivar servicios puede romper Windows).
/// Cada entrada se marca como de confianza (Windows o editor de confianza) o sospechosa (sin firma en
/// una carpeta de usuario). Es de SOLO LECTURA: desactivar/restaurar lo hace AutorunManager (servicio).
/// </summary>
public static class AutorunInventory
{
    public const string KindRegistry = "Registro";
    public const string KindStartupFolder = "Carpeta Inicio";
    public const string KindTask = "Tarea programada";
    public const string KindService = "Servicio";

    private static readonly string WindowsDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows).TrimEnd('\\') + "\\";

    public sealed record RegistryLocation(RegistryKey Root, string RootName, string SubKey);

    public static List<AutorunEntryDto> Collect(bool includeServices = true)
    {
        var list = new List<AutorunEntryDto>();
        Safe(() => list.AddRange(RegistryEntries()));
        Safe(() => list.AddRange(StartupFolderEntries()));
        Safe(() => list.AddRange(TaskEntries()));
        if (includeServices)
            Safe(() => list.AddRange(ServiceEntries()));
        return list;
    }

    private static void Safe(Action a)
    {
        try { a(); }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException or IOException) { }
    }

    // ---------------- Registro ----------------

    public static IEnumerable<RegistryLocation> RunKeys()
    {
        foreach (var sub in new[] { "Run", "RunOnce" })
        {
            yield return new(Registry.LocalMachine, "HKLM", $@"SOFTWARE\Microsoft\Windows\CurrentVersion\{sub}");
            yield return new(Registry.LocalMachine, "HKLM", $@"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\{sub}");
        }
        foreach (var p in ScanTargets.GetUserProfiles().Where(p => !string.IsNullOrEmpty(p.Sid)))
            foreach (var sub in new[] { "Run", "RunOnce" })
                yield return new(Registry.Users, $@"HKU\{p.Sid}", $@"{p.Sid}\Software\Microsoft\Windows\CurrentVersion\{sub}");
    }

    /// <summary>Ubicación legible y ÚNICA de una clave Run (p. ej. "HKU\S-1-5-21-...\Software\...\Run").</summary>
    public static string DisplayLocation(RegistryLocation loc) => loc.Root == Registry.Users
        ? $@"HKU\{loc.SubKey}"
        : $@"{loc.RootName}\{loc.SubKey}";

    private static IEnumerable<AutorunEntryDto> RegistryEntries()
    {
        foreach (var loc in RunKeys())
        {
            using var key = loc.Root.OpenSubKey(loc.SubKey);
            if (key is null)
                continue;
            foreach (string valueName in key.GetValueNames())
            {
                if (key.GetValue(valueName) is not string command || string.IsNullOrWhiteSpace(command))
                    continue;
                yield return Build(KindRegistry, DisplayLocation(loc), valueName, command, canDisable: true);
            }
        }
    }

    // ---------------- Carpetas Inicio ----------------

    public static IEnumerable<string> StartupFolders()
    {
        yield return Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup);
        foreach (var p in ScanTargets.GetUserProfiles())
            yield return Path.Combine(p.ProfilePath, "AppData", "Roaming", "Microsoft", "Windows", "Start Menu", "Programs", "Startup");
    }

    private static IEnumerable<AutorunEntryDto> StartupFolderEntries()
    {
        foreach (string dir in StartupFolders().Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (!Directory.Exists(dir))
                continue;
            foreach (string file in Directory.EnumerateFiles(dir))
            {
                if (Path.GetFileName(file).Equals("desktop.ini", StringComparison.OrdinalIgnoreCase))
                    continue;
                string command = file.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase) ? (ResolveShortcut(file) ?? file) : file;
                var e = Build(KindStartupFolder, dir, Path.GetFileName(file), command, canDisable: true);
                e.Id = MakeId(KindStartupFolder, file, "");
                yield return e;
            }
        }
    }

    /// <summary>Destino de un acceso directo (.lnk) mediante el COM de Windows Script Host.</summary>
    private static string? ResolveShortcut(string lnk)
    {
        try
        {
            var type = Type.GetTypeFromProgID("WScript.Shell");
            if (type is null) return null;
            dynamic shell = Activator.CreateInstance(type)!;
            dynamic sc = shell.CreateShortcut(lnk);
            string target = sc.TargetPath;
            string args = sc.Arguments;
            return string.IsNullOrWhiteSpace(target) ? null : (args.Length > 0 ? $"\"{target}\" {args}" : $"\"{target}\"");
        }
        catch
        {
            return null;
        }
    }

    // ---------------- Tareas programadas ----------------

    private static readonly XNamespace TaskNs = "http://schemas.microsoft.com/windows/2004/02/mit/task";

    private static IEnumerable<AutorunEntryDto> TaskEntries()
    {
        string root = Path.Combine(WindowsDir, "System32", "Tasks");
        if (!Directory.Exists(root))
            yield break;

        foreach (string file in Directory.EnumerateFiles(root, "*", new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true }))
        {
            XDocument doc;
            try { doc = XDocument.Load(file); }
            catch { continue; }

            string taskName = "\\" + Path.GetRelativePath(root, file);
            bool enabled = !string.Equals(doc.Descendants(TaskNs + "Settings").Elements(TaskNs + "Enabled").FirstOrDefault()?.Value, "false", StringComparison.OrdinalIgnoreCase);
            foreach (var exec in doc.Descendants(TaskNs + "Exec"))
            {
                string cmd = exec.Element(TaskNs + "Command")?.Value?.Trim() ?? "";
                if (cmd.Length == 0)
                    continue;
                string args = exec.Element(TaskNs + "Arguments")?.Value?.Trim() ?? "";
                string full = (cmd.StartsWith('"') ? cmd : $"\"{cmd}\"") + (args.Length > 0 ? " " + args : "");
                var e = Build(KindTask, taskName, Path.GetFileName(taskName), full, canDisable: true);
                e.Enabled = enabled;
                // Las tareas de \Microsoft\ son de Windows aunque su ejecutable esté firmado por catálogo.
                if (taskName.StartsWith(@"\Microsoft\", StringComparison.OrdinalIgnoreCase) && e.IsTrusted)
                    e.IsMicrosoft = true;
                yield return e;
                break; // una entrada por tarea
            }
        }
    }

    // ---------------- Servicios ----------------

    private static IEnumerable<AutorunEntryDto> ServiceEntries()
    {
        using var services = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
        if (services is null)
            yield break;
        foreach (string name in services.GetSubKeyNames())
        {
            using var k = services.OpenSubKey(name);
            if (k is null)
                continue;
            // Solo servicios Win32 (no drivers) de inicio automático.
            int type = k.GetValue("Type") is int t ? t : 0;
            int start = k.GetValue("Start") is int s ? s : 4;
            if ((type & 0x30) == 0 || start > 2 || k.GetValue("ImagePath") is not string imagePath)
                continue;
            var e = Build(KindService, @"HKLM\SYSTEM\CurrentControlSet\Services", (k.GetValue("DisplayName") as string) is { Length: > 0 } dn && !dn.StartsWith('@') ? dn : name, imagePath, canDisable: false);
            e.Id = MakeId(KindService, name, "");
            yield return e;
        }
    }

    // ---------------- Común ----------------

    private static AutorunEntryDto Build(string kind, string location, string name, string command, bool canDisable)
    {
        string? image = ResolveImage(command);
        bool exists = image is not null && File.Exists(image);
        bool inWindows = image is not null && image.StartsWith(WindowsDir, StringComparison.OrdinalIgnoreCase);
        var sig = exists && !inWindows ? Authenticode.Verify(image!) : SignatureInfo.Unsigned;
        bool trusted = inWindows || sig.IsTrustedPublisher;
        bool userWritable = image is not null && (image.Contains(@"\Users\", StringComparison.OrdinalIgnoreCase) || image.Contains(@"\ProgramData\", StringComparison.OrdinalIgnoreCase) || image.Contains(@"\Temp\", StringComparison.OrdinalIgnoreCase));

        // Intérpretes (cmd, powershell, wscript, rundll32...) que ejecutan algo de una carpeta de usuario.
        bool scriptFromUserPath = inWindows && command.Contains(@"\Users\", StringComparison.OrdinalIgnoreCase) &&
                                  ScriptHosts.Contains(Path.GetFileName(image!));

        return new AutorunEntryDto
        {
            Id = MakeId(kind, location, name),
            Kind = kind,
            Location = location,
            Name = name,
            Command = command,
            ImagePath = image,
            Publisher = inWindows ? "Microsoft Windows" : sig.IsValid ? sig.Publisher : null,
            IsSigned = inWindows || sig.IsValid,
            IsTrusted = trusted && !scriptFromUserPath,
            IsMicrosoft = inWindows || string.Equals(sig.Publisher, "Microsoft Corporation", StringComparison.OrdinalIgnoreCase),
            FileExists = exists,
            CanDisable = canDisable,
            IsSuspicious = scriptFromUserPath || (exists && !sig.IsValid && !inWindows && userWritable)
        };
    }

    private static readonly HashSet<string> ScriptHosts = new(StringComparer.OrdinalIgnoreCase)
    {
        "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe"
    };

    /// <summary>Ejecutable de una línea de comandos (con variables de entorno expandidas).</summary>
    public static string? ResolveImage(string command)
    {
        if (string.IsNullOrWhiteSpace(command))
            return null;
        string expanded = Environment.ExpandEnvironmentVariables(command.Trim());
        // Rutas de servicios del estilo \SystemRoot\System32\... o \??\C:\...
        expanded = expanded.Replace(@"\SystemRoot\", WindowsDir, StringComparison.OrdinalIgnoreCase);
        if (expanded.StartsWith(@"\??\")) expanded = expanded[4..];
        if (expanded.StartsWith(@"system32\", StringComparison.OrdinalIgnoreCase)) expanded = WindowsDir + expanded;

        string file = CommandLine.Split(expanded).FileName.Trim('"');
        if (file.Length == 0)
            return null;
        if (!Path.IsPathRooted(file))
        {
            // "rundll32.exe x" sin ruta: buscarlo en System32.
            string sys = Path.Combine(WindowsDir, "System32", file.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? file : file + ".exe");
            return File.Exists(sys) ? sys : file;
        }
        return file;
    }

    public static string MakeId(string kind, string location, string name) =>
        Convert.ToHexString(SHA1.HashData(Encoding.UTF8.GetBytes($"{kind}|{location}|{name}".ToUpperInvariant())))[..16];
}
