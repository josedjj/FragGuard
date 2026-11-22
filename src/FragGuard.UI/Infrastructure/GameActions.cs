using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using CommunityToolkit.Mvvm.ComponentModel;
using FragGuard.Shared;
using FragGuard.Shared.Models;

namespace FragGuard.UI.Infrastructure;

/// <summary>
/// Acciones sobre juegos. Se ejecutan en la UI, con los permisos del USUARIO (nunca en el servicio SYSTEM):
///  - Jugar: el juego debe abrirse en la sesión del usuario.
///  - Desinstalar: siempre con el desinstalador OFICIAL de la plataforma (Steam, Riot, EA...), que limpia
///    también su registro y su lanzador. Si el desinstalador necesita administrador, Windows pide UAC.
///  - Borrar restos: con los permisos del usuario y a la Papelera (recuperable).
/// </summary>
public static class GameActions
{
    public static void Launch(GameDto game)
    {
        if (string.IsNullOrWhiteSpace(game.LaunchTarget))
            throw new InvalidOperationException("No se sabe cómo abrir este juego. Ábrelo desde su lanzador.");
        Start(game.LaunchTarget, workingDirFromExe: true);
    }

    /// <summary>Abre el desinstalador oficial. Devuelve false si el usuario canceló el aviso de UAC.</summary>
    public static bool StartUninstall(GameDto game)
    {
        if (string.IsNullOrWhiteSpace(game.UninstallCommand))
            throw new InvalidOperationException("Este juego no tiene desinstalador registrado. Desinstálalo desde su lanzador.");
        try
        {
            Start(game.UninstallCommand, workingDirFromExe: false);
            return true;
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 1223) // el usuario dijo "No" en UAC
        {
            return false;
        }
    }

    public static void OpenFolder(GameDto game)
    {
        if (game.InstallPath is { } p && Directory.Exists(p))
            Process.Start(new ProcessStartInfo("explorer.exe", $"\"{p}\"") { UseShellExecute = true });
    }

    private static void Start(string target, bool workingDirFromExe)
    {
        if (CommandLine.IsUri(target))
        {
            // steam://, uplay://, com.epicgames.launcher://: los abre el lanzador correspondiente.
            Process.Start(new ProcessStartInfo(target) { UseShellExecute = true });
            return;
        }

        var cmd = CommandLine.Split(target);
        var psi = new ProcessStartInfo(cmd.FileName, cmd.Arguments) { UseShellExecute = true };
        if (workingDirFromExe && Path.GetDirectoryName(cmd.FileName) is { Length: > 0 } dir)
            psi.WorkingDirectory = dir; // muchos juegos esperan arrancar desde su carpeta
        Process.Start(psi);
    }
}

/// <summary>Una carpeta candidata a "resto" de un juego desinstalado.</summary>
public sealed partial class LeftoverItem : ObservableObject
{
    public required string Path { get; init; }
    public required string Category { get; init; }
    /// <summary>Aviso para el usuario (p. ej. "puede contener partidas guardadas").</summary>
    public string? Note { get; init; }
    public bool MayContainSaves { get; init; }

    [ObservableProperty] private bool _isSelected;
    [ObservableProperty] private long _sizeBytes = -1;
    [ObservableProperty] private string _sizeText = "calculando…";
}

/// <summary>
/// Busca restos de un juego en las carpetas donde los juegos suelen guardar configuración, cachés y partidas.
///
/// Criterios CONSERVADORES (borrar de más es mucho peor que dejar algo):
///  - Solo carpetas cuyo nombre coincide EXACTAMENTE (sin distinguir mayúsculas) con el nombre del juego
///    o con el nombre de su carpeta de instalación. Nada de coincidencias parciales.
///  - Solo en ubicaciones conocidas (AppData, LocalLow, Documentos, My Games, Partidas guardadas, ProgramData),
///    hasta dos niveles (p. ej. LocalLow\Estudio\Juego).
///  - Nunca una carpeta que contenga la instalación de OTRO juego.
///  - Lo que puede contener partidas guardadas viene DESMARCADO por defecto.
/// </summary>
public static class LeftoverFinder
{
    private const int MinNameLength = 4;

    public static List<LeftoverItem> Find(GameDto game, bool stillInstalled, IEnumerable<GameDto> otherGames)
    {
        var variants = NameVariants(game);
        var protectedPaths = otherGames
            .Where(g => g.Id != game.Id && g.InstallPath is not null)
            .Select(g => Normalize(g.InstallPath!))
            .ToList();

        var results = new List<LeftoverItem>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        // 1) Carpeta de instalación que el desinstalador dejó atrás
        if (!stillInstalled && game.InstallPath is { } install && Directory.Exists(install) && IsSafeCandidate(install, protectedPaths))
        {
            seen.Add(Normalize(install));
            results.Add(new LeftoverItem
            {
                Path = install,
                Category = "Carpeta de instalación",
                Note = "El desinstalador la dejó en el disco.",
                IsSelected = true
            });
        }

        // 2) Ubicaciones típicas de configuración, cachés y partidas
        string profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string documents = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        var roots = new (string Path, string Category, bool Saves)[]
        {
            (Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "AppData\\Local", true),
            (Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "AppData\\Roaming", true),
            (System.IO.Path.Combine(profile, "AppData", "LocalLow"), "AppData\\LocalLow", true),
            (documents, "Documentos", true),
            (System.IO.Path.Combine(documents, "My Games"), "Documentos\\My Games", true),
            (System.IO.Path.Combine(profile, "Saved Games"), "Partidas guardadas", true),
            (Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "ProgramData", false)
        };

        foreach (var (root, category, saves) in roots)
        {
            if (!Directory.Exists(root))
                continue;
            foreach (string dir in CandidateDirs(root))
            {
                string leaf = System.IO.Path.GetFileName(dir);
                if (!variants.Contains(leaf) || !seen.Add(Normalize(dir)) || !IsSafeCandidate(dir, protectedPaths))
                    continue;
                results.Add(new LeftoverItem
                {
                    Path = dir,
                    Category = category,
                    MayContainSaves = saves,
                    Note = saves ? "Puede contener tus partidas guardadas y ajustes." : "Datos compartidos del juego.",
                    IsSelected = false // el usuario decide: mejor no borrar partidas por sorpresa
                });
            }
        }
        return results;
    }

    /// <summary>Subcarpetas de primer y segundo nivel de una raíz (p. ej. LocalLow\Estudio\Juego).</summary>
    private static IEnumerable<string> CandidateDirs(string root)
    {
        IEnumerable<string> level1;
        try { level1 = Directory.EnumerateDirectories(root).ToList(); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { yield break; }

        foreach (string d1 in level1)
        {
            yield return d1;
            IEnumerable<string> level2;
            try { level2 = Directory.EnumerateDirectories(d1).ToList(); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { continue; }
            foreach (string d2 in level2)
                yield return d2;
        }
    }

    /// <summary>Nombres con los que el juego suele crear sus carpetas.</summary>
    public static HashSet<string> NameVariants(GameDto game)
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        void Add(string? s)
        {
            if (string.IsNullOrWhiteSpace(s)) return;
            string t = s.Trim();
            if (t.Length >= MinNameLength) set.Add(t);
        }

        Add(game.Name);
        // Sin símbolos de marca ni signos: "Marvel’s Spider-Man™: Remastered" → "Marvels Spider-Man Remastered"
        string clean = Regex.Replace(game.Name, @"[™®©’'`:]", "").Trim();
        Add(clean);
        Add(Regex.Replace(clean, @"\s+", " "));
        Add(clean.Replace(" ", ""));
        if (game.InstallPath is { } p)
            Add(System.IO.Path.GetFileName(p.TrimEnd('\\', '/')));
        return set;
    }

    private static bool IsSafeCandidate(string dir, List<string> protectedPaths)
    {
        string d = Normalize(dir);
        // Nunca raíces de unidad ni carpetas del sistema.
        if (d.Length <= 3 || d.StartsWith(Normalize(Environment.GetFolderPath(Environment.SpecialFolder.Windows)), StringComparison.OrdinalIgnoreCase))
            return false;
        // Nunca algo que contenga (o sea) la instalación de otro juego.
        return !protectedPaths.Any(p => p.Equals(d, StringComparison.OrdinalIgnoreCase) || p.StartsWith(d + "\\", StringComparison.OrdinalIgnoreCase));
    }

    private static string Normalize(string path)
    {
        try { return System.IO.Path.GetFullPath(path).TrimEnd('\\'); }
        catch { return path.TrimEnd('\\'); }
    }

    public static long DirectorySize(string dir)
    {
        long total = 0;
        try
        {
            foreach (var f in new DirectoryInfo(dir).EnumerateFiles("*", new EnumerationOptions
                     { RecurseSubdirectories = true, IgnoreInaccessible = true, AttributesToSkip = FileAttributes.ReparsePoint }))
                total += f.Length;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        return total;
    }
}

/// <summary>Envío a la Papelera de reciclaje (recuperable), con aviso de Windows si algo no cabe y se borraría para siempre.</summary>
public static class RecycleBin
{
    public static (bool Ok, string? Error) Send(string path)
    {
        var op = new SHFILEOPSTRUCT
        {
            wFunc = FO_DELETE,
            pFrom = path + "\0", // la API exige doble terminador nulo
            fFlags = FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_WANTNUKEWARNING | FOF_NOERRORUI | FOF_SILENT
        };
        int result = SHFileOperation(ref op);
        if (result == 0 && !op.fAnyOperationsAborted && !Directory.Exists(path))
            return (true, null);
        if (op.fAnyOperationsAborted)
            return (false, "Cancelado.");
        return (false, result is 0x78 or 5 ? "Acceso denegado (prueba como administrador)." : $"Error de Windows 0x{result:X}.");
    }

    private const uint FO_DELETE = 0x0003;
    private const ushort FOF_SILENT = 0x0004;
    private const ushort FOF_NOCONFIRMATION = 0x0010;
    private const ushort FOF_ALLOWUNDO = 0x0040;
    private const ushort FOF_NOERRORUI = 0x0400;
    private const ushort FOF_WANTNUKEWARNING = 0x4000;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct SHFILEOPSTRUCT
    {
        public IntPtr hwnd;
        public uint wFunc;
        public string pFrom;
        public string? pTo;
        public ushort fFlags;
        [MarshalAs(UnmanagedType.Bool)] public bool fAnyOperationsAborted;
        public IntPtr hNameMappings;
        public string? lpszProgressTitle;
    }

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    private static extern int SHFileOperation(ref SHFILEOPSTRUCT lpFileOp);
}
