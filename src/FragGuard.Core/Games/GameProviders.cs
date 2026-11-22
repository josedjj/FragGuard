using System.Text.Json;
using System.Text.RegularExpressions;
using FragGuard.Core.Scanning;
using FragGuard.Shared.Models;
using Microsoft.Win32;

namespace FragGuard.Core.Games;

/// <summary>Juego detectado + datos internos que no viajan a la UI.</summary>
internal sealed class DetectedGame
{
    public required GameDto Dto { get; init; }
    /// <summary>LastPlayed según la propia plataforma (Steam).</summary>
    public DateTime? PlatformLastPlayedUtc { get; init; }
    /// <summary>Ejecutables conocidos del juego (además de los que se encuentren en su carpeta).</summary>
    public List<string> KnownExecutables { get; } = new();
}

// =====================================================================================
//  Steam
// =====================================================================================

/// <summary>
/// Juegos de Steam: libraryfolders.vdf → bibliotecas (puede haber varias en distintos discos)
/// → steamapps\appmanifest_*.acf (nombre, carpeta, tamaño y LastPlayed).
/// </summary>
public static class SteamGames
{
    // Herramientas que Steam instala como "apps" pero que no son juegos.
    private static readonly HashSet<string> ToolAppIds = new() { "228980", "1070560", "1391110", "1628350", "1493710", "1826330", "2180100", "2348590", "961940", "1161040", "1580130", "1887720" };
    private static readonly Regex ToolNames = new(@"Redistributable|Steam Linux Runtime|^Proton|Steamworks|SteamVR", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    public static string? FindSteamPath()
    {
        foreach (var keyPath in new[] { @"SOFTWARE\WOW6432Node\Valve\Steam", @"SOFTWARE\Valve\Steam" })
        {
            using var key = Registry.LocalMachine.OpenSubKey(keyPath);
            if (key?.GetValue("InstallPath") is string p && Directory.Exists(p))
                return p;
        }
        return null;
    }

    internal static IEnumerable<DetectedGame> Scan()
    {
        string? steam = FindSteamPath();
        if (steam is null)
            yield break;

        var libraries = new List<string> { steam };
        string lf = Path.Combine(steam, "steamapps", "libraryfolders.vdf");
        if (File.Exists(lf))
        {
            var root = VdfParser.ParseFile(lf).Child("libraryfolders");
            if (root is not null)
                foreach (var entry in root.Values.OfType<VdfParser.Node>())
                    if (entry.Str("path") is { } p && Directory.Exists(p))
                        libraries.Add(p);
        }

        string cache = Path.Combine(steam, "appcache", "librarycache");
        var seen = new HashSet<string>();

        foreach (string lib in libraries.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            string steamapps = Path.Combine(lib, "steamapps");
            if (!Directory.Exists(steamapps))
                continue;

            foreach (string acf in Directory.EnumerateFiles(steamapps, "appmanifest_*.acf"))
            {
                VdfParser.Node? app;
                try { app = VdfParser.ParseFile(acf).Child("AppState"); }
                catch (IOException) { continue; }
                if (app is null)
                    continue;

                string? appId = app.Str("appid");
                string? name = app.Str("name");
                string? installDir = app.Str("installdir");
                if (appId is null || name is null || installDir is null || !seen.Add(appId))
                    continue;
                if (ToolAppIds.Contains(appId) || ToolNames.IsMatch(name))
                    continue;

                string path = Path.Combine(steamapps, "common", installDir);
                if (!Directory.Exists(path))
                    continue; // manifiesto huérfano o descarga sin empezar

                long? lastPlayed = app.Long("LastPlayed");
                yield return new DetectedGame
                {
                    PlatformLastPlayedUtc = lastPlayed is > 0 ? DateTimeOffset.FromUnixTimeSeconds(lastPlayed.Value).UtcDateTime : null,
                    Dto = new GameDto
                    {
                        Id = "steam:" + appId,
                        Name = name,
                        Launcher = "Steam",
                        InstallPath = path,
                        SizeBytes = app.Long("SizeOnDisk") is > 0 and var size ? size : null,
                        LaunchTarget = "steam://rungameid/" + appId,
                        UninstallCommand = "steam://uninstall/" + appId,
                        CoverPath = FindCover(cache, appId)
                    }
                };
            }
        }
    }

    /// <summary>Portada vertical de la caché de Steam (la estructura varía según la versión del cliente).</summary>
    private static string? FindCover(string cache, string appId)
    {
        string dir = Path.Combine(cache, appId);
        if (Directory.Exists(dir))
        {
            string direct = Path.Combine(dir, "library_600x900.jpg");
            if (File.Exists(direct))
                return direct;
            // Orden de preferencia: portada vertical (antigua y nueva, con o sin sufijo de idioma)
            // y, si no hay, la cabecera horizontal.
            foreach (string pattern in new[] { "library_600x900*.jpg", "library_capsule*.jpg", "header*.jpg", "library_header*.jpg" })
            {
                var found = Directory.EnumerateFiles(dir, pattern, SearchOption.AllDirectories).FirstOrDefault();
                if (found is not null)
                    return found;
            }
        }
        // Formato antiguo: librarycache\730_library_600x900.jpg
        string legacy = Path.Combine(cache, appId + "_library_600x900.jpg");
        return File.Exists(legacy) ? legacy : null;
    }
}

// =====================================================================================
//  Epic Games
// =====================================================================================

/// <summary>Juegos de Epic: manifiestos JSON en %ProgramData%\Epic\EpicGamesLauncher\Data\Manifests.</summary>
internal static class EpicGames
{
    public static IEnumerable<DetectedGame> Scan()
    {
        string dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "Epic", "EpicGamesLauncher", "Data", "Manifests");
        if (!Directory.Exists(dir))
            yield break;

        foreach (string file in Directory.EnumerateFiles(dir, "*.item"))
        {
            JsonElement root;
            try
            {
                using var doc = JsonDocument.Parse(File.ReadAllText(file));
                root = doc.RootElement.Clone();
            }
            catch (Exception ex) when (ex is IOException or JsonException) { continue; }

            if (Bool(root, "bIsIncompleteInstall") || !Bool(root, "bIsApplication", defaultValue: true))
                continue;

            string? name = Str(root, "DisplayName");
            string? location = Str(root, "InstallLocation");
            string? appName = Str(root, "AppName");
            if (name is null || location is null || appName is null || !Directory.Exists(location))
                continue;

            string? exe = Str(root, "LaunchExecutable") is { } rel ? Path.Combine(location, rel) : null;
            string? ns = Str(root, "CatalogNamespace");
            string? item = Str(root, "CatalogItemId");

            var game = new DetectedGame
            {
                Dto = new GameDto
                {
                    Id = "epic:" + appName,
                    Name = name,
                    Launcher = "Epic Games",
                    InstallPath = location,
                    SizeBytes = root.TryGetProperty("InstallSize", out var size) && size.TryGetInt64(out long s) && s > 0 ? s : null,
                    LaunchTarget = ns is not null && item is not null
                        ? $"com.epicgames.launcher://apps/{ns}%3A{item}%3A{appName}?action=launch&silent=true"
                        : exe,
                    // Epic no ofrece desinstalador por línea de comandos: se desinstala desde su biblioteca.
                    UninstallCommand = "com.epicgames.launcher://",
                    UninstallViaLauncher = true,
                    IconPath = exe is not null && File.Exists(exe) ? exe : null
                }
            };
            if (exe is not null)
                game.KnownExecutables.Add(exe);
            yield return game;
        }
    }

    private static string? Str(JsonElement e, string name) =>
        e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    private static bool Bool(JsonElement e, string name, bool defaultValue = false) =>
        e.TryGetProperty(name, out var v) && v.ValueKind is JsonValueKind.True or JsonValueKind.False ? v.GetBoolean() : defaultValue;
}

// =====================================================================================
//  Registro de Windows (Riot, EA, Ubisoft, GOG, Battle.net, Rockstar y otros)
// =====================================================================================

/// <summary>
/// Juegos registrados en "Programas y características" (claves Uninstall), del equipo y de cada usuario.
/// Solo se aceptan editores de videojuegos conocidos, y se descartan los propios lanzadores y herramientas.
/// </summary>
internal static class RegistryGames
{
    private const string UninstallKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
    private const string UninstallKeyWow = @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall";

    private static readonly Regex GamePublishers = new(
        @"Riot|Blizzard|GOG\.com|Electronic Arts|Ubisoft|Mojang|Rockstar|Bethesda|CD PROJEKT|Activision|Bandai|Square Enix|SEGA|Capcom|" +
        @"\b2K\b|Paradox|Warner Bros|Bungie|miHoYo|HoYoverse|Cognosphere|Krafton|PUBG|Wargaming|Grinding Gear|Digital Extremes|Hi-Rez|" +
        @"Nexon|NetEase|Garena|Smilegate|Gaijin|Bohemia|Respawn|Epic Games",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    // Lanzadores, herramientas y componentes que NO son juegos.
    private static readonly Regex NotAGame = new(
        @"Launcher|Riot Client|Vanguard|Repair Tool|GALAXY|EA app|Origin\b|Battle\.net|Ubisoft Connect|Uplay\b|Online Services|" +
        @"\bSDK\b|Social Club|REDlauncher|Overlay|Anti.?Cheat|Redistributable|Prerequisite|Runtime|Driver|Updater|Helper|Installer",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    public static IEnumerable<DetectedGame> Scan()
    {
        var sources = new List<(RegistryKey Root, string Path)>
        {
            (Registry.LocalMachine, UninstallKey),
            (Registry.LocalMachine, UninstallKeyWow)
        };

        // Instalaciones por usuario (Riot instala en HKCU). El servicio corre como SYSTEM: leemos el hive
        // de cada usuario con sesión iniciada (cargado en HKEY_USERS).
        foreach (var profile in ScanTargets.GetUserProfiles())
            if (!string.IsNullOrEmpty(profile.Sid))
                sources.Add((Registry.Users, $@"{profile.Sid}\{UninstallKey}"));
        sources.Add((Registry.CurrentUser, UninstallKey)); // ejecución interactiva (tests / desarrollo)

        var seenKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (root, path) in sources)
        {
            RegistryKey? parent;
            try { parent = root.OpenSubKey(path); }
            catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException) { continue; }
            if (parent is null)
                continue;

            using (parent)
            {
                foreach (string keyName in parent.GetSubKeyNames())
                {
                    if (keyName.StartsWith("Steam App ", StringComparison.OrdinalIgnoreCase) || !seenKeys.Add(keyName))
                        continue; // los de Steam ya los lee SteamGames con más detalle

                    using var k = parent.OpenSubKey(keyName);
                    if (k is null)
                        continue;
                    if (TryCreate(keyName, k) is { } game)
                        yield return game;
                }
            }
        }
    }

    private static DetectedGame? TryCreate(string keyName, RegistryKey k)
    {
        string? name = (k.GetValue("DisplayName") as string)?.Trim();
        string? publisher = k.GetValue("Publisher") as string;
        if (string.IsNullOrEmpty(name) || k.GetValue("SystemComponent") is 1)
            return null;

        bool isRiot = keyName.StartsWith("Riot Game ", StringComparison.OrdinalIgnoreCase);
        bool isUbisoft = keyName.StartsWith("Uplay Install ", StringComparison.OrdinalIgnoreCase);
        if (!isRiot && !isUbisoft && (publisher is null || !GamePublishers.IsMatch(publisher)))
            return null;
        if (NotAGame.IsMatch(name))
            return null;

        string? location = Normalize(k.GetValue("InstallLocation") as string);
        string? icon = CleanIconPath(k.GetValue("DisplayIcon") as string);
        string? uninstall = k.GetValue("UninstallString") as string;
        bool hasLocation = location is not null && Directory.Exists(location);
        bool iconIsExe = icon is not null && icon.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) && File.Exists(icon);
        if (!hasLocation && !iconIsExe)
            return null; // entrada huérfana

        string launcher = isRiot ? "Riot Games"
            : isUbisoft ? "Ubisoft"
            : publisher!.Contains("Electronic Arts", StringComparison.OrdinalIgnoreCase) ? "EA"
            : publisher.Contains("GOG", StringComparison.OrdinalIgnoreCase) ? "GOG"
            : publisher.Contains("Blizzard", StringComparison.OrdinalIgnoreCase) ? "Battle.net"
            : publisher.Contains("Rockstar", StringComparison.OrdinalIgnoreCase) ? "Rockstar"
            : "Otro";

        // Cómo se lanza cada plataforma:
        string? launch = null;
        if (isRiot && uninstall is not null)
            launch = uninstall.Replace("--uninstall-product", "--launch-product").Replace("--uninstall-patchline", "--launch-patchline");
        else if (isUbisoft)
            launch = $"uplay://launch/{keyName["Uplay Install ".Length..]}/0";
        else if (iconIsExe)
            launch = $"\"{icon}\"";

        long? size = k.GetValue("EstimatedSize") is int kb && kb > 0 ? kb * 1024L : null;

        var game = new DetectedGame
        {
            Dto = new GameDto
            {
                Id = "reg:" + keyName,
                Name = name,
                Launcher = launcher,
                InstallPath = hasLocation ? location : Path.GetDirectoryName(icon),
                SizeBytes = size,
                LaunchTarget = launch,
                UninstallCommand = string.IsNullOrWhiteSpace(uninstall) ? null : uninstall,
                IconPath = icon is not null && File.Exists(icon) ? icon : null
            }
        };
        if (iconIsExe)
            game.KnownExecutables.Add(icon!);
        return game;
    }

    private static string? Normalize(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return null;
        try { return Path.GetFullPath(path.Trim().Trim('"')).TrimEnd('\\'); }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException) { return null; }
    }

    /// <summary>DisplayIcon suele venir como "C:\juego\game.exe",0 → C:\juego\game.exe</summary>
    private static string? CleanIconPath(string? icon)
    {
        if (string.IsNullOrWhiteSpace(icon))
            return null;
        string s = icon.Trim();
        int comma = s.LastIndexOf(',');
        if (comma > 2 && int.TryParse(s[(comma + 1)..].Trim(), out _))
            s = s[..comma];
        return Normalize(s);
    }
}

// =====================================================================================
//  Prefetch (última ejecución de cada .exe)
// =====================================================================================

/// <summary>
/// Windows guarda en C:\Windows\Prefetch un archivo NOMBRE.EXE-HASH.pf por programa ejecutado,
/// y lo actualiza en cada ejecución: su fecha de modificación ≈ última vez que se abrió.
/// Solo se puede leer como administrador (el servicio corre como SYSTEM). Si Prefetch está desactivado,
/// simplemente no hay datos.
/// </summary>
internal sealed class PrefetchIndex
{
    // El nombre del ejecutable en los archivos .pf se trunca a 29 caracteres.
    private const int MaxNameLength = 29;
    private readonly Dictionary<string, DateTime> _lastRun = new(StringComparer.OrdinalIgnoreCase);

    public static PrefetchIndex Load()
    {
        var index = new PrefetchIndex();
        string dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");
        try
        {
            foreach (var file in new DirectoryInfo(dir).EnumerateFiles("*.pf"))
            {
                int dash = file.Name.LastIndexOf('-');
                if (dash <= 0)
                    continue;
                string exe = file.Name[..dash];
                DateTime t = file.LastWriteTimeUtc;
                if (!index._lastRun.TryGetValue(exe, out var prev) || t > prev)
                    index._lastRun[exe] = t;
            }
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or System.Security.SecurityException)
        {
            // Sin permisos (UI sin servicio, tests) o Prefetch desactivado.
        }
        return index;
    }

    public int Count => _lastRun.Count;

    public DateTime? LastRun(string exeFileName)
    {
        string name = Path.GetFileName(exeFileName).ToUpperInvariant();
        if (name.Length > MaxNameLength)
            name = name[..MaxNameLength];
        return _lastRun.TryGetValue(name, out var t) ? t : null;
    }
}
