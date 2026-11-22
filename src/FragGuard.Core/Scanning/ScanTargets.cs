using Microsoft.Win32;

namespace FragGuard.Core.Scanning;

/// <summary>
/// Resolución de carpetas a analizar.
///
/// El servicio corre como SYSTEM, así que Environment.GetFolderPath devolvería el perfil de SYSTEM.
/// Por eso enumeramos los perfiles reales de usuario desde el registro (ProfileList) y, si el usuario
/// tiene la sesión iniciada (su hive está cargado en HKEY_USERS), leemos la ruta real de Descargas
/// (que el usuario puede haber movido a otro disco).
/// </summary>
public static class ScanTargets
{
    private const string DownloadsGuid = "{374DE290-123F-4565-9164-39C4925E467B}";

    public sealed record UserProfile(string Sid, string ProfilePath);

    /// <summary>Perfiles de usuario locales/dominio (SID S-1-5-21-*).</summary>
    public static List<UserProfile> GetUserProfiles()
    {
        var result = new List<UserProfile>();
        try
        {
            using var list = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList");
            if (list is null)
                return result;
            foreach (string sid in list.GetSubKeyNames())
            {
                if (!sid.StartsWith("S-1-5-21-", StringComparison.Ordinal))
                    continue; // descartamos SYSTEM, LocalService, NetworkService
                using var key = list.OpenSubKey(sid);
                if (key?.GetValue("ProfileImagePath") is string raw)
                {
                    string path = Environment.ExpandEnvironmentVariables(raw);
                    if (Directory.Exists(path))
                        result.Add(new UserProfile(sid, path));
                }
            }
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException or IOException)
        {
            // Sin acceso al registro: caemos al perfil actual.
        }

        if (result.Count == 0)
        {
            string current = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            if (!string.IsNullOrEmpty(current))
                result.Add(new UserProfile("", current));
        }
        return result;
    }

    /// <summary>Carpeta de Descargas de un perfil (la redirigida si se puede leer, si no la estándar).</summary>
    public static string GetDownloadsFolder(UserProfile profile)
    {
        if (!string.IsNullOrEmpty(profile.Sid))
        {
            try
            {
                using var key = Registry.Users.OpenSubKey($@"{profile.Sid}\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders");
                if (key?.GetValue(DownloadsGuid, null, RegistryValueOptions.DoNotExpandEnvironmentNames) is string raw)
                {
                    // %USERPROFILE% hay que expandirlo con el perfil del usuario, no con el de SYSTEM.
                    string expanded = raw.Replace("%USERPROFILE%", profile.ProfilePath, StringComparison.OrdinalIgnoreCase);
                    expanded = Environment.ExpandEnvironmentVariables(expanded);
                    if (Directory.Exists(expanded))
                        return expanded;
                }
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException or IOException)
            {
            }
        }
        return Path.Combine(profile.ProfilePath, "Downloads");
    }

    /// <summary>
    /// Ruta REAL de una carpeta de usuario ("Personal" = Documentos, "My Pictures", "Desktop"...) según su registro.
    /// Con OneDrive, Escritorio y Documentos suelen estar redirigidos a OneDrive\...; si no se puede leer
    /// (usuario sin sesión iniciada), se usa la ruta por defecto.
    /// </summary>
    public static string GetShellFolder(UserProfile profile, string valueName, string defaultSubfolder)
    {
        if (!string.IsNullOrEmpty(profile.Sid))
        {
            try
            {
                using var key = Registry.Users.OpenSubKey($@"{profile.Sid}\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders");
                if (key?.GetValue(valueName, null, RegistryValueOptions.DoNotExpandEnvironmentNames) is string raw)
                {
                    string expanded = Environment.ExpandEnvironmentVariables(
                        raw.Replace("%USERPROFILE%", profile.ProfilePath, StringComparison.OrdinalIgnoreCase));
                    if (Directory.Exists(expanded))
                        return expanded;
                }
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException or IOException)
            {
            }
        }
        return Path.Combine(profile.ProfilePath, defaultSubfolder);
    }

    /// <summary>Escaneo rápido: Descargas, Escritorio y AppData\Local\Temp de cada usuario (+ carpetas extra).</summary>
    public static List<string> GetQuickScanRoots(IEnumerable<string>? extraFolders = null)
    {
        var roots = new List<string>();
        foreach (var profile in GetUserProfiles())
        {
            roots.Add(GetDownloadsFolder(profile));
            roots.Add(GetShellFolder(profile, "Desktop", "Desktop"));
            roots.Add(Path.Combine(profile.ProfilePath, "AppData", "Local", "Temp"));
        }
        if (extraFolders is not null)
            roots.AddRange(extraFolders);
        return Normalize(roots);
    }

    /// <summary>Escaneo completo: todas las unidades fijas.</summary>
    public static List<string> GetFullScanRoots() =>
        DriveInfo.GetDrives()
            .Where(d => d.DriveType == DriveType.Fixed && d.IsReady)
            .Select(d => d.RootDirectory.FullName)
            .ToList();

    /// <summary>Carpetas que se excluyen siempre por rendimiento (almacén de componentes de Windows).</summary>
    public static List<string> GetDefaultExcludedDirectories()
    {
        string windir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        return new List<string>
        {
            Path.Combine(windir, "WinSxS"),
            Path.Combine(windir, "servicing"),
            Path.Combine(windir, "SoftwareDistribution", "DataStore")
        };
    }

    /// <summary>Quita duplicados, inexistentes y carpetas contenidas en otras de la lista.</summary>
    public static List<string> Normalize(IEnumerable<string> folders)
    {
        var existing = folders
            .Where(f => !string.IsNullOrWhiteSpace(f))
            .Select(f => Path.GetFullPath(f).TrimEnd('\\'))
            .Where(f => Directory.Exists(f) || File.Exists(f))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(f => f.Length)
            .ToList();

        var result = new List<string>();
        foreach (var f in existing)
        {
            if (!result.Any(r => f.StartsWith(r + "\\", StringComparison.OrdinalIgnoreCase)))
                result.Add(f);
        }
        return result;
    }
}
