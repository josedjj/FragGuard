namespace FragGuard.Service.Infrastructure;

/// <summary>
/// Carpetas conocidas que la UI resuelve en la sesión del usuario y nos envía por el pipe
/// (complementan lo que el servicio deduce del registro de cada perfil).
/// </summary>
public sealed class UserFolderRegistry
{
    private readonly object _sync = new();
    private readonly HashSet<string> _downloads = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _desktops = new(StringComparer.OrdinalIgnoreCase);

    public event Action? Changed;

    public void Register(string? downloads, string? desktop)
    {
        bool changed = false;
        lock (_sync)
        {
            if (IsValid(downloads))
                changed |= _downloads.Add(Path.GetFullPath(downloads!));
            if (IsValid(desktop))
                changed |= _desktops.Add(Path.GetFullPath(desktop!));
        }
        if (changed)
            Changed?.Invoke();
    }

    public List<string> Downloads
    {
        get { lock (_sync) return _downloads.ToList(); }
    }

    public List<string> AllFolders
    {
        get { lock (_sync) return _downloads.Concat(_desktops).ToList(); }
    }

    // Solo rutas absolutas locales existentes: no aceptamos rutas UNC ni relativas desde el pipe.
    private static bool IsValid(string? path) =>
        !string.IsNullOrWhiteSpace(path) && Path.IsPathFullyQualified(path) && !path.StartsWith(@"\\") && Directory.Exists(path);
}
