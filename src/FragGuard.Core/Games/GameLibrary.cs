using FragGuard.Shared.Models;
using Microsoft.Extensions.Logging;

namespace FragGuard.Core.Games;

/// <summary>
/// Catálogo de juegos instalados: combina Steam, Epic y el registro de Windows, y calcula la
/// "última vez jugado" como el máximo entre lo que dice la plataforma (Steam) y Prefetch de Windows
/// (última ejecución de cualquier .exe de la carpeta del juego).
///
/// Es de SOLO LECTURA: no lanza, desinstala ni borra nada (eso lo hace la UI con los permisos del usuario).
/// El resultado se cachea unos minutos: escanear las carpetas de juegos no es gratis.
/// </summary>
public sealed class GameLibrary
{
    private static readonly TimeSpan CacheTtl = TimeSpan.FromMinutes(2);
    private const int MaxExecutablesPerGame = 150;

    // Ejecutables que no indican que se haya JUGADO, o con nombres tan GENÉRICOS que otros programas
    // también los usan. Prefetch solo guarda el nombre (no la ruta): un "launcher.exe" o "crashpad_handler.exe"
    // de cualquier otra app haría parecer que jugaste. Comprobado en un equipo real (RDR2 "jugado hace 43 min").
    private static readonly string[] IgnoredExeFragments =
    {
        "unins", "setup", "redist", "vcredist", "dxsetup", "install", "dotnet", "crash", "report", "prereq",
        "launcher", "bootstrap", "updater", "update", "helper", "anticheat", "easyanticheat", "eac_", "battleye", "beservice",
        "start_protected", "qtwebengine", "cefsharp", "subprocess", "cef", "webhelper", "activation", "cleanup",
        "touchup", "vulkan", "dxwebsetup", "overlay", "service", "server", "tool", "editor", "benchmark", "config", "settings"
    };

    /// <summary>Nombres exactos demasiado genéricos para atribuirlos a un juego concreto.</summary>
    private static readonly HashSet<string> GenericExeNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "game.exe", "play.exe", "start.exe", "run.exe", "main.exe", "app.exe", "client.exe", "win64.exe", "x64.exe", "shipping.exe"
    };

    private readonly ILogger<GameLibrary> _logger;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private List<GameDto>? _cache;
    private DateTime _cachedAtUtc;

    public GameLibrary(ILogger<GameLibrary> logger) => _logger = logger;

    public async Task<List<GameDto>> GetGamesAsync(bool forceRefresh, CancellationToken ct)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (!forceRefresh && _cache is not null && DateTime.UtcNow - _cachedAtUtc < CacheTtl)
                return _cache;

            var sw = System.Diagnostics.Stopwatch.StartNew();
            _cache = await Task.Run(() => Scan(ct), ct).ConfigureAwait(false);
            _cachedAtUtc = DateTime.UtcNow;
            _logger.LogInformation("Juegos detectados: {Count} en {Ms} ms", _cache.Count, sw.ElapsedMilliseconds);
            return _cache;
        }
        finally
        {
            _gate.Release();
        }
    }

    private List<GameDto> Scan(CancellationToken ct)
    {
        var prefetch = PrefetchIndex.Load();
        var detected = new List<DetectedGame>();

        // Cada proveedor por separado: si uno falla (formato raro, permisos), los demás siguen.
        AddSafe(detected, "Steam", SteamGames.Scan);
        AddSafe(detected, "Epic", EpicGames.Scan);
        AddSafe(detected, "Registro", RegistryGames.Scan);

        var result = new List<GameDto>();
        var seenPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var g in detected)
        {
            ct.ThrowIfCancellationRequested();

            // Un mismo juego puede aparecer en dos fuentes (p. ej. Epic + registro): nos quedamos con el primero.
            if (g.Dto.InstallPath is { } path && !seenPaths.Add(path.TrimEnd('\\')))
                continue;

            ComputeLastPlayed(g, prefetch);
            result.Add(g.Dto);
        }

        return result
            .OrderByDescending(g => g.LastPlayedUtc ?? DateTime.MinValue)
            .ThenBy(g => g.Name, StringComparer.CurrentCultureIgnoreCase)
            .ToList();
    }

    private void AddSafe(List<DetectedGame> target, string source, Func<IEnumerable<DetectedGame>> scan)
    {
        try
        {
            target.AddRange(scan());
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "No se pudieron leer los juegos de {Source}", source);
        }
    }

    private static void ComputeLastPlayed(DetectedGame g, PrefetchIndex prefetch)
    {
        DateTime? best = g.PlatformLastPlayedUtc;
        string? source = best is null ? null : "Steam";

        // Steam lanza sus juegos y registra cuándo: es la fuente exacta. Prefetch (solo nombres de exe)
        // podría confundirse con otros programas, así que para Steam no se usa.
        if (g.Dto.Launcher == "Steam")
        {
            g.Dto.LastPlayedUtc = best;
            g.Dto.LastPlayedSource = source;
            return;
        }

        if (prefetch.Count > 0)
        {
            foreach (string exe in GameExecutables(g))
            {
                if (prefetch.LastRun(exe) is { } t && (best is null || t > best))
                {
                    best = t;
                    source = "Windows";
                }
            }
        }

        g.Dto.LastPlayedUtc = best;
        g.Dto.LastPlayedSource = source;
    }

    /// <summary>Ejecutables del juego: los conocidos + los .exe de su carpeta (hasta 3 niveles de profundidad).</summary>
    private static IEnumerable<string> GameExecutables(DetectedGame g)
    {
        foreach (var exe in g.KnownExecutables)
            yield return exe;

        if (g.Dto.InstallPath is not { } dir || !Directory.Exists(dir))
            yield break;

        IEnumerable<string> files;
        try
        {
            files = Directory.EnumerateFiles(dir, "*.exe", new EnumerationOptions
            {
                RecurseSubdirectories = true,
                MaxRecursionDepth = 3,
                IgnoreInaccessible = true,
                AttributesToSkip = FileAttributes.ReparsePoint
            });
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            yield break;
        }

        int count = 0;
        foreach (string f in files)
        {
            string name = Path.GetFileName(f);
            if (name.Length < 9 /* "abcd.exe": nombres muy cortos son ambiguos */ || GenericExeNames.Contains(name) ||
                IgnoredExeFragments.Any(frag => name.Contains(frag, StringComparison.OrdinalIgnoreCase)))
                continue;
            yield return name;
            if (++count >= MaxExecutablesPerGame)
                yield break;
        }
    }
}
