namespace FragGuard.Shared.Models;

/// <summary>Un juego instalado detectado por el servicio (Steam, Epic, Riot, EA, Ubisoft, GOG, Battle.net...).</summary>
public sealed class GameDto
{
    /// <summary>Identificador estable: "steam:730", "epic:Calluna", "reg:Riot Game valorant.live"...</summary>
    public string Id { get; set; } = "";
    public string Name { get; set; } = "";
    /// <summary>Plataforma: "Steam", "Epic Games", "Riot Games", "EA", "Ubisoft", "GOG", "Battle.net" u "Otro".</summary>
    public string Launcher { get; set; } = "";
    public string? InstallPath { get; set; }
    public long? SizeBytes { get; set; }

    /// <summary>Última vez que se abrió (UTC), o null si no se sabe / nunca.</summary>
    public DateTime? LastPlayedUtc { get; set; }
    /// <summary>De dónde sale la fecha: "Steam" (manifiesto) o "Windows" (Prefetch).</summary>
    public string? LastPlayedSource { get; set; }

    /// <summary>URI (steam://, uplay://, com.epicgames.launcher://) o línea de comandos para jugar.</summary>
    public string? LaunchTarget { get; set; }
    /// <summary>URI o línea de comandos del desinstalador OFICIAL de la plataforma.</summary>
    public string? UninstallCommand { get; set; }
    /// <summary>True si la plataforma no ofrece desinstalador directo y hay que hacerlo desde su lanzador (Epic).</summary>
    public bool UninstallViaLauncher { get; set; }

    /// <summary>Ejecutable o .ico para el icono.</summary>
    public string? IconPath { get; set; }
    /// <summary>Portada vertical (caché de Steam), si existe.</summary>
    public string? CoverPath { get; set; }
}

/// <summary>Petición de la lista de juegos.</summary>
public sealed class ListGamesRequest
{
    /// <summary>Ignorar la caché del servicio y volver a escanear.</summary>
    public bool ForceRefresh { get; set; }
}
