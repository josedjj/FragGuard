namespace FragGuard.Shared.Models;

/// <summary>
/// Configuración editable por el usuario. La persiste el servicio en %ProgramData%\FragGuard\settings.json.
/// La clave de VirusTotal NO forma parte de este objeto: se guarda aparte cifrada con DPAPI
/// y nunca se envía de vuelta a la UI (solo <see cref="HasVirusTotalKey"/>).
/// </summary>
public sealed class FragGuardSettings
{
    // ---------- Protección en tiempo real ----------
    public bool RealtimeEnabled { get; set; } = true;

    /// <summary>Carpetas extra vigiladas (carpetas de mods, etc.). Las Descargas de cada usuario se añaden solas.</summary>
    public List<string> WatchedFolders { get; set; } = new();

    /// <summary>Extensiones analizadas por la protección en tiempo real.</summary>
    public List<string> RealtimeExtensions { get; set; } = new()
    {
        ".exe", ".dll", ".bat", ".cmd", ".ps1", ".zip", ".rar", ".7z", ".scr", ".msi"
    };

    // ---------- Detección ----------
    /// <summary>Poner en cuarentena automáticamente los archivos con veredicto Malicioso.</summary>
    public bool AutoQuarantine { get; set; } = true;

    /// <summary>Tamaño máximo (MB) de archivo a analizar. Los mayores se omiten (SkipReason.TooLarge).</summary>
    public int MaxFileSizeMb { get; set; } = 200;

    /// <summary>Rutas excluidas (prefijo, sin distinguir mayúsculas).</summary>
    public List<string> Exclusions { get; set; } = new();

    /// <summary>Consultar hashes en VirusTotal (requiere clave configurada).</summary>
    public bool VirusTotalEnabled { get; set; } = true;

    /// <summary>Solo lectura para la UI: indica si hay una clave de VirusTotal guardada.</summary>
    public bool HasVirusTotalKey { get; set; }

    // ---------- Modo juego ----------
    public bool GameModeAuto { get; set; } = true;

    /// <summary>Activar modo juego cuando una aplicación está a pantalla completa (lo detecta la UI).</summary>
    public bool GameModeOnFullscreen { get; set; } = true;

    /// <summary>
    /// Lanzadores. Ojo: tener Steam abierto NO activa el modo juego; lo activa un proceso HIJO del lanzador
    /// (el juego), excepto los procesos auxiliares de <see cref="LauncherHelperProcesses"/>.
    /// </summary>
    public List<string> LauncherProcesses { get; set; } = new()
    {
        "steam.exe", "EpicGamesLauncher.exe", "Battle.net.exe", "RiotClientServices.exe",
        "EADesktop.exe", "UbisoftConnect.exe", "upc.exe", "GalaxyClient.exe", "XboxPcApp.exe"
    };

    /// <summary>Procesos auxiliares de los lanzadores que NO son juegos.</summary>
    public List<string> LauncherHelperProcesses { get; set; } = new()
    {
        "steamwebhelper.exe", "steamservice.exe", "steamerrorreporter.exe", "steamerrorreporter64.exe",
        "gldriverquery.exe", "gldriverquery64.exe", "vulkandriverquery.exe", "vulkandriverquery64.exe",
        "EpicWebHelper.exe", "UnrealCEFSubProcess.exe", "CrashReportClient.exe",
        "Battle.net Helper.exe", "Agent.exe", "RiotClientUx.exe", "RiotClientUxRender.exe", "RiotClientCrashHandler.exe",
        "EABackgroundService.exe", "EAConnect_microsoft.exe", "QtWebEngineProcess.exe", "UplayWebCore.exe",
        "GalaxyClient Helper.exe", "GOG Galaxy Notifications Renderer.exe", "conhost.exe", "WerFault.exe"
    };

    /// <summary>Ejecutables de juegos conocidos que activan el modo juego directamente.</summary>
    public List<string> GameProcesses { get; set; } = new()
    {
        "cs2.exe", "VALORANT-Win64-Shipping.exe", "League of Legends.exe", "FortniteClient-Win64-Shipping.exe",
        "r5apex.exe", "r5apex_dx12.exe", "Overwatch.exe", "RocketLeague.exe", "GTA5.exe", "GTA5_Enhanced.exe",
        "dota2.exe", "eldenring.exe", "Minecraft.Windows.exe", "javaw.exe", "RainbowSix.exe", "cod.exe",
        "TslGame.exe", "destiny2.exe", "Warframe.x64.exe", "PathOfExile.exe", "Diablo IV.exe", "wow.exe"
    };

    // ---------- Escaneo programado ----------
    public bool ScheduledScanEnabled { get; set; } = true;

    /// <summary>Hora local del escaneo rápido diario, formato HH:mm.</summary>
    public string ScheduledScanTime { get; set; } = "13:00";

    // ---------- Notificaciones ----------
    /// <summary>En modo juego solo se muestran notificaciones críticas (amenazas maliciosas).</summary>
    public bool SilenceNonCriticalInGameMode { get; set; } = true;
}
