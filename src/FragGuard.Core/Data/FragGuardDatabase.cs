using Dapper;
using FragGuard.Core.Configuration;
using Microsoft.Data.Sqlite;

namespace FragGuard.Core.Data;

/// <summary>
/// Acceso a SQLite. Se abre una conexión por operación (Microsoft.Data.Sqlite las reutiliza con pooling),
/// lo que hace a los repositorios thread-safe sin bloqueos propios.
///
/// Las fechas se guardan como milisegundos Unix (INTEGER): compacto, ordenable y sin problemas de parseo.
/// </summary>
public sealed class FragGuardDatabase
{
    private readonly string _connectionString;

    public FragGuardDatabase(FragGuardPaths paths)
    {
        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = paths.DatabasePath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Private,
            Pooling = true,
            DefaultTimeout = 30 // segundos esperando un bloqueo antes de fallar
        }.ToString();
    }

    public SqliteConnection Open()
    {
        var connection = new SqliteConnection(_connectionString);
        connection.Open();
        return connection;
    }

    /// <summary>Crea el esquema si no existe. Idempotente: se llama en cada arranque.</summary>
    public void Initialize()
    {
        using var c = Open();
        // WAL: lecturas concurrentes mientras se escribe (UI consultando historial durante un escaneo).
        c.Execute("PRAGMA journal_mode=WAL;");
        c.Execute("PRAGMA synchronous=NORMAL;");
        c.Execute("""
            CREATE TABLE IF NOT EXISTS HashCache (
                Sha256        TEXT PRIMARY KEY,
                Verdict       INTEGER NOT NULL,
                ThreatsJson   TEXT,
                RulesVersion  TEXT NOT NULL,
                VtChecked     INTEGER NOT NULL DEFAULT 0,
                CheckedUnixMs INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS ScanHistory (
                Id             TEXT PRIMARY KEY,
                Kind           INTEGER NOT NULL,
                State          INTEGER NOT NULL,
                StartedUnixMs  INTEGER NOT NULL,
                FinishedUnixMs INTEGER,
                FilesScanned   INTEGER NOT NULL DEFAULT 0,
                FilesSkipped   INTEGER NOT NULL DEFAULT 0,
                ThreatsFound   INTEGER NOT NULL DEFAULT 0,
                Errors         INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS IX_ScanHistory_Started ON ScanHistory(StartedUnixMs DESC);

            CREATE TABLE IF NOT EXISTS Detections (
                Id             INTEGER PRIMARY KEY AUTOINCREMENT,
                ScanId         TEXT,
                ScanKind       INTEGER NOT NULL,
                FilePath       TEXT NOT NULL,
                Sha256         TEXT,
                Verdict        INTEGER NOT NULL,
                Action         INTEGER NOT NULL,
                ThreatsJson    TEXT NOT NULL,
                QuarantineId   TEXT,
                DetectedUnixMs INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS IX_Detections_Detected ON Detections(DetectedUnixMs DESC);

            CREATE TABLE IF NOT EXISTS Quarantine (
                Id                TEXT PRIMARY KEY,
                OriginalPath      TEXT NOT NULL,
                VaultFile         TEXT NOT NULL,
                Sha256            TEXT NOT NULL,
                ThreatName        TEXT NOT NULL,
                SizeBytes         INTEGER NOT NULL,
                QuarantinedUnixMs INTEGER NOT NULL,
                PendingReboot     INTEGER NOT NULL DEFAULT 0
            );

            -- Hashes que el usuario restauró de la cuarentena: no se vuelven a detectar.
            CREATE TABLE IF NOT EXISTS AllowList (
                Sha256      TEXT PRIMARY KEY,
                AddedUnixMs INTEGER NOT NULL,
                Note        TEXT
            );
            """);
    }

    public static long ToUnixMs(DateTime utc) => new DateTimeOffset(DateTime.SpecifyKind(utc, DateTimeKind.Utc)).ToUnixTimeMilliseconds();
    public static DateTime FromUnixMs(long ms) => DateTimeOffset.FromUnixTimeMilliseconds(ms).UtcDateTime;
}
