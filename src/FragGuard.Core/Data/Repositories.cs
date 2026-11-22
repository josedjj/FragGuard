using System.Text.Json;
using Dapper;
using FragGuard.Shared.Ipc;
using FragGuard.Shared.Models;
using static FragGuard.Core.Data.FragGuardDatabase;

namespace FragGuard.Core.Data;

// Filas tal cual están en SQLite (tipos long porque SQLite devuelve INTEGER como Int64).
internal sealed class HashCacheRow
{
    public string Sha256 { get; set; } = "";
    public long Verdict { get; set; }
    public string? ThreatsJson { get; set; }
    public string RulesVersion { get; set; } = "";
    public long VtChecked { get; set; }
    public long CheckedUnixMs { get; set; }
}

internal sealed class ScanHistoryRow
{
    public string Id { get; set; } = "";
    public long Kind { get; set; }
    public long State { get; set; }
    public long StartedUnixMs { get; set; }
    public long? FinishedUnixMs { get; set; }
    public long FilesScanned { get; set; }
    public long FilesSkipped { get; set; }
    public long ThreatsFound { get; set; }
    public long Errors { get; set; }

    public ScanSummaryDto ToDto() => new()
    {
        ScanId = Id,
        Kind = (ScanKind)Kind,
        State = (ScanState)State,
        StartedUtc = FromUnixMs(StartedUnixMs),
        FinishedUtc = FinishedUnixMs is { } f ? FromUnixMs(f) : null,
        FilesScanned = FilesScanned,
        FilesSkipped = FilesSkipped,
        ThreatsFound = ThreatsFound,
        Errors = Errors
    };
}

internal sealed class DetectionRow
{
    public long Id { get; set; }
    public string? ScanId { get; set; }
    public long ScanKind { get; set; }
    public string FilePath { get; set; } = "";
    public string? Sha256 { get; set; }
    public long Verdict { get; set; }
    public long Action { get; set; }
    public string ThreatsJson { get; set; } = "[]";
    public string? QuarantineId { get; set; }
    public long DetectedUnixMs { get; set; }
}

internal sealed class QuarantineRow
{
    public string Id { get; set; } = "";
    public string OriginalPath { get; set; } = "";
    public string VaultFile { get; set; } = "";
    public string Sha256 { get; set; } = "";
    public string ThreatName { get; set; } = "";
    public long SizeBytes { get; set; }
    public long QuarantinedUnixMs { get; set; }
    public long PendingReboot { get; set; }
}

/// <summary>Entrada de la caché de veredictos por hash.</summary>
public sealed record CachedVerdict(FileVerdict Verdict, List<ThreatInfo> Threats, bool VtChecked);

/// <summary>
/// Caché de hashes ya analizados: evita re-analizar (y gastar cuota de VirusTotal) en archivos conocidos.
/// Una entrada solo vale si se generó con la misma versión de reglas YARA y no ha caducado.
/// </summary>
public sealed class HashCacheRepository
{
    private readonly FragGuardDatabase _db;
    public HashCacheRepository(FragGuardDatabase db) => _db = db;

    public CachedVerdict? Get(string sha256, string rulesVersion, TimeSpan ttl)
    {
        using var c = _db.Open();
        var row = c.QuerySingleOrDefault<HashCacheRow>("SELECT * FROM HashCache WHERE Sha256 = @sha256", new { sha256 });
        if (row is null || row.RulesVersion != rulesVersion)
            return null;
        if (DateTime.UtcNow - FromUnixMs(row.CheckedUnixMs) > ttl)
            return null;
        return new CachedVerdict((FileVerdict)row.Verdict, DeserializeThreats(row.ThreatsJson), row.VtChecked != 0);
    }

    public void Put(string sha256, FileVerdict verdict, IEnumerable<ThreatInfo> threats, string rulesVersion, bool vtChecked)
    {
        using var c = _db.Open();
        c.Execute("""
            INSERT INTO HashCache (Sha256, Verdict, ThreatsJson, RulesVersion, VtChecked, CheckedUnixMs)
            VALUES (@Sha256, @Verdict, @ThreatsJson, @RulesVersion, @VtChecked, @Now)
            ON CONFLICT(Sha256) DO UPDATE SET Verdict = excluded.Verdict, ThreatsJson = excluded.ThreatsJson,
                RulesVersion = excluded.RulesVersion, VtChecked = excluded.VtChecked, CheckedUnixMs = excluded.CheckedUnixMs
            """,
            new { Sha256 = sha256, Verdict = (int)verdict, ThreatsJson = SerializeThreats(threats), RulesVersion = rulesVersion, VtChecked = vtChecked ? 1 : 0, Now = ToUnixMs(DateTime.UtcNow) });
    }

    public void Remove(string sha256)
    {
        using var c = _db.Open();
        c.Execute("DELETE FROM HashCache WHERE Sha256 = @sha256", new { sha256 });
    }

    internal static string SerializeThreats(IEnumerable<ThreatInfo> threats) =>
        JsonSerializer.Serialize(threats.ToList(), FragGuardJsonContext.Default.ListThreatInfo);

    internal static List<ThreatInfo> DeserializeThreats(string? json)
    {
        if (string.IsNullOrEmpty(json))
            return new();
        try { return JsonSerializer.Deserialize(json, FragGuardJsonContext.Default.ListThreatInfo) ?? new(); }
        catch (JsonException) { return new(); }
    }
}

public sealed class AllowListRepository
{
    private readonly FragGuardDatabase _db;
    public AllowListRepository(FragGuardDatabase db) => _db = db;

    public bool Contains(string sha256)
    {
        using var c = _db.Open();
        return c.ExecuteScalar<long>("SELECT COUNT(1) FROM AllowList WHERE Sha256 = @sha256", new { sha256 }) > 0;
    }

    public void Add(string sha256, string? note)
    {
        using var c = _db.Open();
        c.Execute("INSERT OR REPLACE INTO AllowList (Sha256, AddedUnixMs, Note) VALUES (@sha256, @now, @note)",
            new { sha256, now = ToUnixMs(DateTime.UtcNow), note });
    }
}

public sealed class ScanHistoryRepository
{
    private readonly FragGuardDatabase _db;
    public ScanHistoryRepository(FragGuardDatabase db) => _db = db;

    public void Upsert(ScanSummaryDto s)
    {
        using var c = _db.Open();
        c.Execute("""
            INSERT INTO ScanHistory (Id, Kind, State, StartedUnixMs, FinishedUnixMs, FilesScanned, FilesSkipped, ThreatsFound, Errors)
            VALUES (@Id, @Kind, @State, @Started, @Finished, @FilesScanned, @FilesSkipped, @ThreatsFound, @Errors)
            ON CONFLICT(Id) DO UPDATE SET State = excluded.State, FinishedUnixMs = excluded.FinishedUnixMs,
                FilesScanned = excluded.FilesScanned, FilesSkipped = excluded.FilesSkipped,
                ThreatsFound = excluded.ThreatsFound, Errors = excluded.Errors
            """,
            new
            {
                Id = s.ScanId, Kind = (int)s.Kind, State = (int)s.State,
                Started = ToUnixMs(s.StartedUtc),
                Finished = s.FinishedUtc is { } f ? ToUnixMs(f) : (long?)null,
                s.FilesScanned, s.FilesSkipped, s.ThreatsFound, s.Errors
            });
    }

    public List<ScanSummaryDto> GetRecent(int limit)
    {
        using var c = _db.Open();
        return c.Query<ScanHistoryRow>("SELECT * FROM ScanHistory ORDER BY StartedUnixMs DESC LIMIT @limit", new { limit })
            .Select(r => r.ToDto()).ToList();
    }

    /// <summary>Último escaneo manual/programado terminado (los de tiempo real no cuentan como "último escaneo").</summary>
    public ScanSummaryDto? GetLastCompleted()
    {
        using var c = _db.Open();
        return c.QuerySingleOrDefault<ScanHistoryRow>(
            "SELECT * FROM ScanHistory WHERE State IN (3, 4) AND Kind <> 3 ORDER BY StartedUnixMs DESC LIMIT 1")?.ToDto();
    }

    /// <summary>Fecha de inicio (UTC) del último escaneo de un tipo dado (para el programador diario).</summary>
    public DateTime? GetLastStartedUtc(ScanKind kind)
    {
        using var c = _db.Open();
        long? ms = c.ExecuteScalar<long?>("SELECT MAX(StartedUnixMs) FROM ScanHistory WHERE Kind = @kind", new { kind = (int)kind });
        return ms is { } v ? FromUnixMs(v) : null;
    }

    /// <summary>Marca como fallidos los escaneos que quedaron "Running" por un apagado inesperado.</summary>
    public void MarkInterrupted()
    {
        using var c = _db.Open();
        c.Execute("UPDATE ScanHistory SET State = @failed, FinishedUnixMs = @now WHERE State IN (1, 2)",
            new { failed = (int)ScanState.Failed, now = ToUnixMs(DateTime.UtcNow) });
    }
}

public sealed class DetectionRepository
{
    private readonly FragGuardDatabase _db;
    public DetectionRepository(FragGuardDatabase db) => _db = db;

    public long Add(DetectionDto d)
    {
        using var c = _db.Open();
        return c.ExecuteScalar<long>("""
            INSERT INTO Detections (ScanId, ScanKind, FilePath, Sha256, Verdict, Action, ThreatsJson, QuarantineId, DetectedUnixMs)
            VALUES (@ScanId, @ScanKind, @FilePath, @Sha256, @Verdict, @Action, @ThreatsJson, @QuarantineId, @Detected);
            SELECT last_insert_rowid();
            """,
            new
            {
                d.ScanId, ScanKind = (int)d.ScanKind, d.FilePath, d.Sha256, Verdict = (int)d.Verdict, Action = (int)d.Action,
                ThreatsJson = HashCacheRepository.SerializeThreats(d.Threats), d.QuarantineId, Detected = ToUnixMs(d.DetectedUtc)
            });
    }

    public List<DetectionDto> GetRecent(int limit)
    {
        using var c = _db.Open();
        return c.Query<DetectionRow>("SELECT * FROM Detections ORDER BY DetectedUnixMs DESC LIMIT @limit", new { limit })
            .Select(r => new DetectionDto
            {
                Id = r.Id,
                ScanId = r.ScanId,
                ScanKind = (ScanKind)r.ScanKind,
                FilePath = r.FilePath,
                Sha256 = r.Sha256,
                Verdict = (FileVerdict)r.Verdict,
                Action = (ThreatAction)r.Action,
                Threats = HashCacheRepository.DeserializeThreats(r.ThreatsJson),
                QuarantineId = r.QuarantineId,
                DetectedUtc = FromUnixMs(r.DetectedUnixMs)
            }).ToList();
    }

    /// <summary>Amenazas bloqueadas = detecciones maliciosas que terminaron en cuarentena.</summary>
    public long CountBlocked()
    {
        using var c = _db.Open();
        return c.ExecuteScalar<long>("SELECT COUNT(1) FROM Detections WHERE Action IN (@q, @p)",
            new { q = (int)ThreatAction.Quarantined, p = (int)ThreatAction.QuarantinePendingReboot });
    }
}

public sealed class QuarantineRepository
{
    private readonly FragGuardDatabase _db;
    public QuarantineRepository(FragGuardDatabase db) => _db = db;

    public sealed record Item(string Id, string OriginalPath, string VaultFile, string Sha256, string ThreatName, long SizeBytes, DateTime QuarantinedUtc, bool PendingReboot)
    {
        public QuarantineItemDto ToDto() => new()
        {
            Id = Id, OriginalPath = OriginalPath, Sha256 = Sha256, ThreatName = ThreatName,
            SizeBytes = SizeBytes, QuarantinedUtc = QuarantinedUtc, PendingReboot = PendingReboot
        };
    }

    public void Add(Item i)
    {
        using var c = _db.Open();
        c.Execute("""
            INSERT INTO Quarantine (Id, OriginalPath, VaultFile, Sha256, ThreatName, SizeBytes, QuarantinedUnixMs, PendingReboot)
            VALUES (@Id, @OriginalPath, @VaultFile, @Sha256, @ThreatName, @SizeBytes, @Ts, @Pending)
            """,
            new { i.Id, i.OriginalPath, i.VaultFile, i.Sha256, i.ThreatName, i.SizeBytes, Ts = ToUnixMs(i.QuarantinedUtc), Pending = i.PendingReboot ? 1 : 0 });
    }

    public Item? Get(string id)
    {
        using var c = _db.Open();
        var r = c.QuerySingleOrDefault<QuarantineRow>("SELECT * FROM Quarantine WHERE Id = @id", new { id });
        return r is null ? null : Map(r);
    }

    public List<Item> GetAll()
    {
        using var c = _db.Open();
        return c.Query<QuarantineRow>("SELECT * FROM Quarantine ORDER BY QuarantinedUnixMs DESC").Select(Map).ToList();
    }

    public int Count()
    {
        using var c = _db.Open();
        return (int)c.ExecuteScalar<long>("SELECT COUNT(1) FROM Quarantine");
    }

    public void Remove(string id)
    {
        using var c = _db.Open();
        c.Execute("DELETE FROM Quarantine WHERE Id = @id", new { id });
    }

    private static Item Map(QuarantineRow r) =>
        new(r.Id, r.OriginalPath, r.VaultFile, r.Sha256, r.ThreatName, r.SizeBytes, FromUnixMs(r.QuarantinedUnixMs), r.PendingReboot != 0);
}
