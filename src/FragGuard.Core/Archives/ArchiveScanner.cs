using FragGuard.Core.Configuration;
using FragGuard.Core.Detection;
using FragGuard.Core.IO;
using FragGuard.Shared.Models;
using Microsoft.Extensions.Logging;
using SharpCompress.Common;
using SharpCompress.Readers;

namespace FragGuard.Core.Archives;

/// <summary>Resultado del análisis de un comprimido.</summary>
public sealed class ArchiveScanResult
{
    public List<ThreatInfo> Threats { get; } = new();
    /// <summary>El comprimido (o alguna entrada) estaba cifrado con contraseña y no se pudo inspeccionar.</summary>
    public bool HasEncryptedEntries { get; set; }
    public int EntriesScanned { get; set; }
    public int EntriesSkipped { get; set; }
    public bool LimitReached { get; set; }
}

/// <summary>
/// Inspecciona .zip / .rar / .7z entrada a entrada SIN extraer nada a disco:
/// cada entrada se descomprime a un buffer en memoria y se pasa a YARA + heurística de nombres.
///
/// Protecciones anti zip-bomb: nº máximo de entradas, tamaño máximo por entrada,
/// total descomprimido máximo y profundidad máxima de anidamiento.
/// </summary>
public sealed class ArchiveScanner
{
    private readonly IYaraEngine _yara;
    private readonly EngineOptions _options;
    private readonly ILogger<ArchiveScanner> _logger;

    public ArchiveScanner(IYaraEngine yara, EngineOptions options, ILogger<ArchiveScanner> logger)
    {
        _yara = yara;
        _options = options;
        _logger = logger;
    }

    public bool IsArchive(string path) => _options.ArchiveExtensions.Contains(Path.GetExtension(path));

    public ArchiveScanResult Scan(Stream archiveStream, string displayName, CancellationToken ct)
    {
        var result = new ArchiveScanResult();
        long totalBytes = 0;
        ScanRecursive(archiveStream, displayName, depth: 1, result, ref totalBytes, ct);
        return result;
    }

    private void ScanRecursive(Stream stream, string displayName, int depth, ArchiveScanResult result, ref long totalBytes, CancellationToken ct)
    {
        IReader reader;
        try
        {
            reader = ReaderFactory.OpenReader(stream, new ReaderOptions { LeaveStreamOpen = true });
        }
        catch (Exception ex) when (IsArchiveReadError(ex))
        {
            // Formato no soportado por el lector en streaming (p. ej. algunos 7z) o comprimido dañado.
            _logger.LogDebug("No se pudo abrir el comprimido {Name}: {Error}", displayName, ex.Message);
            result.EntriesSkipped++;
            return;
        }

        using (reader)
        {
            while (true)
            {
                ct.ThrowIfCancellationRequested();

                bool hasNext;
                try { hasNext = reader.MoveToNextEntry(); }
                catch (Exception ex) when (IsEncryptionError(ex)) { result.HasEncryptedEntries = true; break; }
                catch (Exception ex) when (IsArchiveReadError(ex))
                {
                    _logger.LogDebug("Comprimido {Name} dañado o no soportado: {Error}", displayName, ex.Message);
                    break;
                }
                if (!hasNext)
                    break;

                var entry = reader.Entry;
                if (entry.IsDirectory)
                    continue;

                if (result.EntriesScanned + result.EntriesSkipped >= _options.ArchiveMaxEntries)
                {
                    result.LimitReached = true;
                    break;
                }

                string entryName = entry.Key ?? "(sin nombre)";
                string fullName = $"{displayName} > {entryName}";

                // Heurística de nombres también dentro del comprimido (cheat.exe dentro de "skins.zip").
                if (CheatLureAnalyzer.Analyze(entryName) is { } lure)
                {
                    lure.Description = $"[{entryName}] {lure.Description}";
                    result.Threats.Add(lure);
                }

                if (entry.IsEncrypted)
                {
                    result.HasEncryptedEntries = true;
                    result.EntriesSkipped++;
                    continue;
                }

                if (totalBytes >= _options.ArchiveMaxTotalBytes)
                {
                    result.EntriesSkipped++;
                    result.LimitReached = true;
                    break;
                }

                if (entry.Size > _options.ArchiveMaxEntryBytes)
                {
                    result.EntriesSkipped++;
                    continue;
                }

                ScanEntry(reader, entry.Size, entryName, fullName, depth, result, ref totalBytes, ct);
            }
        }
    }

    private void ScanEntry(IReader reader, long declaredSize, string entryName, string fullName, int depth,
        ArchiveScanResult result, ref long totalBytes, CancellationToken ct)
    {
        // Límite de lectura: lo que quede de presupuesto, sin pasar del máximo por entrada.
        int cap = (int)Math.Min(_options.ArchiveMaxEntryBytes, _options.ArchiveMaxTotalBytes - totalBytes);

        // Si el comprimido declara el tamaño, reservamos solo eso (+1 para detectar si miente).
        // Un tamaño declarado falso (zip-bomb) se detecta porque la lectura supera el buffer.
        int bufferSize = declaredSize > 0 ? (int)Math.Min(cap, declaredSize + 1) : cap;

        byte[] buffer = ScanBuffers.Rent(bufferSize);
        try
        {
            int length;
            try
            {
                using var entryStream = reader.OpenEntryStream();
                length = ReadUpTo(entryStream, buffer, bufferSize, out bool truncated);
                if (truncated)
                {
                    result.EntriesSkipped++;
                    result.LimitReached = true;
                    return;
                }
            }
            catch (Exception ex) when (IsEncryptionError(ex))
            {
                result.HasEncryptedEntries = true;
                result.EntriesSkipped++;
                return;
            }
            catch (Exception ex) when (IsArchiveReadError(ex))
            {
                _logger.LogDebug("Entrada ilegible {Entry}: {Error}", fullName, ex.Message);
                result.EntriesSkipped++;
                return;
            }

            totalBytes += length;
            result.EntriesScanned++;

            foreach (var threat in _yara.ScanMemory(buffer, length))
            {
                threat.Description = $"[{entryName}] {threat.Description}";
                result.Threats.Add(threat);
            }

            // Comprimido dentro de comprimido: se inspecciona hasta la profundidad máxima.
            if (depth < _options.ArchiveMaxDepth && _options.ArchiveExtensions.Contains(Path.GetExtension(entryName)))
            {
                using var inner = new MemoryStream(buffer, 0, length, writable: false);
                ScanRecursive(inner, fullName, depth + 1, result, ref totalBytes, ct);
            }
        }
        finally
        {
            ScanBuffers.Return(buffer);
        }
    }

    /// <summary>Lee hasta llenar el buffer; truncated = true si la entrada tenía más datos de los permitidos.</summary>
    private static int ReadUpTo(Stream stream, byte[] buffer, int cap, out bool truncated)
    {
        int total = 0;
        while (total < cap)
        {
            int read = stream.Read(buffer, total, cap - total);
            if (read == 0)
            {
                truncated = false;
                return total;
            }
            total += read;
        }
        truncated = stream.ReadByte() != -1;
        return total;
    }

    private static bool IsEncryptionError(Exception ex) =>
        ex is SharpCompress.Common.CryptographicException or System.Security.Cryptography.CryptographicException;

    private static bool IsArchiveReadError(Exception ex) =>
        ex is InvalidFormatException or ArchiveException or IncompleteArchiveException
            or IOException or NotSupportedException or InvalidOperationException or IndexOutOfRangeException
            or ArgumentException;
}
