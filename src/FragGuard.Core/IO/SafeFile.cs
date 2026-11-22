using FragGuard.Shared.Models;

namespace FragGuard.Core.IO;

/// <summary>
/// Apertura de archivos "a prueba de balas": nunca lanza por archivos bloqueados, sin permisos o borrados;
/// devuelve un motivo (<see cref="SkipReason"/>) para que el escaneo continúe con el siguiente archivo.
/// </summary>
public static class SafeFile
{
    // ERROR_SHARING_VIOLATION (32) y ERROR_LOCK_VIOLATION (33) en HRESULT
    private const int HrSharingViolation = unchecked((int)0x80070020);
    private const int HrLockViolation = unchecked((int)0x80070021);

    public readonly record struct OpenResult(FileStream? Stream, SkipReason Reason, string? Error)
    {
        public bool Success => Stream is not null;
    }

    /// <summary>
    /// Abre en solo lectura compartiendo lectura/escritura/borrado (para no molestar al programa que lo use)
    /// y reintenta si está bloqueado (típico mientras el navegador termina una descarga).
    /// </summary>
    public static async Task<OpenResult> OpenReadAsync(string path, int retries, TimeSpan retryDelay, CancellationToken ct)
    {
        for (int attempt = 0; ; attempt++)
        {
            try
            {
                var stream = new FileStream(path, new FileStreamOptions
                {
                    Mode = FileMode.Open,
                    Access = FileAccess.Read,
                    Share = FileShare.ReadWrite | FileShare.Delete,
                    // Buffer pequeño: leemos en bloques grandes nosotros mismos
                    BufferSize = 0,
                    Options = FileOptions.SequentialScan
                });
                return new OpenResult(stream, SkipReason.None, null);
            }
            catch (FileNotFoundException) { return new(null, SkipReason.NotFound, null); }
            catch (DirectoryNotFoundException) { return new(null, SkipReason.NotFound, null); }
            catch (UnauthorizedAccessException ex) { return new(null, SkipReason.AccessDenied, ex.Message); }
            catch (IOException ex) when (IsLockViolation(ex))
            {
                if (attempt >= retries)
                    return new(null, SkipReason.Locked, ex.Message);
                await Task.Delay(retryDelay * (attempt + 1), ct).ConfigureAwait(false);
            }
            catch (IOException ex) { return new(null, SkipReason.Unsupported, ex.Message); }
        }
    }

    public static bool IsLockViolation(IOException ex) =>
        ex.HResult == HrSharingViolation || ex.HResult == HrLockViolation;

    /// <summary>Lee exactamente <paramref name="count"/> bytes (o hasta EOF) en el buffer.</summary>
    public static async Task<int> ReadFullyAsync(Stream stream, byte[] buffer, int count, CancellationToken ct)
    {
        int total = 0;
        while (total < count)
        {
            int read = await stream.ReadAsync(buffer.AsMemory(total, count - total), ct).ConfigureAwait(false);
            if (read == 0)
                break;
            total += read;
        }
        return total;
    }

    /// <summary>Comprueba si una ruta está bajo alguno de los prefijos dados (sin distinguir mayúsculas).</summary>
    public static bool IsUnder(string path, IEnumerable<string> prefixes)
    {
        foreach (var prefix in prefixes)
        {
            if (string.IsNullOrWhiteSpace(prefix))
                continue;
            string p = prefix.TrimEnd('\\', '/');
            if (path.Equals(p, StringComparison.OrdinalIgnoreCase) ||
                path.StartsWith(p + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }
}
