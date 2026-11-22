using System.Buffers;
using System.Security.Cryptography;

namespace FragGuard.Core.Hashing;

/// <summary>Cálculo de SHA-256 sin cargar el archivo entero en memoria.</summary>
public static class FileHasher
{
    private const int ChunkSize = 256 * 1024;

    public static string HashBuffer(byte[] buffer, int length) =>
        Convert.ToHexString(SHA256.HashData(buffer.AsSpan(0, length))).ToLowerInvariant();

    /// <summary>Hash por streaming en bloques de 256 KB tomados del ArrayPool (RAM constante).</summary>
    public static async Task<string> HashStreamAsync(Stream stream, CancellationToken ct)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        byte[] chunk = ArrayPool<byte>.Shared.Rent(ChunkSize);
        try
        {
            int read;
            while ((read = await stream.ReadAsync(chunk.AsMemory(0, ChunkSize), ct).ConfigureAwait(false)) > 0)
                hash.AppendData(chunk, 0, read);
            return Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(chunk);
        }
    }
}
