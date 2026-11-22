using System.Buffers;

namespace FragGuard.Core.IO;

/// <summary>
/// Gestión de buffers de análisis pensada para el objetivo de RAM en reposo (~50 MB):
/// - Buffers pequeños (≤ 1 MB): se reutilizan del ArrayPool compartido (rápido, sin presión de GC).
/// - Buffers grandes: se reservan puntualmente y NO se devuelven a ningún pool, para que el GC los libere
///   al terminar el escaneo. Si los pooláramos, el pool retendría decenas de MB por núcleo indefinidamente.
/// </summary>
public static class ScanBuffers
{
    public const int PooledMaxBytes = 1024 * 1024;

    public static byte[] Rent(int minimumLength) =>
        minimumLength <= PooledMaxBytes
            ? ArrayPool<byte>.Shared.Rent(Math.Max(minimumLength, 1))
            : GC.AllocateUninitializedArray<byte>(minimumLength);

    public static void Return(byte[] buffer)
    {
        if (buffer.Length <= PooledMaxBytes)
            ArrayPool<byte>.Shared.Return(buffer);
        // Los grandes simplemente se sueltan: el servicio compacta el LOH al terminar cada escaneo.
    }
}
