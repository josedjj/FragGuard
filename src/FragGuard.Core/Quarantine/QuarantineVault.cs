using System.Buffers.Binary;
using System.Security.Cryptography;
using FragGuard.Core.Security;

namespace FragGuard.Core.Quarantine;

/// <summary>
/// Cifrado de archivos en cuarentena con AES-256-GCM por bloques (streaming: RAM constante aunque el archivo sea grande).
///
/// Formato del archivo .fgq:
///   "FGQ1" (4) | tamaño de bloque int32 (4) | prefijo de nonce aleatorio (8)
///   y por cada bloque: longitud int32 (4) | tag GCM (16) | datos cifrados (longitud)
///
/// Nonce de cada bloque = prefijo(8) + contador(4). El contador y un indicador de "último bloque" van como
/// datos asociados (AAD), así que reordenar, quitar o truncar bloques hace fallar el descifrado.
///
/// La clave (32 bytes aleatorios) se genera la primera vez y se guarda protegida con DPAPI.
/// </summary>
public sealed class QuarantineVault
{
    private static readonly byte[] Magic = "FGQ1"u8.ToArray();
    private const int ChunkSize = 1024 * 1024;
    private const int TagSize = 16;

    private readonly byte[] _key;

    public QuarantineVault(string keyPath)
    {
        _key = LoadOrCreateKey(keyPath);
    }

    private static byte[] LoadOrCreateKey(string keyPath)
    {
        byte[]? existing = SecretProtector.LoadFromFile(keyPath);
        if (existing is { Length: 32 })
            return existing;

        if (File.Exists(keyPath))
        {
            // Hay una clave pero no se puede descifrar (otra máquina / corrupta): NO la sobrescribimos,
            // porque perderíamos para siempre los archivos ya en cuarentena.
            throw new CryptographicException($"No se pudo descifrar la clave de cuarentena: {keyPath}");
        }

        byte[] key = RandomNumberGenerator.GetBytes(32);
        SecretProtector.SaveToFile(keyPath, key);
        return key;
    }

    public void Encrypt(Stream input, Stream output)
    {
        byte[] noncePrefix = RandomNumberGenerator.GetBytes(8);
        Span<byte> header = stackalloc byte[16];
        Magic.CopyTo(header);
        BinaryPrimitives.WriteInt32LittleEndian(header[4..], ChunkSize);
        noncePrefix.CopyTo(header[8..]);
        output.Write(header);

        using var aes = new AesGcm(_key, TagSize);
        // Dos buffers que se alternan: leemos con un bloque de adelanto para saber cuál es el último
        // (se marca en el AAD) sin reservar memoria nueva por bloque.
        byte[] plain = new byte[ChunkSize];
        byte[] next = new byte[ChunkSize];
        byte[] cipher = new byte[ChunkSize];
        byte[] tag = new byte[TagSize];
        byte[] nonce = new byte[12];
        byte[] aad = new byte[5];
        Span<byte> lenBuf = stackalloc byte[4];

        noncePrefix.CopyTo(nonce, 0);
        int counter = 0;

        int read = ReadChunk(input, plain);
        while (true)
        {
            int nextRead = 0;
            bool isLast;
            if (read < ChunkSize)
            {
                isLast = true;
            }
            else
            {
                nextRead = ReadChunk(input, next);
                isLast = nextRead == 0;
            }

            BinaryPrimitives.WriteInt32LittleEndian(nonce.AsSpan(8), counter);
            BinaryPrimitives.WriteInt32LittleEndian(aad, counter);
            aad[4] = (byte)(isLast ? 1 : 0);

            aes.Encrypt(nonce, plain.AsSpan(0, read), cipher.AsSpan(0, read), tag, aad);

            BinaryPrimitives.WriteInt32LittleEndian(lenBuf, read);
            output.Write(lenBuf);
            output.Write(tag);
            output.Write(cipher, 0, read);

            if (isLast)
                break;

            (plain, next) = (next, plain);
            read = nextRead;
            counter++;
        }

        CryptographicOperations.ZeroMemory(plain);
        CryptographicOperations.ZeroMemory(next);
    }

    public void Decrypt(Stream input, Stream output)
    {
        Span<byte> header = stackalloc byte[16];
        input.ReadExactly(header);
        if (!header[..4].SequenceEqual(Magic))
            throw new InvalidDataException("No es un archivo de cuarentena de FragGuard.");
        int chunkSize = BinaryPrimitives.ReadInt32LittleEndian(header[4..]);
        if (chunkSize <= 0 || chunkSize > 16 * 1024 * 1024)
            throw new InvalidDataException("Tamaño de bloque inválido.");

        byte[] nonce = new byte[12];
        header[8..16].CopyTo(nonce);

        using var aes = new AesGcm(_key, TagSize);
        byte[] cipher = new byte[chunkSize];
        byte[] plain = new byte[chunkSize];
        byte[] tag = new byte[TagSize];
        byte[] aad = new byte[5];
        Span<byte> lenBuf = stackalloc byte[4];
        int counter = 0;

        while (true)
        {
            input.ReadExactly(lenBuf);
            int len = BinaryPrimitives.ReadInt32LittleEndian(lenBuf);
            if (len < 0 || len > chunkSize)
                throw new InvalidDataException("Bloque corrupto.");
            input.ReadExactly(tag);
            input.ReadExactly(cipher, 0, len);

            // ¿Es el último? Lo es si no quedan más bytes en el archivo.
            bool isLast = input.Position >= input.Length;

            BinaryPrimitives.WriteInt32LittleEndian(nonce.AsSpan(8), counter);
            BinaryPrimitives.WriteInt32LittleEndian(aad, counter);
            aad[4] = (byte)(isLast ? 1 : 0);

            // Lanza AuthenticationTagMismatchException si el archivo fue manipulado.
            aes.Decrypt(nonce, cipher.AsSpan(0, len), tag, plain.AsSpan(0, len), aad);
            output.Write(plain, 0, len);

            if (isLast)
                break;
            counter++;
        }

        CryptographicOperations.ZeroMemory(plain);
    }

    private static int ReadChunk(Stream s, byte[] buffer)
    {
        int total = 0;
        while (total < buffer.Length)
        {
            int r = s.Read(buffer, total, buffer.Length - total);
            if (r == 0)
                break;
            total += r;
        }
        return total;
    }
}
