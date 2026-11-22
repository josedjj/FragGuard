using System.Buffers;
using System.Buffers.Binary;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;

namespace FragGuard.Shared.Ipc;

/// <summary>
/// Framing del protocolo: [longitud int32 little-endian][JSON UTF-8].
/// Prefijar la longitud evita depender de delimitadores y permite rechazar mensajes enormes antes de leerlos.
/// </summary>
public static class PipeProtocol
{
    /// <summary>Tamaño máximo de un mensaje (protege al servicio de clientes maliciosos o defectuosos).</summary>
    public const int MaxMessageBytes = 4 * 1024 * 1024;

    public static async Task WriteAsync(Stream stream, PipeMessage message, CancellationToken ct)
    {
        byte[] json = JsonSerializer.SerializeToUtf8Bytes(message, FragGuardJsonContext.Default.PipeMessage);
        if (json.Length > MaxMessageBytes)
            throw new InvalidDataException($"Mensaje demasiado grande ({json.Length} bytes).");

        // Cabecera + cuerpo en un único Write para que el mensaje llegue entero.
        byte[] buffer = ArrayPool<byte>.Shared.Rent(4 + json.Length);
        try
        {
            BinaryPrimitives.WriteInt32LittleEndian(buffer, json.Length);
            json.CopyTo(buffer, 4);
            await stream.WriteAsync(buffer.AsMemory(0, 4 + json.Length), ct).ConfigureAwait(false);
            await stream.FlushAsync(ct).ConfigureAwait(false);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    /// <summary>Lee un mensaje. Devuelve null si el otro extremo cerró la conexión.</summary>
    public static async Task<PipeMessage?> ReadAsync(Stream stream, CancellationToken ct)
    {
        byte[] header = new byte[4];
        if (!await ReadExactlyOrEofAsync(stream, header, ct).ConfigureAwait(false))
            return null;

        int length = BinaryPrimitives.ReadInt32LittleEndian(header);
        if (length <= 0 || length > MaxMessageBytes)
            throw new InvalidDataException($"Longitud de mensaje inválida: {length}.");

        byte[] body = ArrayPool<byte>.Shared.Rent(length);
        try
        {
            if (!await ReadExactlyOrEofAsync(stream, body.AsMemory(0, length), ct).ConfigureAwait(false))
                return null;
            return JsonSerializer.Deserialize(body.AsSpan(0, length), FragGuardJsonContext.Default.PipeMessage);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(body);
        }
    }

    private static async Task<bool> ReadExactlyOrEofAsync(Stream stream, Memory<byte> buffer, CancellationToken ct)
    {
        int total = 0;
        while (total < buffer.Length)
        {
            int read = await stream.ReadAsync(buffer[total..], ct).ConfigureAwait(false);
            if (read == 0)
                return false; // EOF: el cliente/servidor se desconectó
            total += read;
        }
        return true;
    }

    // ----- Ayudantes para construir y leer payloads tipados -----

    public static PipeMessage Create<T>(string type, T payload, JsonTypeInfo<T> typeInfo, string? correlationId = null) => new()
    {
        Type = type,
        CorrelationId = correlationId,
        Payload = JsonSerializer.SerializeToElement(payload, typeInfo)
    };

    public static PipeMessage Create(string type, string? correlationId = null) => new()
    {
        Type = type,
        CorrelationId = correlationId
    };

    public static T? GetPayload<T>(this PipeMessage message, JsonTypeInfo<T> typeInfo) =>
        message.Payload is { ValueKind: not JsonValueKind.Null and not JsonValueKind.Undefined } payload
            ? payload.Deserialize(typeInfo)
            : default;
}
