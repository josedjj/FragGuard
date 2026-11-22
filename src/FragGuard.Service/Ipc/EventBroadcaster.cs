using System.Collections.Concurrent;
using System.Text.Json.Serialization.Metadata;
using FragGuard.Shared.Ipc;

namespace FragGuard.Service.Ipc;

/// <summary>
/// Reparte eventos (amenazas, progreso, modo juego...) a todas las UIs conectadas.
/// Si no hay ninguna conectada, el evento simplemente se descarta (queda en el historial/BD).
/// </summary>
public sealed class EventBroadcaster
{
    private readonly ConcurrentDictionary<Guid, ClientConnection> _clients = new();

    public int ClientCount => _clients.Count;

    internal void Register(ClientConnection client) => _clients[client.Id] = client;
    internal void Unregister(ClientConnection client) => _clients.TryRemove(client.Id, out _);

    public void Publish<T>(string eventType, T payload, JsonTypeInfo<T> typeInfo)
    {
        if (_clients.IsEmpty)
            return;
        var message = PipeProtocol.Create(eventType, payload, typeInfo);
        foreach (var client in _clients.Values)
            client.PostEvent(message);
    }
}
