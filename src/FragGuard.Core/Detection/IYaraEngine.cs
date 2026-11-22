using FragGuard.Shared.Models;

namespace FragGuard.Core.Detection;

/// <summary>
/// Abstracción del motor YARA. Permite cambiar dnYara por otra implementación
/// (p. ej. yara64.exe como proceso externo) sin tocar el resto del motor.
/// </summary>
public interface IYaraEngine : IDisposable
{
    /// <summary>Número de reglas compiladas cargadas.</summary>
    int RuleCount { get; }

    /// <summary>Huella de las reglas cargadas. Si cambia, la caché de hashes deja de ser válida.</summary>
    string RulesVersion { get; }

    /// <summary>
    /// (Re)compila todas las reglas .yar/.yara de las carpetas indicadas (en orden: un archivo con el mismo nombre
    /// en una carpeta posterior sustituye al anterior, así las reglas actualizadas reemplazan a las de serie).
    /// Las reglas con errores se omiten y se registran.
    /// </summary>
    void LoadRules(params string[] rulesDirectories);

    IReadOnlyList<ThreatInfo> ScanFile(string path);

    IReadOnlyList<ThreatInfo> ScanMemory(byte[] buffer, int length);
}
