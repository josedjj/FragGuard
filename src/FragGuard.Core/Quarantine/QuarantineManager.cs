using System.ComponentModel;
using System.Runtime.InteropServices;
using FragGuard.Core.Configuration;
using FragGuard.Core.Data;
using FragGuard.Core.Hashing;
using FragGuard.Core.IO;
using FragGuard.Shared.Models;
using Microsoft.Extensions.Logging;

namespace FragGuard.Core.Quarantine;

public sealed record QuarantineOutcome(bool Success, ThreatAction Action, string? QuarantineId, string? Error);

/// <summary>
/// Mueve archivos a la cuarentena cifrada y permite restaurarlos o eliminarlos.
///
/// Flujo de "mover a cuarentena":
///  1. Se cifra el original en %ProgramData%\FragGuard\quarantine\{guid}.fgq (no ejecutable, con ACL restringida).
///  2. Se borra el original. Si está en uso (p. ej. un .exe ejecutándose), se programa su borrado
///     al reiniciar (MoveFileEx + MOVEFILE_DELAY_UNTIL_REBOOT) y se marca como "pendiente de reinicio".
/// </summary>
public sealed class QuarantineManager
{
    private readonly FragGuardPaths _paths;
    private readonly QuarantineVault _vault;
    private readonly QuarantineRepository _repo;
    private readonly AllowListRepository _allowList;
    private readonly HashCacheRepository _cache;
    private readonly ILogger<QuarantineManager> _logger;
    private readonly SemaphoreSlim _gate = new(1, 1); // una operación de cuarentena a la vez

    public QuarantineManager(FragGuardPaths paths, QuarantineVault vault, QuarantineRepository repo,
        AllowListRepository allowList, HashCacheRepository cache, ILogger<QuarantineManager> logger)
    {
        _paths = paths;
        _vault = vault;
        _repo = repo;
        _allowList = allowList;
        _cache = cache;
        _logger = logger;
    }

    public async Task<QuarantineOutcome> QuarantineAsync(string path, string sha256, string threatName, CancellationToken ct)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            string id = Guid.NewGuid().ToString("N");
            string vaultFile = Path.Combine(_paths.QuarantineDirectory, id + ".fgq");
            long size;

            // 1) Cifrar copia dentro de la bóveda.
            try
            {
                using var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                size = input.Length;
                using var output = new FileStream(vaultFile, FileMode.CreateNew, FileAccess.Write, FileShare.None);
                _vault.Encrypt(input, output);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                TryDelete(vaultFile);
                _logger.LogError(ex, "No se pudo copiar a cuarentena {Path}", path);
                return new(false, ThreatAction.QuarantineFailed, null, ex.Message);
            }

            // 2) Eliminar el original.
            bool pendingReboot = false;
            try
            {
                File.SetAttributes(path, FileAttributes.Normal); // quita solo-lectura/oculto
                File.Delete(path);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                if (ScheduleDeleteOnReboot(path))
                {
                    pendingReboot = true;
                    _logger.LogWarning("Archivo en uso, se eliminará al reiniciar: {Path}", path);
                }
                else
                {
                    // Ni borrar ni programar el borrado: deshacemos para no dejar una copia huérfana.
                    TryDelete(vaultFile);
                    _logger.LogError(ex, "No se pudo eliminar el original {Path}", path);
                    return new(false, ThreatAction.QuarantineFailed, null, ex.Message);
                }
            }

            _repo.Add(new QuarantineRepository.Item(id, path, Path.GetFileName(vaultFile), sha256, threatName, size, DateTime.UtcNow, pendingReboot));
            _logger.LogWarning("Cuarentena: {Path} ({Threat}) -> {Id}", path, threatName, id);
            return new(true, pendingReboot ? ThreatAction.QuarantinePendingReboot : ThreatAction.Quarantined, id, null);
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>
    /// Restaura un archivo a su ruta original (o a "nombre (restaurado N).ext" si ya existe otro allí)
    /// y añade su hash a la lista de permitidos para que no se vuelva a detectar.
    /// </summary>
    public async Task<(bool Success, string Message)> RestoreAsync(string id, CancellationToken ct)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var item = _repo.Get(id);
            if (item is null)
                return (false, "Elemento no encontrado en cuarentena.");

            string vaultPath = Path.Combine(_paths.QuarantineDirectory, item.VaultFile);
            if (!File.Exists(vaultPath))
                return (false, "El archivo cifrado ya no existe.");

            string target = GetFreeRestorePath(item.OriginalPath);
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            string temp = target + ".fgrestore";

            try
            {
                using (var input = new FileStream(vaultPath, FileMode.Open, FileAccess.Read, FileShare.Read))
                using (var output = new FileStream(temp, FileMode.Create, FileAccess.Write, FileShare.None))
                    _vault.Decrypt(input, output);

                // Verificamos integridad antes de dejar el archivo en su sitio.
                string hash;
                using (var check = File.OpenRead(temp))
                    hash = await FileHasher.HashStreamAsync(check, ct).ConfigureAwait(false);
                if (!hash.Equals(item.Sha256, StringComparison.OrdinalIgnoreCase))
                {
                    TryDelete(temp);
                    return (false, "El hash del archivo restaurado no coincide: no se restaura.");
                }

                File.Move(temp, target);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.Cryptography.CryptographicException or InvalidDataException)
            {
                TryDelete(temp);
                _logger.LogError(ex, "Fallo restaurando {Id}", id);
                return (false, "No se pudo restaurar: " + ex.Message);
            }

            _allowList.Add(item.Sha256, $"Restaurado por el usuario desde cuarentena ({item.ThreatName})");
            _cache.Remove(item.Sha256);
            TryDelete(vaultPath);
            _repo.Remove(id);
            _logger.LogWarning("Restaurado de cuarentena {Id} -> {Target}", id, target);
            return (true, target);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<(bool Success, string Message)> DeleteAsync(string id, CancellationToken ct)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var item = _repo.Get(id);
            if (item is null)
                return (false, "Elemento no encontrado en cuarentena.");
            TryDelete(Path.Combine(_paths.QuarantineDirectory, item.VaultFile));
            _repo.Remove(id);
            _logger.LogInformation("Eliminado definitivamente de cuarentena {Id} ({Path})", id, item.OriginalPath);
            return (true, "Eliminado.");
        }
        finally
        {
            _gate.Release();
        }
    }

    public List<QuarantineItemDto> List() => _repo.GetAll().Select(i => i.ToDto()).ToList();

    private static string GetFreeRestorePath(string original)
    {
        if (!File.Exists(original))
            return original;
        string dir = Path.GetDirectoryName(original)!;
        string name = Path.GetFileNameWithoutExtension(original);
        string ext = Path.GetExtension(original);
        for (int i = 1; ; i++)
        {
            string candidate = Path.Combine(dir, $"{name} (restaurado {i}){ext}");
            if (!File.Exists(candidate))
                return candidate;
        }
    }

    private void TryDelete(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); }
        catch (Exception ex) { _logger.LogDebug(ex, "No se pudo borrar {Path}", path); }
    }

    // ---- Borrado diferido al reiniciar (requiere privilegios de administrador/SYSTEM) ----

    private const int MOVEFILE_DELAY_UNTIL_REBOOT = 0x4;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool MoveFileEx(string lpExistingFileName, string? lpNewFileName, int dwFlags);

    private bool ScheduleDeleteOnReboot(string path)
    {
        if (MoveFileEx(path, null, MOVEFILE_DELAY_UNTIL_REBOOT))
            return true;
        _logger.LogDebug("MoveFileEx falló: {Error}", new Win32Exception(Marshal.GetLastWin32Error()).Message);
        return false;
    }
}
