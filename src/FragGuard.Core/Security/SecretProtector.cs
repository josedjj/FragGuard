using System.Security.Cryptography;
using System.Text;

namespace FragGuard.Core.Security;

/// <summary>
/// Envoltorio de DPAPI (Data Protection API de Windows).
/// Se usa ámbito LocalMachine porque el servicio corre como SYSTEM y los datos deben sobrevivir a cambios
/// de usuario. La protección real frente a otros usuarios la aporta la ACL de la carpeta de datos.
/// </summary>
public static class SecretProtector
{
    // Entropía adicional: un atacante necesita conocerla además de poder llamar a DPAPI en esta máquina.
    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("FragGuard.DPAPI.v1::7d1c0e5a");

    public static byte[] Protect(byte[] plain) =>
        ProtectedData.Protect(plain, Entropy, DataProtectionScope.LocalMachine);

    public static byte[] Unprotect(byte[] cipher) =>
        ProtectedData.Unprotect(cipher, Entropy, DataProtectionScope.LocalMachine);

    /// <summary>Guarda un secreto cifrado en disco (escritura atómica).</summary>
    public static void SaveToFile(string path, byte[] plain)
    {
        byte[] cipher = Protect(plain);
        string tmp = path + ".tmp";
        File.WriteAllBytes(tmp, cipher);
        File.Move(tmp, path, overwrite: true);
    }

    /// <summary>Lee un secreto cifrado. Devuelve null si no existe o no se puede descifrar.</summary>
    public static byte[]? LoadFromFile(string path)
    {
        if (!File.Exists(path))
            return null;
        try
        {
            return Unprotect(File.ReadAllBytes(path));
        }
        catch (CryptographicException)
        {
            return null; // Archivo corrupto o creado en otra máquina
        }
    }
}
