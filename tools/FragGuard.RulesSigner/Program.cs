using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using FragGuard.Core.Updates;

// =====================================================================================
//  FragGuard.RulesSigner: herramienta del AUTOR (no se distribuye a los usuarios).
//
//    keygen                       Crea la clave del canal de reglas. La privada se guarda cifrada con DPAPI
//                                 (solo tu usuario en este PC puede usarla) y se imprime la pública para
//                                 embeberla en RulesChannel.EmbeddedPublicKey.
//    sign <reglas> <salida>       Firma todas las *.yar de <reglas> y genera el canal en <salida>
//                                 (manifest.json + manifest.sig + reglas).
//    verify <canal>               Verifica un canal con la clave pública embebida en FragGuard.
//    export-backup <archivo.pfx>  Exporta la clave privada protegida con contraseña (copia de seguridad).
// =====================================================================================

string keyDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "FragGuard-Signing");
string keyPath = Path.Combine(keyDir, "rules-signing.key");
byte[] entropy = Encoding.UTF8.GetBytes("FragGuard.RulesSigning.v1");

try
{
    switch (args.FirstOrDefault())
    {
        case "keygen": return KeyGen();
        case "sign" when args.Length == 3: return Sign(args[1], args[2]);
        case "verify" when args.Length == 2: return Verify(args[1]);
        case "export-backup" when args.Length == 2: return ExportBackup(args[1]);
        default:
            Console.WriteLine("Uso: keygen | sign <carpetaReglas> <carpetaCanal> | verify <carpetaCanal> | export-backup <archivo>");
            return 2;
    }
}
catch (Exception ex)
{
    Console.Error.WriteLine("ERROR: " + ex.Message);
    return 1;
}

int KeyGen()
{
    if (File.Exists(keyPath))
    {
        Console.Error.WriteLine($"Ya existe una clave en {keyPath}. No se sobrescribe (perderías la capacidad de firmar para las instalaciones existentes).");
        return 1;
    }
    Directory.CreateDirectory(keyDir);
    using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    byte[] privateKey = ecdsa.ExportPkcs8PrivateKey();
    File.WriteAllBytes(keyPath, ProtectedData.Protect(privateKey, entropy, DataProtectionScope.CurrentUser));
    CryptographicOperations.ZeroMemory(privateKey);

    Console.WriteLine("Clave del canal de reglas creada.");
    Console.WriteLine($"  Privada (cifrada con DPAPI de tu usuario): {keyPath}");
    Console.WriteLine("  HAZ UNA COPIA DE SEGURIDAD con: export-backup <archivo>");
    Console.WriteLine();
    Console.WriteLine("PUBLIC_KEY=" + Convert.ToBase64String(ecdsa.ExportSubjectPublicKeyInfo()));
    return 0;
}

ECDsa LoadPrivateKey()
{
    if (!File.Exists(keyPath))
        throw new InvalidOperationException($"No hay clave en {keyPath}. Ejecuta primero: keygen");
    byte[] pkcs8 = ProtectedData.Unprotect(File.ReadAllBytes(keyPath), entropy, DataProtectionScope.CurrentUser);
    var ecdsa = ECDsa.Create();
    ecdsa.ImportPkcs8PrivateKey(pkcs8, out _);
    CryptographicOperations.ZeroMemory(pkcs8);
    return ecdsa;
}

int Sign(string rulesDir, string channelDir)
{
    using var ecdsa = LoadPrivateKey();
    string publicKey = Convert.ToBase64String(ecdsa.ExportSubjectPublicKeyInfo());
    if (publicKey != RulesChannel.EmbeddedPublicKey)
        Console.WriteLine("AVISO: esta clave no coincide con la embebida en FragGuard; las instalaciones actuales rechazarán el canal.");

    var files = Directory.GetFiles(rulesDir, "*.yar").OrderBy(f => f, StringComparer.OrdinalIgnoreCase).ToList();
    if (files.Count == 0)
        throw new InvalidOperationException("No hay reglas .yar que firmar.");

    if (Directory.Exists(channelDir))
        foreach (var old in Directory.GetFiles(channelDir))
            File.Delete(old);
    Directory.CreateDirectory(channelDir);

    // Versión = fecha UTC (yyyyMMddHHmm): siempre creciente.
    long version = long.Parse(DateTime.UtcNow.ToString("yyyyMMddHHmm"));
    var entries = new List<object>();
    foreach (var f in files)
    {
        byte[] content = File.ReadAllBytes(f);
        string name = Path.GetFileName(f);
        File.WriteAllBytes(Path.Combine(channelDir, name), content);
        entries.Add(new { name, sha256 = Convert.ToHexString(SHA256.HashData(content)) });
    }

    byte[] manifest = JsonSerializer.SerializeToUtf8Bytes(new { version, createdUtc = DateTime.UtcNow, files = entries }, new JsonSerializerOptions { WriteIndented = true });
    RulesChannel.ParseManifest(manifest); // misma validación que hará el servicio
    byte[] signature = ecdsa.SignData(manifest, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

    File.WriteAllBytes(Path.Combine(channelDir, "manifest.json"), manifest);
    File.WriteAllText(Path.Combine(channelDir, "manifest.sig"), Convert.ToBase64String(signature));

    Console.WriteLine($"Canal firmado: versión {version}, {files.Count} reglas → {channelDir}");
    return Verify(channelDir);
}

int Verify(string channelDir)
{
    byte[] manifest = File.ReadAllBytes(Path.Combine(channelDir, "manifest.json"));
    byte[] signature = Convert.FromBase64String(File.ReadAllText(Path.Combine(channelDir, "manifest.sig")).Trim());
    bool ok = RulesChannel.VerifySignature(manifest, signature, RulesChannel.EmbeddedPublicKey);
    var parsed = RulesChannel.ParseManifest(manifest);
    foreach (var f in parsed.Files)
    {
        string hash = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(Path.Combine(channelDir, f.Name))));
        if (!hash.Equals(f.Sha256, StringComparison.OrdinalIgnoreCase)) { ok = false; Console.WriteLine($"  Hash incorrecto: {f.Name}"); }
    }
    Console.WriteLine(ok ? $"Verificación correcta (versión {parsed.Version}, {parsed.Files.Count} archivos)." : "VERIFICACIÓN FALLIDA.");
    return ok ? 0 : 1;
}

int ExportBackup(string target)
{
    Console.Write("Contraseña para la copia de seguridad: ");
    string password = ReadPassword();
    if (password.Length < 12)
        throw new InvalidOperationException("Usa una contraseña de al menos 12 caracteres.");
    using var ecdsa = LoadPrivateKey();
    byte[] encrypted = ecdsa.ExportEncryptedPkcs8PrivateKey(password,
        new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 600_000));
    File.WriteAllBytes(target, encrypted);
    Console.WriteLine($"Copia cifrada guardada en {target}. Guárdala fuera de este PC (no en el repositorio).");
    return 0;
}

static string ReadPassword()
{
    var sb = new StringBuilder();
    while (true)
    {
        var k = Console.ReadKey(intercept: true);
        if (k.Key == ConsoleKey.Enter) { Console.WriteLine(); return sb.ToString(); }
        if (k.Key == ConsoleKey.Backspace) { if (sb.Length > 0) sb.Length--; }
        else sb.Append(k.KeyChar);
    }
}
