using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace FragGuard.Core.Security;

/// <summary>Resultado de verificar la firma Authenticode de un archivo.</summary>
public sealed record SignatureInfo(bool IsSigned, bool IsValid, string? Publisher, string? Thumbprint)
{
    public static readonly SignatureInfo Unsigned = new(false, false, null, null);

    /// <summary>Firma válida de un editor de la lista de confianza (Valve, Riot, Microsoft, NVIDIA...).</summary>
    public bool IsTrustedPublisher => IsValid && Publisher is not null && TrustedPublishers.Contains(Publisher);
}

/// <summary>
/// Verificación de firmas Authenticode con WinVerifyTrust, sin red (no consulta revocaciones en línea:
/// rápido y sin depender de Internet). Solo cubre firmas EMBEBIDAS; los binarios de Windows firmados por
/// catálogo aparecen como "sin firma embebida", lo cual no es un problema porque la firma solo se usa para
/// RELAJAR detecciones dudosas, nunca para endurecerlas.
///
/// Usos: reducir falsos positivos (un ejecutable firmado por Valve no es un "cheat"), avisar de procesos
/// sin firmar en reglas de comportamiento y comprobar la integridad de los propios binarios de FragGuard.
/// </summary>
public static class Authenticode
{
    private static readonly ConcurrentDictionary<(string Path, long Size, DateTime Written), SignatureInfo> Cache = new();
    private const int MaxCacheEntries = 4000;

    public static SignatureInfo Verify(string path)
    {
        FileInfo fi;
        try
        {
            fi = new FileInfo(path);
            if (!fi.Exists)
                return SignatureInfo.Unsigned;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            return SignatureInfo.Unsigned;
        }

        var key = (fi.FullName.ToUpperInvariant(), fi.Length, fi.LastWriteTimeUtc);
        if (Cache.TryGetValue(key, out var cached))
            return cached;

        var info = VerifyCore(fi.FullName);
        if (Cache.Count >= MaxCacheEntries)
            Cache.Clear(); // caché simple: se vacía entera al llenarse
        Cache[key] = info;
        return info;
    }

    private static SignatureInfo VerifyCore(string path)
    {
        int result = WinVerify(path);
        bool signed = result is not (TRUST_E_NOSIGNATURE or TRUST_E_SUBJECT_FORM_UNKNOWN or TRUST_E_PROVIDER_UNKNOWN);
        if (!signed)
            return SignatureInfo.Unsigned;

        string? publisher = null;
        string? thumbprint = null;
        try
        {
#pragma warning disable SYSLIB0057 // API clásica, la única que extrae el certificado de un archivo firmado
            using var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
#pragma warning restore SYSLIB0057
            publisher = PublisherName(cert);
            thumbprint = cert.Thumbprint;
        }
        catch (System.Security.Cryptography.CryptographicException) { }

        return new SignatureInfo(true, result == 0, publisher, thumbprint);
    }

    /// <summary>Organización (O=) del certificado; si no tiene, el nombre común (CN=).</summary>
    internal static string? PublisherName(X509Certificate2 cert)
    {
        foreach (var part in cert.SubjectName.Decode(X500DistinguishedNameFlags.UseNewLines).Split('\n'))
        {
            string p = part.Trim();
            if (p.StartsWith("O=", StringComparison.OrdinalIgnoreCase))
                return p[2..].Trim().Trim('"');
        }
        return cert.GetNameInfo(X509NameType.SimpleName, false);
    }

    // ---------------- WinVerifyTrust ----------------

    private const int TRUST_E_NOSIGNATURE = unchecked((int)0x800B0100);
    private const int TRUST_E_SUBJECT_FORM_UNKNOWN = unchecked((int)0x800B0003);
    private const int TRUST_E_PROVIDER_UNKNOWN = unchecked((int)0x800B0001);

    private static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
    private const uint WTD_UI_NONE = 2;
    private const uint WTD_REVOKE_NONE = 0;
    private const uint WTD_CHOICE_FILE = 1;
    private const uint WTD_STATEACTION_VERIFY = 1;
    private const uint WTD_STATEACTION_CLOSE = 2;
    private const uint WTD_REVOCATION_CHECK_NONE = 0x00000010;
    private const uint WTD_CACHE_ONLY_URL_RETRIEVAL = 0x00001000;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        public string pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pFile;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [DllImport("wintrust.dll", ExactSpelling = true, CharSet = CharSet.Unicode)]
    private static extern int WinVerifyTrust(IntPtr hwnd, [MarshalAs(UnmanagedType.LPStruct)] Guid pgActionID, ref WINTRUST_DATA pWVTData);

    private static int WinVerify(string path)
    {
        var fileInfo = new WINTRUST_FILE_INFO { cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(), pcwszFilePath = path };
        IntPtr pFile = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());
        try
        {
            Marshal.StructureToPtr(fileInfo, pFile, false);
            var data = new WINTRUST_DATA
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
                dwUIChoice = WTD_UI_NONE,
                fdwRevocationChecks = WTD_REVOKE_NONE,
                dwUnionChoice = WTD_CHOICE_FILE,
                pFile = pFile,
                dwStateAction = WTD_STATEACTION_VERIFY,
                dwProvFlags = WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL
            };
            int result = WinVerifyTrust(IntPtr.Zero, WINTRUST_ACTION_GENERIC_VERIFY_V2, ref data);
            data.dwStateAction = WTD_STATEACTION_CLOSE; // libera el estado interno
            WinVerifyTrust(IntPtr.Zero, WINTRUST_ACTION_GENERIC_VERIFY_V2, ref data);
            return result;
        }
        finally
        {
            Marshal.DestroyStructure<WINTRUST_FILE_INFO>(pFile);
            Marshal.FreeHGlobal(pFile);
        }
    }
}

/// <summary>
/// Editores cuya firma válida RELAJA detecciones dudosas (heurística, PUP, coincidencias YARA de reglas genéricas).
/// Nunca anula una detección de VirusTotal o MalwareBazaar: si un certificado legítimo se roba,
/// esas fuentes externas lo reflejan.
/// </summary>
public static class TrustedPublishers
{
    private static readonly HashSet<string> Names = new(StringComparer.OrdinalIgnoreCase)
    {
        // Plataformas y estudios de juegos
        "Valve", "Valve Corp.", "Valve Corporation", "Riot Games, Inc.", "Epic Games Inc.", "Epic Games, Inc.",
        "Blizzard Entertainment, Inc.", "Electronic Arts, Inc.", "Electronic Arts Inc.", "Electronic Arts",
        "Ubisoft Entertainment Sweden AB", "Ubisoft Entertainment", "Rockstar Games, Inc.", "Take-Two Interactive Software, Inc.",
        "GOG Sp. z o.o.", "CD PROJEKT S.A.", "Mojang AB", "Activision Publishing Inc", "Activision Publishing, Inc.", "Bungie, Inc.",
        "Wargaming Group Limited", "KRAFTON, Inc.", "PUBG Corporation", "Bethesda Softworks LLC", "Square Enix Co., Ltd.",
        "Bandai Namco Entertainment Inc.", "CAPCOM CO., LTD.", "SEGA CORPORATION", "COGNOSPHERE PTE. LTD.", "miHoYo Co.,Ltd.",
        "Battlestate Games Limited", "Grinding Gear Games Limited", "Digital Extremes Ltd.", "Paradox Interactive AB",
        // Anti-cheat
        "Easy Anti-Cheat Oy", "Epic Games Finland Oy", "BattlEye Innovations e.K.", "Riot Games Vanguard",
        // Sistema, hardware y periféricos
        "Microsoft Corporation", "Microsoft Windows", "Microsoft Windows Publisher", "NVIDIA Corporation",
        "Advanced Micro Devices, Inc.", "Advanced Micro Devices INC.", "Intel Corporation", "Realtek Semiconductor Corp.",
        "Logitech Inc", "Logitech Inc.", "Razer USA Ltd.", "Corsair Memory, Inc.", "SteelSeries ApS", "HyperX", "ASUSTeK COMPUTER INC.",
        "MICRO-STAR INTERNATIONAL CO., LTD.", "GIGA-BYTE TECHNOLOGY CO., LTD.",
        // Aplicaciones habituales en un PC gamer
        "Discord Inc.", "Overwolf Ltd", "Overwolf Ltd.", "Google LLC", "Mozilla Corporation", "Opera Norway AS", "Brave Software, Inc.",
        "Spotify AB", "OBS Project", "Elgato Systems GmbH", "Medal B.V.", "Oracle America, Inc.", "Python Software Foundation",
        "GitHub, Inc.", "OpenJS Foundation", "JetBrains s.r.o.", "Docker Inc", "Zoom Video Communications, Inc.",
        "FragGuard"
    };

    public static bool Contains(string publisher) => Names.Contains(publisher.Trim());
}
