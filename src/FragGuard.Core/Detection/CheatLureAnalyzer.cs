using System.Text.RegularExpressions;
using FragGuard.Shared.Models;

namespace FragGuard.Core.Detection;

/// <summary>
/// Heurística por NOMBRE de archivo/proceso para cebos típicos dirigidos a gamers:
/// cheats, aimbots, trainers, inyectores, spoofers, "free skins / V-Bucks / Robux"...
///
/// Es un aviso, no una detección de malware: muchos de estos archivos son malware disfrazado
/// (infostealers que roban la cuenta de Discord/Steam), y además pueden provocar baneos del anti-cheat.
/// </summary>
public static partial class CheatLureAnalyzer
{
    /// <summary>
    /// Extensiones en las que tiene sentido avisar: lo que se descarga y se ejecuta (o se inyecta) como "cheat".
    /// NO incluimos .js/.vbs/.jar: en la primera instalación real, librerías de node_modules como
    /// "import-injector.js" o "no-async-promise-executor.js" generaban falsos positivos.
    /// </summary>
    private static readonly HashSet<string> RelevantExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".scr", ".com", ".bat", ".cmd", ".msi", ".dll", ".zip", ".rar", ".7z"
    };

    /// <summary>Carpetas de dependencias de desarrollo: su código no son "cheats" descargados por el usuario.</summary>
    private static readonly string[] IgnoredPathSegments =
    {
        @"\node_modules\", @"\site-packages\", @"\.nuget\packages\", @"\vendor\bundle\", @"\.cargo\registry\"
    };

    // Términos fuertes: por sí solos justifican el aviso.
    [GeneratedRegex(
        @"(aim[\s._-]?bot|wall[\s._-]?hack|trigger[\s._-]?bot|no[\s._-]?recoil|esp[\s._-]?hack|" +
        // Nota: NO incluimos "loader" ni "mod" a secas: los mod loaders legítimos (BepInEx, Fabric, Forge) son habituales.
        @"cheat|hack(?!athon)|trainer|injector|spoofer|hwid[\s._-]?(spoof|changer)|unlock[\s._-]?all|" +
        @"skin[\s._-]?changer|mod[\s._-]?menu|executor|bypass|crack(ed)?|keygen)",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex StrongTermsRegex();

    // Cebos "gratis": free skins, free vbucks, robux gratis, etc.
    [GeneratedRegex(
        @"(free[\s._-]?(skins?|v[\s._-]?bucks|robux|rp|vp|nitro|coins|gems|items|steam[\s._-]?(keys?|games?))|" +
        @"(skins?|v[\s._-]?bucks|robux|nitro)[\s._-]?(gratis|free|generator|gen)|" +
        @"(robux|vbucks|nitro)[\s._-]?generator)",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex FreebieRegex();

    /// <summary>
    /// Analiza un nombre de archivo o de proceso. Devuelve null si no parece un cebo.
    /// </summary>
    public static ThreatInfo? Analyze(string fileNameOrPath)
    {
        string name = Path.GetFileName(fileNameOrPath);
        if (string.IsNullOrEmpty(name))
            return null;

        string ext = Path.GetExtension(name);
        if (!RelevantExtensions.Contains(ext))
            return null;

        foreach (var segment in IgnoredPathSegments)
        {
            if (fileNameOrPath.Contains(segment, StringComparison.OrdinalIgnoreCase))
                return null;
        }

        string stem = Path.GetFileNameWithoutExtension(name);

        var freebie = FreebieRegex().Match(stem);
        if (freebie.Success)
        {
            return new ThreatInfo
            {
                Name = "FG.Heur.FreebieLure",
                Category = "CheatLure",
                Severity = ThreatSeverity.Medium,
                Source = DetectionSource.Heuristic,
                Description = $"El nombre promete regalos gratis (\"{freebie.Value}\"). Es un cebo clásico para robar cuentas de Discord/Steam."
            };
        }

        var strong = StrongTermsRegex().Match(stem);
        if (strong.Success)
        {
            return new ThreatInfo
            {
                Name = "FG.Heur.CheatTool",
                Category = "CheatLure",
                Severity = ThreatSeverity.Low,
                Source = DetectionSource.Heuristic,
                Description = $"El nombre parece de un cheat/trainer/inyector (\"{strong.Value}\"). Suelen ser malware disfrazado y pueden provocar baneos del anti-cheat."
            };
        }

        return null;
    }
}
