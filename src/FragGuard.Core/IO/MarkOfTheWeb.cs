namespace FragGuard.Core.IO;

/// <summary>Origen de un archivo descargado según Mark-of-the-Web.</summary>
public sealed record WebOrigin(int ZoneId, string? HostUrl, string? ReferrerUrl)
{
    /// <summary>Zona 3 = Internet, 4 = sitios restringidos.</summary>
    public bool IsFromInternet => ZoneId >= 3;

    /// <summary>Host de la descarga (p. ej. "cdn.discordapp.com"), o null.</summary>
    public string? Host => Uri.TryCreate(HostUrl, UriKind.Absolute, out var u) ? u.Host : null;
}

/// <summary>
/// Lectura de Mark-of-the-Web: el flujo NTFS alternativo "archivo:Zone.Identifier" que navegadores,
/// Discord y clientes de correo añaden a lo que descargan. Dice DE DÓNDE vino el archivo:
///
///   [ZoneTransfer]
///   ZoneId=3
///   ReferrerUrl=https://ejemplo.com/pagina
///   HostUrl=https://cdn.ejemplo.com/archivo.exe
///
/// Coste casi nulo (una lectura de pocos bytes) y muy útil: permite consultar la URL en URLhaus y decirle
/// al usuario de dónde salió la amenaza.
/// </summary>
public static class MarkOfTheWeb
{
    public static WebOrigin? Read(string path)
    {
        string text;
        try
        {
            using var fs = new FileStream(path + ":Zone.Identifier", FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            if (fs.Length > 16 * 1024)
                return null; // un Zone.Identifier legítimo ocupa unos pocos cientos de bytes
            using var reader = new StreamReader(fs);
            text = reader.ReadToEnd();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException or ArgumentException)
        {
            return null; // sin MOTW (archivo local, FAT32/exFAT, o se eliminó)
        }
        return Parse(text);
    }

    internal static WebOrigin? Parse(string text)
    {
        int zone = -1;
        string? host = null, referrer = null;
        foreach (var raw in text.Split('\n'))
        {
            string line = raw.Trim();
            int eq = line.IndexOf('=');
            if (eq <= 0)
                continue;
            string key = line[..eq].Trim();
            string value = line[(eq + 1)..].Trim();
            if (key.Equals("ZoneId", StringComparison.OrdinalIgnoreCase) && int.TryParse(value, out int z))
                zone = z;
            else if (key.Equals("HostUrl", StringComparison.OrdinalIgnoreCase))
                host = Sanitize(value);
            else if (key.Equals("ReferrerUrl", StringComparison.OrdinalIgnoreCase))
                referrer = Sanitize(value);
        }
        return zone < 0 ? null : new WebOrigin(zone, host, referrer);
    }

    // Solo URLs http(s) razonables: el contenido del flujo lo puede escribir cualquiera.
    private static string? Sanitize(string value) =>
        value.Length is > 0 and < 2048 && Uri.TryCreate(value, UriKind.Absolute, out var u) && (u.Scheme == Uri.UriSchemeHttp || u.Scheme == Uri.UriSchemeHttps)
            ? value
            : null;
}
