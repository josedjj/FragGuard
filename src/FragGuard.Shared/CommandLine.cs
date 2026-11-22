namespace FragGuard.Shared;

/// <summary>
/// Separa una línea de comandos de Windows (como las UninstallString del registro) en ejecutable + argumentos.
/// Soporta rutas entre comillas y rutas SIN comillas que contienen espacios
/// (p. ej. C:\Program Files\Juego\unins000.exe /SILENT), muy habituales en el registro.
/// </summary>
public static class CommandLine
{
    public readonly record struct Parsed(string FileName, string Arguments);

    public static Parsed Split(string commandLine)
    {
        string s = commandLine.Trim();
        if (s.Length == 0)
            return new Parsed("", "");

        if (s[0] == '"')
        {
            int end = s.IndexOf('"', 1);
            if (end > 0)
                return new Parsed(s[1..end], s[(end + 1)..].Trim());
            return new Parsed(s.Trim('"'), "");
        }

        // Sin comillas: el ejecutable termina en la primera ".exe" seguida de espacio o fin de cadena.
        int exe = s.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
        while (exe >= 0)
        {
            int after = exe + 4;
            if (after == s.Length || char.IsWhiteSpace(s[after]))
                return new Parsed(s[..after], s[after..].Trim());
            exe = s.IndexOf(".exe", after, StringComparison.OrdinalIgnoreCase);
        }

        // Sin ".exe": primer token separado por espacio (p. ej. "MsiExec /X{GUID}").
        int space = s.IndexOf(' ');
        return space < 0 ? new Parsed(s, "") : new Parsed(s[..space], s[(space + 1)..].Trim());
    }

    /// <summary>True si es una URI de protocolo (steam://, uplay://...), que se abre con el shell.</summary>
    public static bool IsUri(string target) =>
        target.Contains("://", StringComparison.Ordinal) && !target.StartsWith('"') && !Path.IsPathRooted(target);
}
