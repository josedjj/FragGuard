using System.Text;

namespace FragGuard.Core.Games;

/// <summary>
/// Lector mínimo del formato de texto "KeyValues" de Valve (VDF), el que usan
/// libraryfolders.vdf y appmanifest_*.acf de Steam:
///
///   "AppState" { "appid" "730"  "name" "Counter-Strike 2"  "UserConfig" { ... } }
///
/// Devuelve diccionarios anidados (claves sin distinguir mayúsculas). Tolera comentarios // y
/// secuencias de escape (\\, \", \n). Nunca lanza por un archivo mal formado: devuelve lo que pudo leer.
/// </summary>
public static class VdfParser
{
    public sealed class Node : Dictionary<string, object>
    {
        public Node() : base(StringComparer.OrdinalIgnoreCase) { }

        public string? Str(string key) => TryGetValue(key, out var v) ? v as string : null;
        public Node? Child(string key) => TryGetValue(key, out var v) ? v as Node : null;
        public long? Long(string key) => long.TryParse(Str(key), out long n) ? n : null;
    }

    public static Node Parse(string text)
    {
        int pos = 0;
        var root = new Node();
        try { ParseInto(root, text, ref pos, topLevel: true); }
        catch (FormatException) { /* archivo truncado: devolvemos lo leído */ }
        return root;
    }

    public static Node ParseFile(string path) => Parse(File.ReadAllText(path));

    private static void ParseInto(Node node, string s, ref int pos, bool topLevel)
    {
        while (true)
        {
            SkipWhitespaceAndComments(s, ref pos);
            if (pos >= s.Length)
            {
                if (!topLevel) throw new FormatException("Falta '}'");
                return;
            }
            if (s[pos] == '}')
            {
                pos++;
                return;
            }

            string key = ReadToken(s, ref pos);
            SkipWhitespaceAndComments(s, ref pos);
            if (pos >= s.Length)
                throw new FormatException("Valor ausente");

            if (s[pos] == '{')
            {
                pos++;
                var child = new Node();
                ParseInto(child, s, ref pos, topLevel: false);
                node[key] = child;
            }
            else
            {
                node[key] = ReadToken(s, ref pos);
            }
        }
    }

    private static string ReadToken(string s, ref int pos)
    {
        if (s[pos] != '"')
        {
            // Token sin comillas (poco habitual): hasta el siguiente espacio o llave.
            int start = pos;
            while (pos < s.Length && !char.IsWhiteSpace(s[pos]) && s[pos] is not '{' and not '}')
                pos++;
            return s[start..pos];
        }

        pos++; // comilla de apertura
        var sb = new StringBuilder();
        while (pos < s.Length)
        {
            char c = s[pos++];
            if (c == '"')
                return sb.ToString();
            if (c == '\\' && pos < s.Length)
            {
                char e = s[pos++];
                sb.Append(e switch { 'n' => '\n', 't' => '\t', _ => e });
                continue;
            }
            sb.Append(c);
        }
        throw new FormatException("Cadena sin cerrar");
    }

    private static void SkipWhitespaceAndComments(string s, ref int pos)
    {
        while (pos < s.Length)
        {
            if (char.IsWhiteSpace(s[pos]))
            {
                pos++;
            }
            else if (s[pos] == '/' && pos + 1 < s.Length && s[pos + 1] == '/')
            {
                while (pos < s.Length && s[pos] != '\n') pos++;
            }
            else
            {
                return;
            }
        }
    }
}
