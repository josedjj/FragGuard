namespace FragGuard.Shared;

/// <summary>
/// Constantes globales del producto compartidas por el servicio y la interfaz.
/// </summary>
public static class AppInfo
{
    public const string ProductName = "FragGuard";
    public const string Version = "0.1.0";

    /// <summary>Nombre interno del servicio de Windows (sc.exe / services.msc).</summary>
    public const string ServiceName = "FragGuardService";
    public const string ServiceDisplayName = "FragGuard Protection Service";

    /// <summary>Nombre del named pipe (\\.\pipe\FragGuard.v1). Se versiona para no romper clientes antiguos.</summary>
    public const string PipeName = "FragGuard.v1";

    /// <summary>
    /// Carpeta raíz de datos: %ProgramData%\FragGuard. El servicio la protege con ACL (SYSTEM + Administradores).
    /// </summary>
    public static string DefaultDataRoot =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), ProductName);
}
