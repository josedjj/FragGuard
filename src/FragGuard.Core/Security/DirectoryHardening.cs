using System.Security.AccessControl;
using System.Security.Principal;

namespace FragGuard.Core.Security;

/// <summary>
/// Restringe una carpeta para que solo SYSTEM y Administradores tengan acceso.
/// Se aplica a %ProgramData%\FragGuard (base de datos, claves y cuarentena).
/// </summary>
public static class DirectoryHardening
{
    public static void RestrictToSystemAndAdmins(string directory)
    {
        var info = new DirectoryInfo(directory);
        var security = new DirectorySecurity();

        // Cortamos la herencia y descartamos las reglas heredadas (p. ej. "Usuarios: lectura" de ProgramData).
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        const InheritanceFlags inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;

        security.AddAccessRule(new FileSystemAccessRule(system, FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(admins, FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
        security.SetOwner(admins);

        info.SetAccessControl(security);
    }
}
