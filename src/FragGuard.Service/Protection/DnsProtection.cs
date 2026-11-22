using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text.Json;
using FragGuard.Core.Configuration;
using FragGuard.Shared.Ipc;

namespace FragGuard.Service.Protection;

/// <summary>
/// "DNS protegido" opcional: configura los adaptadores de red activos para usar Quad9 (9.9.9.9 / 149.112.112.112),
/// un resolvedor DNS sin ánimo de lucro que bloquea dominios de malware y phishing. En Windows 11 además
/// registra DNS cifrado (DoH) para Quad9.
///
/// Seguro de revertir: antes de cambiar nada guarda la configuración DNS de cada adaptador en
/// %ProgramData%\FragGuard\dns-backup.json, y al desactivarlo la restaura exactamente (o vuelve a DHCP).
/// No toca adaptadores virtuales, de VPN ni de bucle invertido. Solo lo puede cambiar un administrador.
/// </summary>
public sealed class DnsProtection
{
    private static readonly string[] Quad9 = { "9.9.9.9", "149.112.112.112" };
    private const string Quad9Doh = "https://dns.quad9.net/dns-query";

    private readonly FragGuardPaths _paths;
    private readonly ILogger<DnsProtection> _logger;

    public DnsProtection(FragGuardPaths paths, ILogger<DnsProtection> logger)
    {
        _paths = paths;
        _logger = logger;
    }

    private string BackupPath => Path.Combine(_paths.DataRoot, "dns-backup.json");

    private sealed record AdapterDns(int Index, string Name, List<string> Servers);

    /// <summary>Adaptadores físicos activos con puerta de enlace IPv4 (Ethernet y Wi-Fi reales).</summary>
    private static List<AdapterDns> ActiveAdapters() =>
        NetworkInterface.GetAllNetworkInterfaces()
            .Where(n => n.OperationalStatus == OperationalStatus.Up &&
                        n.NetworkInterfaceType is NetworkInterfaceType.Ethernet or NetworkInterfaceType.Wireless80211 or NetworkInterfaceType.GigabitEthernet &&
                        !n.Description.Contains("Virtual", StringComparison.OrdinalIgnoreCase) &&
                        !n.Description.Contains("VPN", StringComparison.OrdinalIgnoreCase) &&
                        !n.Description.Contains("Hyper-V", StringComparison.OrdinalIgnoreCase) &&
                        !n.Description.Contains("TAP-", StringComparison.OrdinalIgnoreCase) &&
                        n.GetIPProperties().GatewayAddresses.Any(g => g.Address.AddressFamily == AddressFamily.InterNetwork))
            .Select(n => new AdapterDns(
                n.GetIPProperties().GetIPv4Properties()?.Index ?? -1,
                n.Name,
                n.GetIPProperties().DnsAddresses.Where(a => a.AddressFamily == AddressFamily.InterNetwork).Select(a => a.ToString()).ToList()))
            .Where(a => a.Index >= 0)
            .ToList();

    public OperationResult Status()
    {
        var adapters = ActiveAdapters();
        if (adapters.Count == 0)
            return new OperationResult { Success = false, Message = "No hay adaptadores de red activos." };
        bool all = adapters.All(a => a.Servers.Count > 0 && a.Servers.All(s => Quad9.Contains(s)));
        string detail = string.Join(" · ", adapters.Select(a => $"{a.Name}: {(a.Servers.Count == 0 ? "automático" : string.Join(", ", a.Servers))}"));
        return new OperationResult { Success = all && File.Exists(BackupPath), Message = detail };
    }

    public OperationResult Enable()
    {
        var adapters = ActiveAdapters();
        if (adapters.Count == 0)
            return OperationResult.Fail("No hay adaptadores de red activos que configurar.");

        // Copia de seguridad (solo la primera vez: si ya existe, es la configuración ORIGINAL a restaurar).
        if (!File.Exists(BackupPath))
            File.WriteAllText(BackupPath, JsonSerializer.Serialize(adapters));

        var script = new List<string>();
        foreach (var a in adapters)
            script.Add($"Set-DnsClientServerAddress -InterfaceIndex {a.Index} -ServerAddresses ('{Quad9[0]}','{Quad9[1]}')");
        // DNS cifrado (DoH): disponible en Windows 11; en Windows 10 se ignora el error.
        foreach (var ip in Quad9)
            script.Add($"try {{ Add-DnsClientDohServerAddress -ServerAddress {ip} -DohTemplate '{Quad9Doh}' -AllowFallbackToUdp $true -AutoUpgrade $true -ErrorAction Stop }} catch {{ }}");
        script.Add("Clear-DnsClientCache");

        if (!RunPowerShell(string.Join("; ", script), out string error))
            return OperationResult.Fail("No se pudo cambiar el DNS: " + error);

        _logger.LogWarning("DNS protegido ACTIVADO (Quad9) en {Count} adaptador(es)", adapters.Count);
        return OperationResult.Ok("DNS protegido activado (Quad9).");
    }

    public OperationResult Disable()
    {
        if (!File.Exists(BackupPath))
            return OperationResult.Fail("No hay copia de la configuración anterior.");
        var backup = JsonSerializer.Deserialize<List<AdapterDns>>(File.ReadAllText(BackupPath)) ?? new();

        var script = backup.Select(a => a.Servers.Count == 0
            ? $"Set-DnsClientServerAddress -InterfaceIndex {a.Index} -ResetServerAddresses"
            : $"Set-DnsClientServerAddress -InterfaceIndex {a.Index} -ServerAddresses ({string.Join(",", a.Servers.Select(s => $"'{IPAddress.Parse(s)}'"))})").ToList();
        script.Add("Clear-DnsClientCache");

        if (!RunPowerShell(string.Join("; ", script), out string error))
            return OperationResult.Fail("No se pudo restaurar el DNS: " + error);

        File.Delete(BackupPath);
        _logger.LogWarning("DNS protegido desactivado: configuración original restaurada");
        return OperationResult.Ok("DNS restaurado a tu configuración anterior.");
    }

    private static bool RunPowerShell(string command, out string error)
    {
        error = "";
        try
        {
            using var p = Process.Start(new ProcessStartInfo("powershell.exe", $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"{command.Replace("\"", "\\\"")}\"")
            { CreateNoWindow = true, UseShellExecute = false, RedirectStandardError = true, RedirectStandardOutput = true });
            if (p is null) { error = "no se pudo iniciar PowerShell"; return false; }
            error = p.StandardError.ReadToEnd();
            p.WaitForExit(60000);
            return p.ExitCode == 0 && string.IsNullOrWhiteSpace(error);
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            error = ex.Message;
            return false;
        }
    }
}
