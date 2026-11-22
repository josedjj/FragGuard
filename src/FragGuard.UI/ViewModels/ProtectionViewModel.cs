using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using FragGuard.Shared.Models;
using FragGuard.UI.Infrastructure;
using FragGuard.UI.Views;

namespace FragGuard.UI.ViewModels;

/// <summary>Una tarjeta de módulo de protección (activo / inactivo + detalle).</summary>
public sealed class ProtectionModule
{
    public required string Title { get; init; }
    public required string Detail { get; init; }
    public required bool Active { get; init; }
    public required string Icon { get; init; }
    public string StatusText => Active ? "ACTIVO" : "INACTIVO";
}

/// <summary>Uso de cámara/micrófono preparado para la vista.</summary>
public sealed class DeviceUsageItem
{
    public DeviceUsageItem(DeviceUsageDto dto) => Dto = dto;
    public DeviceUsageDto Dto { get; }
    public string App => Dto.App;
    public string Device => Dto.Device;
    public bool InUse => Dto.InUse;
    public bool IsCamera => Dto.Device == "Cámara";
    public bool IsUntrusted => !Dto.IsTrusted;
    public string WhenText => Dto.InUse ? "En uso ahora" : Dto.LastStartUtc is { } t ? "Usado " + Format.Relative(t) : "—";
    public string PublisherText => Dto.Publisher ?? (Dto.IsStoreApp ? "Microsoft Store" : "Sin firma digital");
}

/// <summary>Página "Protección": módulos en ejecución, cámara y micrófono, y escaneo de memoria.</summary>
public sealed partial class ProtectionViewModel : PageViewModel
{
    private readonly Action<string> _navigate;

    public ProtectionViewModel(ServiceClient client, Action<string> navigate) : base(client) => _navigate = navigate;

    public override string Key => "Protection";

    public ObservableCollection<ProtectionModule> Modules { get; } = new();
    public ObservableCollection<DeviceUsageItem> DeviceUsage { get; } = new();

    [ObservableProperty] private string _integrityText = "";
    [ObservableProperty] private bool _integrityOk = true;
    [ObservableProperty] private bool _noDeviceUsage = true;

    public override async Task RefreshAsync()
    {
        if (!Client.IsConnected)
            return;
        await RunAsync(async () =>
        {
            var s = await Client.GetProtectionStatusAsync();
            var usage = await Client.GetDeviceUsageAsync();
            Apply(s);
            DeviceUsage.Clear();
            foreach (var u in usage.Take(30))
                DeviceUsage.Add(new DeviceUsageItem(u));
            NoDeviceUsage = DeviceUsage.Count == 0;
        }, showErrors: false);
    }

    private void Apply(ProtectionStatusDto s)
    {
        Modules.Clear();
        Modules.Add(new ProtectionModule
        {
            Title = "Monitor de procesos", Icon = "IconRadar", Active = s.ProcessMonitorActive,
            Detail = "Analiza cada programa al arrancar y detiene comportamientos de malware: borrar copias de seguridad, desactivar Defender, PowerShell oculto…"
        });
        Modules.Add(new ProtectionModule
        {
            Title = "Escudo anti-ransomware", Icon = "IconLock", Active = s.RansomwareShieldActive,
            Detail = s.RansomwareShieldActive
                ? $"{s.RansomwareCanaries} archivos señuelo ocultos vigilando Documentos, Imágenes y Escritorio. Si algo intenta cifrarlos, se detiene."
                : "Desactivado en Ajustes."
        });
        Modules.Add(new ProtectionModule
        {
            Title = "Cuentas gamer", Icon = "IconAccount", Active = s.AccountProtectionActive,
            Detail = s.AccountProtectionActive
                ? (s.AccountProtectionTargets.Count > 0
                    ? $"Vigilando quién lee tus sesiones de {string.Join(", ", s.AccountProtectionTargets.Distinct())}."
                    : "Activa, pero no se encontró Discord ni Steam instalados.")
                : s.AccountProtectionError ?? "Desactivado en Ajustes."
        });
        Modules.Add(new ProtectionModule
        {
            Title = "Cámara y micrófono", Icon = "IconWebcam", Active = s.PrivacyMonitorActive,
            Detail = "Avisa si un programa sin firma de confianza empieza a usar tu cámara o tu micrófono."
        });
        Modules.Add(new ProtectionModule
        {
            Title = "Programas de inicio", Icon = "IconPower", Active = s.PersistenceMonitorActive,
            Detail = $"{s.AutorunCount} entradas vigiladas. Avisa de lo nuevo y de las exclusiones añadidas a Windows Defender ({s.DefenderExclusionCount} ahora)."
        });
        Modules.Add(new ProtectionModule
        {
            Title = "Memorias USB", Icon = "IconDisk", Active = s.RemovableDrivesActive,
            Detail = s.RemovableDrives.Count > 0 ? $"Conectadas: {string.Join(", ", s.RemovableDrives)}" : "Se analizan al conectarlas (autorun.inf, ejecutables y comprimidos)."
        });
        IntegrityText = s.SelfIntegrity;
        IntegrityOk = s.SelfIntegrityOk;
    }

    [RelayCommand]
    private async Task ScanMemoryAsync()
    {
        if (!NeonDialog.Confirm("Escanear memoria",
                "Se analizará la memoria de los programas abiertos para encontrar malware que en disco está cifrado.\n\n" +
                "Solo avisa (no cierra nada): en memoria también coinciden programas que simplemente muestran texto sospechoso. " +
                "No se tocan los juegos ni los anti-cheat, y no se permite durante el modo juego. Puede tardar unos minutos.",
                "Escanear", "Cancelar", DialogKind.Info))
            return;
        if (await RunAsync(() => Client.ScanMemoryAsync()))
            _navigate("Scan");
    }

    [RelayCommand]
    private void OpenSettings() => _navigate("Settings");

    [RelayCommand]
    private Task ReloadAsync() => RefreshAsync();
}
