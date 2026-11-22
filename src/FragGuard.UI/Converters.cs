using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;
using FragGuard.Shared.Models;
using FragGuard.UI.ViewModels;

namespace FragGuard.UI;

/// <summary>bool → Visibility. ConverterParameter="invert" para invertir.</summary>
public sealed class BoolToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        bool v = value is bool b && b;
        if (parameter is string s && s == "invert") v = !v;
        return v ? Visibility.Visible : Visibility.Collapsed;
    }
    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotSupportedException();
}

/// <summary>!bool (para IsEnabled = !IsScanning, etc.).</summary>
public sealed class InverseBoolConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) => !(value is bool b && b);
    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => !(value is bool b && b);
}

/// <summary>null/vacío → Collapsed. ConverterParameter="invert" para invertir.</summary>
public sealed class NullToVisibilityConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object parameter, CultureInfo culture)
    {
        bool hasValue = value is not null && !(value is string s && string.IsNullOrEmpty(s)) && !(value is int i && i == 0);
        if (parameter is string p && p == "invert") hasValue = !hasValue;
        return hasValue ? Visibility.Visible : Visibility.Collapsed;
    }
    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotSupportedException();
}

/// <summary>Compara con ConverterParameter (para marcar la página activa en la navegación).</summary>
public sealed class EqualsConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object parameter, CultureInfo culture) => Equals(value?.ToString(), parameter?.ToString());
    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => Binding.DoNothing;
}

/// <summary>Ruta completa → solo el nombre del archivo.</summary>
public sealed class FileNameConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object parameter, CultureInfo culture) =>
        value is string s ? System.IO.Path.GetFileName(s.Split(" > ")[^1]) : "";
    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotSupportedException();
}

/// <summary>Fecha UTC → fecha/hora local legible.</summary>
public sealed class LocalTimeConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object parameter, CultureInfo culture) =>
        value is DateTime d ? Format.LocalDateTime(d) : "—";
    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotSupportedException();
}

/// <summary>Bytes → "12,3 MB".</summary>
public sealed class BytesConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object parameter, CultureInfo culture) =>
        value is long l ? Format.Bytes(l) : "";
    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotSupportedException();
}

/// <summary>Enums del modelo → texto en español.</summary>
public sealed class EnumTextConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object parameter, CultureInfo culture) => value switch
    {
        ScanKind k => Format.ScanKind(k),
        ScanState s => Format.ScanState(s),
        FileVerdict v => Format.Verdict(v),
        ThreatAction a => Format.Action(a),
        _ => value?.ToString() ?? ""
    };
    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotSupportedException();
}

/// <summary>Veredicto / estado → pincel de color (rojo malicioso, ámbar sospechoso...).</summary>
public sealed class SeverityBrushConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object parameter, CultureInfo culture)
    {
        string key = value switch
        {
            FileVerdict.Malicious => "DangerBrush",
            FileVerdict.Suspicious => "WarnBrush",
            FileVerdict.Clean => "OkBrush",
            ThreatAction.Quarantined or ThreatAction.QuarantinePendingReboot => "OkBrush",
            ThreatAction.QuarantineFailed => "DangerBrush",
            ThreatAction.Warned => "WarnBrush",
            ScanState.Completed => "OkBrush",
            ScanState.Failed => "DangerBrush",
            ScanState.Cancelled => "WarnBrush",
            AlertKind.Threat => "DangerBrush",
            AlertKind.Suspicious or AlertKind.Cheat => "WarnBrush",
            _ => "AccentBrush"
        };
        return Application.Current.FindResource(key) as Brush ?? Brushes.White;
    }
    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotSupportedException();
}

/// <summary>Formatos de texto reutilizables.</summary>
public static class Format
{
    private static readonly CultureInfo Es = CultureInfo.GetCultureInfo("es-ES");

    public static string LocalDateTime(DateTime utc) =>
        DateTime.SpecifyKind(utc, DateTimeKind.Utc).ToLocalTime().ToString("dd/MM/yyyy HH:mm", Es);

    public static string Relative(DateTime utc)
    {
        var span = DateTime.UtcNow - DateTime.SpecifyKind(utc, DateTimeKind.Utc);
        if (span.TotalMinutes < 1) return "hace un momento";
        if (span.TotalMinutes < 60) return $"hace {(int)span.TotalMinutes} min";
        if (span.TotalHours < 24) return $"hace {(int)span.TotalHours} h";
        if (span.TotalDays < 2) return "ayer";
        return $"hace {(int)span.TotalDays} días";
    }

    public static string Bytes(long bytes) => bytes switch
    {
        < 1024 => $"{bytes} B",
        < 1024 * 1024 => (bytes / 1024.0).ToString("0.#", Es) + " KB",
        < 1024L * 1024 * 1024 => (bytes / 1024.0 / 1024.0).ToString("0.#", Es) + " MB",
        _ => (bytes / 1024.0 / 1024.0 / 1024.0).ToString("0.##", Es) + " GB"
    };

    public static string Duration(long ms)
    {
        var t = TimeSpan.FromMilliseconds(ms);
        return t.TotalHours >= 1 ? t.ToString(@"h\:mm\:ss") : t.ToString(@"mm\:ss");
    }

    public static string Number(long n) => n.ToString("N0", Es);

    public static string ScanKind(ScanKind k) => k switch
    {
        Shared.Models.ScanKind.Quick => "Rápido",
        Shared.Models.ScanKind.Full => "Completo",
        Shared.Models.ScanKind.Custom => "Personalizado",
        Shared.Models.ScanKind.Realtime => "Tiempo real",
        Shared.Models.ScanKind.Scheduled => "Programado",
        _ => k.ToString()
    };

    public static string ScanState(ScanState s) => s switch
    {
        Shared.Models.ScanState.Running => "En curso",
        Shared.Models.ScanState.Paused => "En pausa",
        Shared.Models.ScanState.Completed => "Completado",
        Shared.Models.ScanState.Cancelled => "Cancelado",
        Shared.Models.ScanState.Failed => "Interrumpido",
        _ => "Inactivo"
    };

    public static string Verdict(FileVerdict v) => v switch
    {
        FileVerdict.Malicious => "Malicioso",
        FileVerdict.Suspicious => "Sospechoso",
        FileVerdict.Clean => "Limpio",
        FileVerdict.Skipped => "Omitido",
        _ => "Error"
    };

    public static string Action(ThreatAction a) => a switch
    {
        ThreatAction.Quarantined => "En cuarentena",
        ThreatAction.QuarantinePendingReboot => "Cuarentena (al reiniciar)",
        ThreatAction.QuarantineFailed => "No se pudo aislar",
        ThreatAction.Warned => "Aviso",
        _ => "Ninguna"
    };
}
