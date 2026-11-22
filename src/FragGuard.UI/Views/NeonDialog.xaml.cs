using System.Windows;
using System.Windows.Media;

namespace FragGuard.UI.Views;

public enum DialogKind { Info, Warning, Danger }

/// <summary>Diálogo modal con el estilo de FragGuard.</summary>
public partial class NeonDialog : Window
{
    private NeonDialog(string title, string message, string okText, string? cancelText, DialogKind kind)
    {
        InitializeComponent();
        TitleText.Text = title;
        MessageText.Text = message;
        OkButton.Content = okText;

        if (cancelText is null)
            CancelButton.Visibility = Visibility.Collapsed;
        else
            CancelButton.Content = cancelText;

        (string icon, string brush) = kind switch
        {
            DialogKind.Warning => ("IconAlert", "WarnBrush"),
            DialogKind.Danger => ("IconAlert", "DangerBrush"),
            _ => ("IconShield", "AccentBrush")
        };
        IconPath.Data = (Geometry)FindResource(icon);
        IconPath.Fill = (Brush)FindResource(brush);

        // Solo usamos como "dueño" la ventana principal si está visible (si la UI está en la bandeja no hay).
        var main = Application.Current.MainWindow;
        if (main is { IsVisible: true } && !ReferenceEquals(main, this))
            Owner = main;
        else
            WindowStartupLocation = WindowStartupLocation.CenterScreen;
    }

    private void Ok_Click(object sender, RoutedEventArgs e) => DialogResult = true;
    private void Cancel_Click(object sender, RoutedEventArgs e) => DialogResult = false;

    public static bool Confirm(string title, string message, string okText = "Aceptar", string cancelText = "Cancelar", DialogKind kind = DialogKind.Warning) =>
        new NeonDialog(title, message, okText, cancelText, kind).ShowDialog() == true;

    public static void Show(string title, string message, DialogKind kind = DialogKind.Info) =>
        new NeonDialog(title, message, "Entendido", null, kind).ShowDialog();
}
