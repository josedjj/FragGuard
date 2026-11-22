using System.Windows;
using FragGuard.UI.ViewModels;

namespace FragGuard.UI;

public partial class MainWindow : Window
{
    public MainWindow(MainViewModel viewModel)
    {
        InitializeComponent();
        DataContext = viewModel;
    }

    private void Minimize_Click(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;

    // Cerrar solo destruye la ventana: la app sigue en la bandeja y el servicio sigue protegiendo.
    private void Close_Click(object sender, RoutedEventArgs e) => Close();

    // Con WindowChrome, una ventana maximizada se sale unos píxeles de la pantalla: lo compensamos.
    private void Window_StateChanged(object? sender, EventArgs e) =>
        RootBorder.Margin = WindowState == WindowState.Maximized ? new Thickness(7) : new Thickness(0);
}
