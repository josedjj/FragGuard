using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using FragGuard.UI.ViewModels;

namespace FragGuard.UI.Views;

public partial class SettingsView : UserControl
{
    private bool _userScrolled;

    public SettingsView()
    {
        InitializeComponent();
        DataContextChanged += OnDataContextChanged;

        // Al cargar la configuración, los TextBox multilínea (listas de juegos) hacen saltar el ScrollViewer
        // hacia abajo y la página aparecía sin su título. Mantenemos la página arriba hasta que el usuario
        // interactúe con ella (rueda, teclado o clic).
        Loaded += (_, _) => { _userScrolled = false; Scroller.ScrollToTop(); };
        Scroller.PreviewMouseWheel += (_, _) => _userScrolled = true;
        Scroller.PreviewMouseDown += (_, _) => _userScrolled = true;
        Scroller.PreviewKeyDown += (_, _) => _userScrolled = true;
        Scroller.ScrollChanged += (_, e) =>
        {
            if (!_userScrolled && e.VerticalChange > 0)
                Scroller.ScrollToTop();
        };
    }

    private SettingsViewModel? Vm => DataContext as SettingsViewModel;

    // PasswordBox.Password no admite binding (para que la clave no quede en memoria en un DependencyProperty):
    // la pasamos a mano al ViewModel.
    private void VtKeyBox_PasswordChanged(object sender, RoutedEventArgs e)
    {
        if (Vm is { } vm)
            vm.VirusTotalKeyInput = VtKeyBox.Password;
    }

    private void OnDataContextChanged(object sender, DependencyPropertyChangedEventArgs e)
    {
        if (e.OldValue is SettingsViewModel old)
            old.PropertyChanged -= OnVmPropertyChanged;
        if (e.NewValue is SettingsViewModel vm)
            vm.PropertyChanged += OnVmPropertyChanged;
    }

    // Tras guardar (o borrar) la clave, vaciamos el campo.
    private void OnVmPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(SettingsViewModel.HasVirusTotalKey))
        {
            VtKeyBox.Clear();
            if (Vm is { } vm) vm.VirusTotalKeyInput = "";
        }
    }
}
