using System.Windows;
using System.Windows.Media;
using System.Windows.Threading;
using Wpf.Ui.Appearance;

namespace YubiVault.App;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        DispatcherUnhandledException += OnUnhandledException;
        base.OnStartup(e);
        // Our own blue-teal accent, matching the icon, instead of the Windows accent color.
        ApplicationAccentColorManager.Apply(BrandAccent, ApplicationTheme.Dark);
    }

    static readonly Color BrandAccent = Color.FromRgb(0x17, 0x8E, 0xC0);

    static void OnUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        MessageBox.Show(e.Exception.Message, "YubiVault", MessageBoxButton.OK, MessageBoxImage.Error);
        e.Handled = true;
    }
}
