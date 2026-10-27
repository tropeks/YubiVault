using Avalonia.Platform.Storage;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using Avalonia.Threading;
using YubiVault.Core;

namespace YubiVault.App;

public partial class App : Application
{
    public override void Initialize() => AvaloniaXamlLoader.Load(this);

    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            var settings = AppSettings.Load();
            Localization.Apply(settings.Language);
            // A vault passed on the command line (e.g. a double-clicked .yvault file) is selected right away.
            string? vault = desktop.Args?.FirstOrDefault(Vault.Exists);
            var window = new MainWindow(settings, vault);
            desktop.MainWindow = window;

            // macOS hands double-clicked files to the running app instead of the command line.
            if (TryGetFeature(typeof(IActivatableLifetime)) is IActivatableLifetime activatable)
            {
                activatable.Activated += (_, e) =>
                {
                    if (e is FileActivatedEventArgs files &&
                        files.Files.Select(f => f.TryGetLocalPath()).FirstOrDefault(p => p is not null && Vault.Exists(p)) is { } path)
                        window.OpenFromSystem(path);
                };
            }
            Dispatcher.UIThread.UnhandledException += (_, e) =>
            {
                e.Handled = true;
                _ = Dialogs.AlertAsync(window, YubiVault.App.Resources.Strings.UnexpectedError, e.Exception.Message);
            };
        }
        base.OnFrameworkInitializationCompleted();
    }
}
