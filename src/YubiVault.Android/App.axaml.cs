using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using YubiVault.Android.Platform;

namespace YubiVault.Android;

public partial class App : Application
{
    public override void Initialize() => AvaloniaXamlLoader.Load(this);

    public override void OnFrameworkInitializationCompleted()
    {
        Views.ThemeSetting.Apply();
        Views.LanguageSetting.Apply();
        if (ApplicationLifetime is ISingleViewApplicationLifetime singleView)
            singleView.MainView = new Views.MainView(AndroidPlatform.Current);
        base.OnFrameworkInitializationCompleted();
    }
}
