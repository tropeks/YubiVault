using Avalonia;
using Avalonia.Media;

namespace YubiVault.App;

static class Program
{
    [STAThread]
    public static void Main(string[] args) => BuildAvaloniaApp().StartWithClassicDesktopLifetime(args);

    public static AppBuilder BuildAvaloniaApp() =>
        AppBuilder.Configure<App>().UsePlatformDetect().WithInterFont().With(FontOptions()).LogToTrace();

    /// <summary>
    /// Each system's own UI font: Segoe UI Variable on Windows 11, San Francisco on macOS (Avalonia's default
    /// there), and Inter, shipped inside the app, on Linux where the installed fonts vary.
    /// </summary>
    static FontManagerOptions FontOptions() => new()
    {
        DefaultFamilyName = OperatingSystem.IsWindowsVersionAtLeast(10, 0, 22000) ? "Segoe UI Variable Text"
            : OperatingSystem.IsLinux() ? "fonts:Inter#Inter"
            : null,
    };
}
