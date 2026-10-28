using Avalonia;
using Avalonia.Styling;

namespace YubiVault.Android.Views;

/// <summary>The app's light/dark choice: dark unless the user picks light or the phone's setting. Kept in a small file.</summary>
static class ThemeSetting
{
    public const string Dark = "dark", Light = "light", System = "system";

    static string FilePath => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "theme");

    public static string Current
    {
        get
        {
            try
            {
                string value = File.Exists(FilePath) ? File.ReadAllText(FilePath).Trim() : Dark;
                return value is Light or System ? value : Dark;
            }
            catch (IOException)
            {
                return Dark;
            }
        }
    }

    public static void Apply() => Apply(Current);

    public static void Set(string theme)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
            File.WriteAllText(FilePath, theme);
        }
        catch (IOException)
        {
            // The choice still applies until the app closes.
        }
        Apply(theme);
    }

    static void Apply(string theme)
    {
        if (Application.Current is { } app)
            app.RequestedThemeVariant = theme switch
            {
                Light => ThemeVariant.Light,
                System => ThemeVariant.Default,
                _ => ThemeVariant.Dark,
            };
    }
}
