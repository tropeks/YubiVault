using System.Globalization;

namespace YubiVault.Android.Views;

/// <summary>The app's language: the phone's unless the user picks one on the start page. Kept in a small file.</summary>
static class LanguageSetting
{
    /// <summary>Culture names with their names in their own language, as on the desktop.</summary>
    public static readonly IReadOnlyList<(string Code, string Name)> Languages =
    [
        ("en", "English"),
        ("zh-Hans", "中文（简体）"),
        ("zh-Hant", "中文（繁體）"),
        ("hi", "हिन्दी"),
        ("es", "Español"),
        ("fr", "Français"),
        ("ar", "العربية"),
        ("bn", "বাংলা"),
        ("pt", "Português"),
        ("ru", "Русский"),
        ("ja", "日本語"),
    ];

    // The phone's language, captured before the app overrides it.
    static readonly CultureInfo PhoneCulture = CultureInfo.CurrentUICulture;

    static string FilePath => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "language");

    /// <summary>The chosen culture name, or "" to follow the phone.</summary>
    public static string Current
    {
        get
        {
            try
            {
                string code = File.Exists(FilePath) ? File.ReadAllText(FilePath).Trim() : "";
                return Languages.Any(l => l.Code == code) ? code : "";
            }
            catch (IOException)
            {
                return "";
            }
        }
    }

    public static void Apply() => Apply(Current);

    public static void Set(string code)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
            File.WriteAllText(FilePath, code);
        }
        catch (IOException)
        {
            // The choice still applies until the app closes.
        }
        Apply(code);
    }

    static void Apply(string code)
    {
        var culture = code.Length == 0 ? PhoneCulture : CultureInfo.GetCultureInfo(code);
        CultureInfo.CurrentUICulture = CultureInfo.DefaultThreadCurrentUICulture = culture;
        CultureInfo.CurrentCulture = CultureInfo.DefaultThreadCurrentCulture = culture;
    }
}
