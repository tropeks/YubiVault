using System.Globalization;
using YubiVault.App.Resources;

namespace YubiVault.App;

/// <summary>The app's languages. Texts live in Resources/Strings*.resx; English is the fallback.</summary>
static class Localization
{
    /// <summary>Culture names with their names in their own language. "" follows the system.</summary>
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

    public static void Apply(string? code)
    {
        CultureInfo culture;
        try
        {
            culture = string.IsNullOrEmpty(code) ? CultureInfo.InstalledUICulture : CultureInfo.GetCultureInfo(code);
        }
        catch (CultureNotFoundException)
        {
            culture = CultureInfo.InvariantCulture;
        }
        CultureInfo.CurrentUICulture = CultureInfo.DefaultThreadCurrentUICulture = culture;
        CultureInfo.CurrentCulture = CultureInfo.DefaultThreadCurrentCulture = culture;
        Strings.Culture = culture;
    }

    public static bool IsRightToLeft => CultureInfo.CurrentUICulture.TextInfo.IsRightToLeft;

    public static string Format(string format, params object?[] args) => string.Format(CultureInfo.CurrentCulture, format, args);
}
