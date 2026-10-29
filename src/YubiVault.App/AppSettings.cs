using System.IO;
using System.Text.Json;

namespace YubiVault.App;

/// <summary>
/// Settings kept in a JSON file next to the executable, never in the registry, so the app stays portable.
/// When that folder is not writable (a macOS app bundle, a Linux AppImage, read-only media) they go to
/// the user's application data folder instead.
/// </summary>
public sealed class AppSettings
{
    const int MaxRecentVaults = 8;
    const string FileName = "yubivault.settings.json";
    static readonly string PortablePath = Path.Combine(AppContext.BaseDirectory, FileName);
    static readonly string UserPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData, Environment.SpecialFolderOption.Create),
        "YubiVault", FileName);

    static string FilePath => File.Exists(PortablePath) || (!File.Exists(UserPath) && CanWrite(AppContext.BaseDirectory))
        ? PortablePath
        : UserPath;
    static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    public List<string> RecentVaults { get; set; } = [];
    public int AutoLockMinutes { get; set; } = 5;

    /// <summary>The interface language, such as "pt" or "zh-Hans"; empty follows the system.</summary>
    public string Language { get; set; } = "";

    /// <summary>Look for a newer signed release on GitHub when the app starts.</summary>
    public bool CheckForUpdates { get; set; } = true;

    public static AppSettings Load()
    {
        try
        {
            if (File.Exists(FilePath))
                return JsonSerializer.Deserialize<AppSettings>(File.ReadAllText(FilePath)) ?? new();
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or JsonException)
        {
        }
        return new();
    }

    public void Save()
    {
        try
        {
            string path = FilePath;
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, JsonSerializer.Serialize(this, JsonOptions));
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            // Read-only media: settings simply don't persist.
        }
    }

    static bool CanWrite(string folder)
    {
        if (OperatingSystem.IsMacOS() && folder.Contains(".app/Contents/", StringComparison.Ordinal))
            return false; // writing inside a signed bundle breaks its signature
        try
        {
            string probe = Path.Combine(folder, $".yubivault-{Guid.NewGuid():n}");
            File.WriteAllBytes(probe, []);
            File.Delete(probe);
            return true;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    public void RememberVault(string path)
    {
        RecentVaults.RemoveAll(p => string.Equals(p, path, OperatingSystem.IsLinux() ? StringComparison.Ordinal : StringComparison.OrdinalIgnoreCase));
        RecentVaults.Insert(0, path);
        if (RecentVaults.Count > MaxRecentVaults)
            RecentVaults.RemoveRange(MaxRecentVaults, RecentVaults.Count - MaxRecentVaults);
        Save();
    }
}
