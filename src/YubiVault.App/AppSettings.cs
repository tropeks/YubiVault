using System.IO;
using System.Text.Json;

namespace YubiVault.App;

/// <summary>
/// Settings kept in a JSON file next to the executable, never in the registry, so the app stays portable.
/// </summary>
public sealed class AppSettings
{
    const int MaxRecentVaults = 8;
    static readonly string FilePath = Path.Combine(AppContext.BaseDirectory, "yubivault.settings.json");
    static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    public List<string> RecentVaults { get; set; } = [];
    public int AutoLockMinutes { get; set; } = 5;

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
            File.WriteAllText(FilePath, JsonSerializer.Serialize(this, JsonOptions));
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            // Read-only media: settings simply don't persist.
        }
    }

    public void RememberVault(string folder)
    {
        RecentVaults.RemoveAll(p => string.Equals(p, folder, StringComparison.OrdinalIgnoreCase));
        RecentVaults.Insert(0, folder);
        if (RecentVaults.Count > MaxRecentVaults)
            RecentVaults.RemoveRange(MaxRecentVaults, RecentVaults.Count - MaxRecentVaults);
        Save();
    }
}
