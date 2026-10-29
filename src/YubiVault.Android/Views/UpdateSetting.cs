namespace YubiVault.Android.Views;

/// <summary>Whether the app looks for a newer signed release when it starts: on unless turned off. Kept in a small file.</summary>
static class UpdateSetting
{
    static string FilePath => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "updates");

    public static bool CheckAutomatically
    {
        get
        {
            try
            {
                return !File.Exists(FilePath) || File.ReadAllText(FilePath).Trim() != "off";
            }
            catch (IOException)
            {
                return true;
            }
        }
        set
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
                File.WriteAllText(FilePath, value ? "on" : "off");
            }
            catch (IOException)
            {
            }
        }
    }
}
