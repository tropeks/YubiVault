using System.Runtime.InteropServices;
using Microsoft.Win32;
using YubiVault.Core;

namespace YubiVault.App;

/// <summary>
/// Makes Windows open .yvault files with this exe, for the current user only (no administrator
/// rights, no installer). Since the app is portable, the registration is tied to the exe's
/// current location and is offered again if the exe moves.
/// </summary>
static class FileAssociation
{
    const string ProgId = "YubiVault.Vault";
    const string ClassesKey = @"Software\Classes\";

    static string ExePath => Environment.ProcessPath!;

    static string OpenCommand => $"\"{ExePath}\" \"%1\"";

    /// <summary>True if .yvault files open with this exe, at its current location.</summary>
    public static bool IsRegistered
    {
        get
        {
            using var extension = Registry.CurrentUser.OpenSubKey(ClassesKey + Vault.FileExtension);
            using var command = Registry.CurrentUser.OpenSubKey(ClassesKey + ProgId + @"\shell\open\command");
            return extension?.GetValue(null) as string == ProgId
                && string.Equals(command?.GetValue(null) as string, OpenCommand, StringComparison.OrdinalIgnoreCase);
        }
    }

    public static void Register()
    {
        using (var extension = Registry.CurrentUser.CreateSubKey(ClassesKey + Vault.FileExtension))
            extension.SetValue(null, ProgId);
        using (var progId = Registry.CurrentUser.CreateSubKey(ClassesKey + ProgId))
        {
            progId.SetValue(null, "YubiVault vault");
            using (var icon = progId.CreateSubKey("DefaultIcon"))
                icon.SetValue(null, $"\"{ExePath}\",0");
            using (var command = progId.CreateSubKey(@"shell\open\command"))
                command.SetValue(null, OpenCommand);
        }
        SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, IntPtr.Zero, IntPtr.Zero);
    }

    const int SHCNE_ASSOCCHANGED = 0x08000000;
    const int SHCNF_IDLIST = 0;

    [DllImport("shell32.dll")]
    static extern void SHChangeNotify(int eventId, int flags, IntPtr item1, IntPtr item2);
}
