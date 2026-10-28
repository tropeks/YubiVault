using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32;
using YubiVault.Core;

namespace YubiVault.App;

/// <summary>
/// Makes the system open .yvault files with this executable, for the current user only (no
/// administrator rights, no installer). Since the app is portable, the registration is tied to the
/// executable's current location and is offered again if it moves.
/// </summary>
/// <remarks>
/// .yvault files get their own folder-with-key icon, distinct from the app icon.
/// Windows: HKCU\Software\Classes, with the file icon copied to the local app data folder. Linux: a shared-mime-info type, a .desktop file and an icon under
/// ~/.local/share. macOS: the app bundle's Info.plist declares the type, so nothing is done here.
/// </remarks>
static class FileAssociation
{
    const string ProgId = "YubiVault.Vault";
    const string ClassesKey = @"Software\Classes\";
    const string MimeType = "application/x-yubivault";
    const string DesktopFileName = "yubivault.desktop";

    /// <summary>
    /// The executable to register. Inside an AppImage the process path is a temporary mount, so the
    /// AppImage file itself is registered instead.
    /// </summary>
    static string ExePath => Environment.GetEnvironmentVariable("APPIMAGE") is { Length: > 0 } appImage
        ? appImage
        : Environment.ProcessPath!;

    public static bool IsSupported => OperatingSystem.IsWindows() || OperatingSystem.IsLinux();

    /// <summary>True if .yvault files open with this executable, at its current location.</summary>
    public static bool IsRegistered =>
        OperatingSystem.IsWindows() ? IsRegisteredWindows()
        : OperatingSystem.IsLinux() ? IsRegisteredLinux()
        : true;

    public static void Register()
    {
        if (OperatingSystem.IsWindows())
            RegisterWindows();
        else if (OperatingSystem.IsLinux())
            RegisterLinux();
    }

    // ---- Windows ----

    static string WindowsOpenCommand => $"\"{ExePath}\" \"%1\"";

    static string WindowsFileIconPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "YubiVault", "yubivault-file.ico");

    [SupportedOSPlatform("windows")]
    static bool IsRegisteredWindows()
    {
        using var extension = Registry.CurrentUser.OpenSubKey(ClassesKey + Vault.FileExtension);
        using var command = Registry.CurrentUser.OpenSubKey(ClassesKey + ProgId + @"\shell\open\command");
        using var icon = Registry.CurrentUser.OpenSubKey(ClassesKey + ProgId + @"\DefaultIcon");
        return extension?.GetValue(null) as string == ProgId
            && icon?.GetValue(null) as string == WindowsFileIconPath && File.Exists(WindowsFileIconPath)
            && string.Equals(command?.GetValue(null) as string, WindowsOpenCommand, StringComparison.OrdinalIgnoreCase);
    }

    [SupportedOSPlatform("windows")]
    static void RegisterWindows()
    {
        CopyAsset("yubivault-file.ico", WindowsFileIconPath);
        using (var extension = Registry.CurrentUser.CreateSubKey(ClassesKey + Vault.FileExtension))
            extension.SetValue(null, ProgId);
        using (var progId = Registry.CurrentUser.CreateSubKey(ClassesKey + ProgId))
        {
            progId.SetValue(null, "YubiVault vault");
            using (var icon = progId.CreateSubKey("DefaultIcon"))
                icon.SetValue(null, WindowsFileIconPath);
            using (var command = progId.CreateSubKey(@"shell\open\command"))
                command.SetValue(null, WindowsOpenCommand);
        }
        SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, IntPtr.Zero, IntPtr.Zero);
    }

    const int SHCNE_ASSOCCHANGED = 0x08000000;
    const int SHCNF_IDLIST = 0;

    [DllImport("shell32.dll")]
    static extern void SHChangeNotify(int eventId, int flags, IntPtr item1, IntPtr item2);

    // ---- Linux (freedesktop.org) ----

    static string DataHome => Environment.GetEnvironmentVariable("XDG_DATA_HOME") is { Length: > 0 } home
        ? home
        : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".local", "share");

    static string DesktopFilePath => Path.Combine(DataHome, "applications", DesktopFileName);

    static string DesktopExec => $"Exec=\"{ExePath.Replace("\\", "\\\\").Replace("\"", "\\\"")}\" %f";

    static bool IsRegisteredLinux()
    {
        try
        {
            return File.Exists(DesktopFilePath) && File.ReadLines(DesktopFilePath).Contains(DesktopExec);
        }
        catch (IOException)
        {
            return false;
        }
    }

    static void RegisterLinux()
    {
        string mimeFolder = Path.Combine(DataHome, "mime");
        Directory.CreateDirectory(Path.Combine(mimeFolder, "packages"));
        File.WriteAllText(Path.Combine(mimeFolder, "packages", "yubivault.xml"), $"""
            <?xml version="1.0" encoding="UTF-8"?>
            <mime-info xmlns="http://www.freedesktop.org/standards/shared-mime-info">
              <mime-type type="{MimeType}">
                <comment>YubiVault vault</comment>
                <icon name="application-x-yubivault"/>
                <magic priority="60"><match type="string" offset="0" value="YVAULT"/></magic>
                <glob pattern="*{Vault.FileExtension}"/>
              </mime-type>
            </mime-info>

            """);

        string iconFolder = Path.Combine(DataHome, "icons", "hicolor", "256x256");
        Directory.CreateDirectory(Path.Combine(iconFolder, "apps"));
        Directory.CreateDirectory(Path.Combine(iconFolder, "mimetypes"));
        CopyAsset("yubivault.png", Path.Combine(iconFolder, "apps", "yubivault.png"));
        CopyAsset("yubivault-file.png", Path.Combine(iconFolder, "mimetypes", MimeType.Replace('/', '-') + ".png"));

        Directory.CreateDirectory(Path.GetDirectoryName(DesktopFilePath)!);
        File.WriteAllText(DesktopFilePath, $"""
            [Desktop Entry]
            Type=Application
            Name=YubiVault
            Comment=Encrypted vaults opened with your security key
            {DesktopExec}
            Icon=yubivault
            Terminal=false
            Categories=Utility;Security;
            MimeType={MimeType};

            """);

        Run("update-mime-database", mimeFolder);
        Run("gtk-update-icon-cache", "-q", "-t", Path.Combine(DataHome, "icons", "hicolor"));
        Run("update-desktop-database", Path.GetDirectoryName(DesktopFilePath)!);
        Run("xdg-mime", "default", DesktopFileName, MimeType);
    }

    static void CopyAsset(string name, string destination)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
        using var asset = Avalonia.Platform.AssetLoader.Open(new Uri($"avares://YubiVault/Assets/{name}"));
        using var file = File.Create(destination);
        asset.CopyTo(file);
    }

    /// <summary>Runs a desktop helper if it is installed; the files above work without it after a re-login.</summary>
    static void Run(string program, params string[] arguments)
    {
        try
        {
            var start = new ProcessStartInfo(program) { UseShellExecute = false, RedirectStandardError = true, RedirectStandardOutput = true };
            foreach (var argument in arguments)
                start.ArgumentList.Add(argument);
            using var process = Process.Start(start);
            process?.WaitForExit(10_000);
        }
        catch (Exception e) when (e is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
        }
    }
}
