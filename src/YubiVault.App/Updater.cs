using System.Diagnostics;
using System.Formats.Tar;
using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Runtime.InteropServices;
using YubiVault.Core.Updates;

namespace YubiVault.App;

/// <summary>
/// Installs a signed release over the running app, in the way that fits how it was installed:
/// the portable Windows .exe and the Linux binary replace themselves, the .deb and .rpm packages go
/// through the system's package tool (which asks for the administrator password), and the macOS
/// .app bundle is swapped for the new one. The app then restarts.
/// </summary>
static class Updater
{
    enum Kind { WindowsExe, LinuxBinary, LinuxDeb, LinuxRpm, MacApp, None }

    const string OldSuffix = ".old";

    static readonly Kind Install = Detect();

    public static Version CurrentVersion =>
        Assembly.GetEntryAssembly()?.GetName().Version is { } v ? new Version(v.Major, v.Minor, Math.Max(v.Build, 0)) : new Version(0, 0, 0);

    /// <summary>Whether this copy can update itself at all (a development build run with dotnet cannot).</summary>
    public static bool IsSupported => Install != Kind.None;

    static string ExePath => Environment.ProcessPath ?? "";

    /// <summary>The program to start after an update; the Windows .exe changes name with the version.</summary>
    static string _restartPath = "";

    /// <summary>The portable Windows .exe as released, e.g. YubiVault-1.2.3-win-x64.exe.</summary>
    static readonly System.Text.RegularExpressions.Regex VersionedExe =
        new(@"^YubiVault-\d+\.\d+\.\d+-win-x64\.exe$", System.Text.RegularExpressions.RegexOptions.IgnoreCase);

    /// <summary>The bundle around the running macOS executable (…/YubiVault.app).</summary>
    static string MacBundle => Path.GetFullPath(Path.Combine(Path.GetDirectoryName(ExePath)!, "..", ".."));

    static Kind Detect()
    {
        string exe = ExePath;
        if (exe.Length == 0 || Path.GetFileNameWithoutExtension(exe).Equals("dotnet", StringComparison.OrdinalIgnoreCase))
            return Kind.None;
        if (OperatingSystem.IsWindows())
            return RuntimeInformation.OSArchitecture == Architecture.X64 ? Kind.WindowsExe : Kind.None;
        if (OperatingSystem.IsMacOS())
            return exe.EndsWith(".app/Contents/MacOS/YubiVault", StringComparison.Ordinal) ? Kind.MacApp : Kind.None;
        if (OperatingSystem.IsLinux())
        {
            if (exe == "/usr/bin/yubivault")
                return File.Exists("/var/lib/dpkg/info/yubivault.list") ? Kind.LinuxDeb
                    : File.Exists("/usr/bin/rpm") ? Kind.LinuxRpm : Kind.None;
            return Kind.LinuxBinary;
        }
        return Kind.None;
    }

    /// <summary>The release file this copy installs from, or null if the release has none for it.</summary>
    public static UpdateFile? FileFor(UpdateRelease release)
    {
        bool arm = RuntimeInformation.OSArchitecture == Architecture.Arm64;
        string v = release.VersionText;
        string? name = Install switch
        {
            Kind.WindowsExe => $"YubiVault-{v}-win-x64.exe",
            Kind.LinuxBinary => $"YubiVault-{v}-linux-{(arm ? "arm64" : "x64")}.tar.gz",
            Kind.LinuxDeb => $"yubivault_{v}_{(arm ? "arm64" : "amd64")}.deb",
            Kind.LinuxRpm => $"yubivault-{v}-1.{(arm ? "aarch64" : "x86_64")}.rpm",
            Kind.MacApp => $"YubiVault-{v}-osx-{(arm ? "arm64" : "x64")}.zip",
            _ => null,
        };
        return name is not null && release.Files.TryGetValue(name, out var file) ? file : null;
    }

    /// <summary>Removes what an earlier update left behind (the replaced program). Called at start-up.</summary>
    public static void CleanUp()
    {
        try
        {
            if (Install is Kind.WindowsExe or Kind.LinuxBinary)
            {
                File.Delete(ExePath + OldSuffix);
                // An update to a renamed .exe leaves the previous version's name behind.
                foreach (string old in Directory.EnumerateFiles(Path.GetDirectoryName(ExePath)!, "YubiVault-*-win-x64.exe" + OldSuffix))
                {
                    if (VersionedExe.IsMatch(Path.GetFileNameWithoutExtension(old)))
                        File.Delete(old);
                }
                File.Delete(Path.Combine(Path.GetDirectoryName(ExePath)!, CliName + OldSuffix));
            }
            else if (Install == Kind.MacApp)
            {
                string old = MacBundle + OldSuffix;
                if (Directory.Exists(old))
                    Directory.Delete(old, recursive: true);
            }
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            // Still in use or read-only; the next start tries again.
        }
    }

    static string CliName => OperatingSystem.IsWindows() ? "yubivault-cli.exe" : "yubivault-cli";

    /// <summary>
    /// Downloads, verifies and installs <paramref name="file"/>. Runs off the UI thread. When it returns,
    /// the new version is in place and <see cref="Restart"/> starts it.
    /// </summary>
    public static async Task InstallAsync(UpdateChecker checker, UpdateFile file, IProgress<double> progress)
    {
        _restartPath = ExePath;
        string work = Directory.CreateTempSubdirectory("yubivault-update-").FullName;
        try
        {
            string download = Path.Combine(work, file.Name);
            await checker.DownloadAsync(file, download, progress);
            switch (Install)
            {
                case Kind.WindowsExe:
                    InstallWindowsExe(download, file.Name);
                    break;
                case Kind.LinuxBinary:
                    InstallFromTarball(download, work);
                    break;
                case Kind.LinuxDeb:
                    RunAsAdmin("dpkg", "-i", download);
                    break;
                case Kind.LinuxRpm:
                    RunAsAdmin("rpm", "-U", download);
                    break;
                case Kind.MacApp:
                    InstallMacBundle(download, work);
                    break;
                default:
                    throw new PlatformNotSupportedException();
            }
        }
        finally
        {
            try
            {
                Directory.Delete(work, recursive: true);
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
            }
        }
    }

    /// <summary>
    /// Starts the updated app; the caller then closes this one. Right after it is written, the new program
    /// can stay locked for a few seconds while the antivirus scans it, so this retries for a while.
    /// </summary>
    /// <returns>Null once started; otherwise why it could not be, and the user opens it again by hand.</returns>
    public static async Task<string?> RestartAsync()
    {
        string? error = null;
        for (int attempt = 0; attempt < 10; attempt++)
        {
            try
            {
                if (Install == Kind.MacApp)
                    Process.Start("open", ["-n", MacBundle]);
                else
                    Process.Start(new ProcessStartInfo(_restartPath) { UseShellExecute = false });
                return null;
            }
            catch (Exception e)
            {
                error = Dialogs.Describe(e);
                await Task.Delay(TimeSpan.FromSeconds(1));
            }
        }
        return error;
    }

    /// <summary>
    /// Installs the new .exe. Kept under its released name (YubiVault-1.2.3-win-x64.exe), the file
    /// takes the new version's name, so the name never shows an old version; .yvault files that opened
    /// with the old one now open with the new one. A copy the user renamed keeps its name.
    /// </summary>
    static void InstallWindowsExe(string download, string releasedName)
    {
        string current = ExePath;
        if (!VersionedExe.IsMatch(Path.GetFileName(current)))
        {
            ReplaceFile(download, current);
            return;
        }
        string target = Path.Combine(Path.GetDirectoryName(current)!, releasedName);
        if (string.Equals(target, current, StringComparison.OrdinalIgnoreCase))
        {
            ReplaceFile(download, current);
            return;
        }
        bool associated = FileAssociation.IsRegistered;
        string staged = target + ".new";
        File.Copy(download, staged, overwrite: true);
        File.Move(staged, target, overwrite: true);
        // The running program can't be deleted, but it can be renamed; the next start removes it.
        File.Move(current, current + OldSuffix, overwrite: true);
        _restartPath = target;
        if (associated)
        {
            try
            {
                FileAssociation.Register(target);
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException or System.Security.SecurityException)
            {
                // The new version offers to associate the files again.
            }
        }
    }

    /// <summary>
    /// Puts <paramref name="source"/> where <paramref name="target"/> is. A running program cannot be
    /// overwritten on Windows but can be renamed, so the current one steps aside first.
    /// </summary>
    static void ReplaceFile(string source, string target)
    {
        string folder = Path.GetDirectoryName(target)!;
        string staged = Path.Combine(folder, $".{Path.GetFileName(target)}.new");
        File.Copy(source, staged, overwrite: true);
        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(staged, File.GetUnixFileMode(target));
        string old = target + OldSuffix;
        File.Delete(old);
        File.Move(target, old);
        try
        {
            File.Move(staged, target);
        }
        catch
        {
            File.Move(old, target);
            File.Delete(staged);
            throw;
        }
    }

    /// <summary>Takes the app (and, if it sits next to it, the CLI) out of YubiVault-x-linux-*.tar.gz.</summary>
    static void InstallFromTarball(string archive, string work)
    {
        string extracted = Directory.CreateDirectory(Path.Combine(work, "x")).FullName;
        using (var gzip = new GZipStream(File.OpenRead(archive), CompressionMode.Decompress))
            TarFile.ExtractToDirectory(gzip, extracted, overwriteFiles: false);
        string root = Directory.GetDirectories(extracted).Single();
        ReplaceFile(Path.Combine(root, "YubiVault"), ExePath);
        string cli = Path.Combine(Path.GetDirectoryName(ExePath)!, CliName);
        if (File.Exists(cli))
            ReplaceFile(Path.Combine(root, CliName), cli);
    }

    /// <summary>Swaps the running YubiVault.app for the one in YubiVault-x-osx-*.zip.</summary>
    static void InstallMacBundle(string archive, string work)
    {
        string extracted = Path.Combine(work, "x");
        // ditto keeps the bundle's permissions, symlinks and signature intact.
        Run("ditto", "-x", "-k", archive, extracted);
        string newBundle = Path.Combine(Directory.GetDirectories(extracted).Single(), "YubiVault.app");
        if (!Directory.Exists(newBundle))
            throw new UpdateException("The update has no YubiVault.app.");

        string bundle = MacBundle;
        string staged = Path.Combine(Path.GetDirectoryName(bundle)!, ".YubiVault.app.new");
        if (Directory.Exists(staged))
            Directory.Delete(staged, recursive: true);
        // The temp folder may be on another volume; copy next to the app first so the swap is two renames.
        Run("ditto", newBundle, staged);
        string old = bundle + OldSuffix;
        if (Directory.Exists(old))
            Directory.Delete(old, recursive: true);
        Directory.Move(bundle, old);
        try
        {
            Directory.Move(staged, bundle);
        }
        catch
        {
            Directory.Move(old, bundle);
            throw;
        }
    }

    static void RunAsAdmin(string tool, params string[] args) => Run("pkexec", [tool, .. args]);

    static void Run(string program, params string[] args)
    {
        using var process = Process.Start(new ProcessStartInfo(program, args)
        {
            UseShellExecute = false,
            RedirectStandardError = true,
        }) ?? throw new UpdateException($"Could not run {program}.");
        string error = process.StandardError.ReadToEnd();
        process.WaitForExit();
        if (process.ExitCode != 0)
            throw new UpdateException(error.Trim() is { Length: > 0 } e ? e : $"{program} failed ({process.ExitCode}).");
    }
}
