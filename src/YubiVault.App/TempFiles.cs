using System.IO;

namespace YubiVault.App;

/// <summary>
/// Files decrypted to open them in another program. They live in a private temp folder and are
/// overwritten and deleted when the vault locks or the app closes.
/// </summary>
public sealed class TempFiles
{
    readonly string _root = Path.Combine(TempRoot(), "YubiVault", Environment.ProcessId.ToString());

    /// <summary>
    /// On Linux, $XDG_RUNTIME_DIR is a per-user tmpfs (memory, not disk) when it exists. Elsewhere the
    /// user's temp folder; on Linux and macOS the folders are made readable by the user only.
    /// </summary>
    static string TempRoot() =>
        OperatingSystem.IsLinux() && Environment.GetEnvironmentVariable("XDG_RUNTIME_DIR") is { Length: > 0 } runtime
            && Directory.Exists(runtime)
            ? runtime
            : Path.GetTempPath();

    /// <summary>A new, empty private folder to decrypt a file into.</summary>
    public string NewFolder()
    {
        string folder = Path.Combine(_root, Guid.NewGuid().ToString("n")[..8]);
        if (OperatingSystem.IsWindows())
        {
            Directory.CreateDirectory(folder);
        }
        else
        {
            const UnixFileMode OwnerOnly = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
            Directory.CreateDirectory(Path.GetDirectoryName(_root)!, OwnerOnly);
            Directory.CreateDirectory(_root, OwnerOnly);
            Directory.CreateDirectory(folder, OwnerOnly);
        }
        return folder;
    }

    public void WipeAll()
    {
        if (!Directory.Exists(_root))
            return;
        foreach (var file in Directory.EnumerateFiles(_root, "*", SearchOption.AllDirectories))
        {
            try
            {
                var length = new FileInfo(file).Length;
                using (var stream = new FileStream(file, FileMode.Open, FileAccess.Write, FileShare.None))
                {
                    var zeros = new byte[64 * 1024];
                    for (long written = 0; written < length; written += zeros.Length)
                        stream.Write(zeros, 0, (int)Math.Min(zeros.Length, length - written));
                }
                File.Delete(file);
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                // Still open in another program; it is retried at the next lock.
            }
        }
        try
        {
            Directory.Delete(_root, recursive: true);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
        }
    }
}
