namespace YubiVault.Core;

/// <summary>Paths inside a vault: '/'-separated, relative, without "." or ".." segments.</summary>
public static class VaultPath
{
    /// <summary>Normalizes <paramref name="path"/>; the vault root is the empty string.</summary>
    /// <exception cref="ArgumentException">The path escapes the vault or has invalid characters.</exception>
    public static string Normalize(string path)
    {
        var segments = path.Replace('\\', '/').Split('/', StringSplitOptions.RemoveEmptyEntries);
        foreach (var segment in segments)
        {
            if (segment is "." or ".." || segment.Any(char.IsControl))
                throw new ArgumentException($"Invalid vault path: {path}", nameof(path));
        }
        return string.Join('/', segments);
    }

    public static string Combine(string directory, string name) =>
        directory.Length == 0 ? name : $"{directory}/{name}";

    /// <summary>The parent folder of <paramref name="path"/> ("" for top-level items).</summary>
    public static string Parent(string path)
    {
        int slash = path.LastIndexOf('/');
        return slash < 0 ? "" : path[..slash];
    }

    /// <summary>True when <paramref name="path"/> is <paramref name="folderOrFile"/> or lies inside it.</summary>
    public static bool IsWithin(string path, string folderOrFile) =>
        folderOrFile.Length == 0
        || path == folderOrFile
        || path.StartsWith(folderOrFile + "/", StringComparison.Ordinal);
}
