using Wpf.Ui.Controls;
using YubiVault.Core;

namespace YubiVault.App.Pages;

/// <summary>A row in the vault browser: a folder (derived from file paths) or a file.</summary>
public sealed class VaultItem
{
    public required string Name { get; init; }
    public required string Path { get; init; }
    public bool IsFolder { get; init; }
    public long Size { get; init; }
    public DateTime? ModifiedUtc { get; init; }

    public SymbolRegular Icon => IsFolder ? SymbolRegular.Folder24 : SymbolRegular.Document24;
    public string SizeText => IsFolder ? "" : Format.Size(Size);
    public string ModifiedText => ModifiedUtc?.ToLocalTime().ToString("g") ?? "";

    /// <summary>The folders and files directly inside <paramref name="folder"/>, folders first.</summary>
    public static List<VaultItem> ListFolder(IEnumerable<VaultEntry> entries, string folder)
    {
        string prefix = folder.Length == 0 ? "" : folder + "/";
        var folders = new Dictionary<string, (long Size, DateTime Modified)>(StringComparer.Ordinal);
        var files = new List<VaultItem>();
        foreach (var entry in entries)
        {
            if (!entry.Path.StartsWith(prefix, StringComparison.Ordinal))
                continue;
            string rest = entry.Path[prefix.Length..];
            int slash = rest.IndexOf('/');
            if (slash < 0)
            {
                files.Add(new VaultItem { Name = rest, Path = entry.Path, Size = entry.Size, ModifiedUtc = entry.ModifiedUtc });
                continue;
            }
            string name = rest[..slash];
            folders.TryGetValue(name, out var totals);
            folders[name] = (totals.Size + entry.Size, entry.ModifiedUtc > totals.Modified ? entry.ModifiedUtc : totals.Modified);
        }
        return folders
            .OrderBy(f => f.Key, StringComparer.CurrentCultureIgnoreCase)
            .Select(f => new VaultItem { Name = f.Key, Path = prefix + f.Key, IsFolder = true, Size = f.Value.Size, ModifiedUtc = f.Value.Modified })
            .Concat(files.OrderBy(f => f.Name, StringComparer.CurrentCultureIgnoreCase))
            .ToList();
    }
}
