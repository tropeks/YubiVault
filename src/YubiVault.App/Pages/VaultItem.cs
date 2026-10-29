using Avalonia.Media;
using FluentAvalonia.UI.Controls;
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

    public Symbol Icon => Kind.Icon;
    public IBrush IconBrush => Kind.Brush;
    public IBrush IconBackground => Kind.Background;
    public string SizeText => IsFolder ? "" : Format.Size(Size);
    public string ModifiedText => ModifiedUtc?.ToLocalTime().ToString("g") ?? "";

    FileKind Kind => IsFolder ? FileKind.Folder : FileKind.For(Name);

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

/// <summary>The icon and color a row gets for its kind of file, so a long list can be scanned at a glance.</summary>
sealed class FileKind(Symbol icon, string color)
{
    public Symbol Icon { get; } = icon;
    public IBrush Brush { get; } = new SolidColorBrush(Color.Parse(color));
    public IBrush Background { get; } = new SolidColorBrush(Color.Parse(color), 0.16);

    public static readonly FileKind Folder = new(Symbol.FolderFilled, "#E8A317");
    static readonly FileKind Image = new(Symbol.ImageFilled, "#8B5CF6");
    static readonly FileKind Video = new(Symbol.VideoFilled, "#EC4899");
    static readonly FileKind Audio = new(Symbol.Audio, "#F97316");
    static readonly FileKind Pdf = new(Symbol.DocumentFilled, "#E5484D");
    static readonly FileKind Text = new(Symbol.DocumentFilled, "#3B82F6");
    static readonly FileKind Sheet = new(Symbol.DocumentFilled, "#22A060");
    static readonly FileKind Archive = new(Symbol.ZipFolderFilled, "#A16207");
    static readonly FileKind Secret = new(Symbol.ProtectedDocument, "#0EA5A4");
    static readonly FileKind Code = new(Symbol.Code, "#64748B");
    static readonly FileKind Other = new(Symbol.Document, "#7C8594");

    static readonly Dictionary<string, FileKind> ByExtension = new(StringComparer.OrdinalIgnoreCase)
    {
        [".jpg"] = Image, [".jpeg"] = Image, [".png"] = Image, [".gif"] = Image, [".webp"] = Image, [".heic"] = Image,
        [".bmp"] = Image, [".tif"] = Image, [".tiff"] = Image, [".svg"] = Image, [".raw"] = Image, [".dng"] = Image,
        [".mp4"] = Video, [".mov"] = Video, [".mkv"] = Video, [".avi"] = Video, [".webm"] = Video, [".m4v"] = Video,
        [".mp3"] = Audio, [".wav"] = Audio, [".flac"] = Audio, [".m4a"] = Audio, [".ogg"] = Audio, [".aac"] = Audio,
        [".pdf"] = Pdf,
        [".doc"] = Text, [".docx"] = Text, [".odt"] = Text, [".rtf"] = Text, [".txt"] = Text, [".md"] = Text,
        [".pages"] = Text,
        [".xls"] = Sheet, [".xlsx"] = Sheet, [".ods"] = Sheet, [".csv"] = Sheet, [".numbers"] = Sheet,
        [".zip"] = Archive, [".7z"] = Archive, [".rar"] = Archive, [".tar"] = Archive, [".gz"] = Archive,
        [".kdbx"] = Secret, [".key"] = Secret, [".pem"] = Secret, [".pfx"] = Secret, [".p12"] = Secret,
        [".gpg"] = Secret, [".asc"] = Secret, [".yvault"] = Secret,
        [".cs"] = Code, [".py"] = Code, [".js"] = Code, [".ts"] = Code, [".json"] = Code, [".xml"] = Code,
        [".html"] = Code, [".sh"] = Code, [".ps1"] = Code,
    };

    public static FileKind For(string name) =>
        ByExtension.TryGetValue(System.IO.Path.GetExtension(name), out var kind) ? kind : Other;
}
