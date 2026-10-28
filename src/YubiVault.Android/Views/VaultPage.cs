using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Media;
using YubiVault.Android.Resources;
using YubiVault.Core;

namespace YubiVault.Android.Views;

/// <summary>A folder or file in the vault browser; folders come from the file paths.</summary>
sealed record VaultItem(string Name, string Path, bool IsFolder, long Size, DateTime ModifiedUtc)
{
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
                files.Add(new VaultItem(rest, entry.Path, false, entry.Size, entry.ModifiedUtc));
                continue;
            }
            string name = rest[..slash];
            folders.TryGetValue(name, out var totals);
            folders[name] = (totals.Size + entry.Size, entry.ModifiedUtc > totals.Modified ? entry.ModifiedUtc : totals.Modified);
        }
        return folders
            .OrderBy(f => f.Key, StringComparer.CurrentCultureIgnoreCase)
            .Select(f => new VaultItem(f.Key, prefix + f.Key, true, f.Value.Size, f.Value.Modified))
            .Concat(files.OrderBy(f => f.Name, StringComparer.CurrentCultureIgnoreCase))
            .ToList();
    }
}

/// <summary>The unlocked vault: browse folders, open, save, rename and delete files, add new ones, lock.</summary>
sealed class VaultPage : UserControl, IBackHandler
{
    readonly MainView _main;
    readonly VaultSession _session;
    readonly StackPanel _list = new() { Margin = new Thickness(8, 0, 8, 104), Spacing = 2 };
    readonly TextBlock _status = Ui.Hint("");
    readonly ContentControl _topBar = new();
    string _folder = "";
    bool _busy;

    public VaultPage(MainView main, VaultSession session)
    {
        _main = main;
        _session = session;
        _status.Margin = new Thickness(20, 0, 20, 8);
        _status.FontSize = 13;

        // An extended floating action button, raised over the list in the bottom corner.
        var add = Ui.Button(Strings.AddFiles, AddFiles, accent: true, icon: Ui.PlusIcon);
        add.HorizontalAlignment = HorizontalAlignment.Stretch;
        add.MinHeight = 56;
        add.CornerRadius = new CornerRadius(16);
        add.Padding = new Thickness(20, 0, 24, 0);
        var fab = new Border
        {
            Child = add,
            CornerRadius = new CornerRadius(16),
            BoxShadow = BoxShadows.Parse("0 6 18 0 #40000000"),
            HorizontalAlignment = HorizontalAlignment.Right,
            VerticalAlignment = VerticalAlignment.Bottom,
            Margin = new Thickness(16, 16, 20, 24),
        };

        var list = new StackPanel { Children = { _status, _list } };
        var scroller = new ScrollViewer
        {
            Content = list,
            HorizontalScrollBarVisibility = Avalonia.Controls.Primitives.ScrollBarVisibility.Disabled,
        };
        var dock = new DockPanel();
        DockPanel.SetDock(_topBar, Dock.Top);
        dock.Children.Add(_topBar);
        dock.Children.Add(new Panel { Children = { scroller, fab } });
        Content = dock;
        Refresh();
    }

    public bool OnBack()
    {
        if (_busy)
            return true;
        if (_folder.Length > 0)
            Navigate(VaultPath.Parent(_folder));
        else
            Lock();
        return true;
    }

    void Navigate(string folder)
    {
        _folder = folder;
        Refresh();
    }

    void Refresh()
    {
        var entries = _session.Vault.Entries;
        if (_folder.Length > 0 && !entries.Any(e => VaultPath.IsWithin(e.Path, _folder)))
            _folder = ""; // the folder was emptied, renamed or deleted
        _topBar.Content = Ui.TopBar(
            _folder.Length == 0 ? _session.Name : _folder[(_folder.LastIndexOf('/') + 1)..],
            _folder.Length == 0 ? (_session.Vault.IsHidden ? Strings.HiddenVault : null) : _session.Name + " / " + _folder.Replace("/", " / "),
            _folder.Length == 0 ? null : () => Navigate(VaultPath.Parent(_folder)),
            // A hidden vault's keys are fixed, and listing them would give it away.
            _session.Vault.IsHidden
                ? [Ui.IconButton(Ui.LockIcon, Strings.Lock, Lock)]
                : [Ui.IconButton(Ui.KeyIcon, Strings.Keys, () => _main.Show(new KeysPage(_main, _session))), Ui.IconButton(Ui.LockIcon, Strings.Lock, Lock)]);

        _list.Children.Clear();
        var items = VaultItem.ListFolder(entries, _folder);
        if (items.Count == 0)
        {
            var empty = Ui.Hint(MobileStrings.EmptyFolder);
            empty.TextAlignment = TextAlignment.Center;
            var badge = Ui.IconBadge(Ui.FolderIcon, 96);
            _list.Children.Add(new StackPanel { Spacing = 16, Margin = new Thickness(24, 64, 24, 0), Children = { badge, empty } });
        }
        foreach (var item in items)
            _list.Children.Add(Row(item));
        _status.Text = Ui.Format(Strings.StatusFiles, entries.Count, Ui.Size(entries.Sum(e => e.Size)));
        if (_session.Vault.HiddenFreeBytes is long free)
            _status.Text += " · " + Ui.Format(Strings.StatusHiddenFree, Ui.Size(free), Ui.Size(_session.Vault.HiddenCapacity!.Value));
    }

    Control Row(VaultItem item)
    {
        string details = item.IsFolder
            ? Ui.Size(item.Size)
            : Ui.Size(item.Size) + " · " + item.ModifiedUtc.ToLocalTime().ToString("g");
        Control badge;
        if (item.IsFolder)
            badge = Ui.IconBadge(Ui.FolderIcon, 44);
        else
        {
            var (icon, color) = Ui.FileKind(item.Name);
            badge = Ui.ColoredBadge(icon, color);
        }
        badge.VerticalAlignment = VerticalAlignment.Center;
        var open = new Button
        {
            Content = new Grid
            {
                ColumnDefinitions = new ColumnDefinitions("Auto,*"),
                ColumnSpacing = 16,
                Children =
                {
                    badge,
                    Column1(new StackPanel
                    {
                        VerticalAlignment = VerticalAlignment.Center,
                        Spacing = 2,
                        Children =
                        {
                            new TextBlock { Text = item.Name, FontSize = 16, FontWeight = FontWeight.Medium, TextTrimming = TextTrimming.CharacterEllipsis },
                            new TextBlock { Text = details, FontSize = 13, Opacity = 0.65, TextTrimming = TextTrimming.CharacterEllipsis },
                        },
                    }),
                },
            },
            MinHeight = 64,
            Padding = new Thickness(12, 8),
            HorizontalAlignment = HorizontalAlignment.Stretch,
            HorizontalContentAlignment = HorizontalAlignment.Stretch,
            Classes = { "flat" },
        };
        open.Click += (_, _) =>
        {
            if (item.IsFolder)
                Navigate(item.Path);
            else
                OpenFile(item);
        };

        var menu = new MenuFlyout();
        if (!item.IsFolder)
        {
            menu.Items.Add(MenuItem(MobileStrings.Open, () => OpenFile(item)));
            menu.Items.Add(MenuItem(MobileStrings.SaveToDevice, () => SaveToDevice(item)));
        }
        menu.Items.Add(MenuItem(Strings.Rename, () => Rename(item)));
        menu.Items.Add(MenuItem(Strings.Delete, () => Delete(item)));
        var more = Ui.IconButton(Ui.MoreIcon, MobileStrings.More);
        more.Flyout = menu;

        var row = new Grid { ColumnDefinitions = new ColumnDefinitions("*,Auto") };
        row.Children.Add(open);
        Grid.SetColumn(more, 1);
        more.VerticalAlignment = VerticalAlignment.Center;
        row.Children.Add(more);
        return row;
    }

    static Control Column1(Control control)
    {
        Grid.SetColumn(control, 1);
        return control;
    }

    static MenuItem MenuItem(string header, Action onClick)
    {
        var item = new MenuItem { Header = header, MinHeight = Ui.TouchSize };
        item.Click += (_, _) => onClick();
        return item;
    }

    /// <summary>Runs a step that may fail, with the page marked busy, and reports errors.</summary>
    async Task Guard(Func<Task> step)
    {
        if (_busy)
            return;
        _busy = true;
        _main.BeginStep();
        try
        {
            await step();
        }
        catch (Exception e)
        {
            await _main.ShowErrorAsync(e);
        }
        finally
        {
            _busy = false;
            _main.EndStep();
        }
    }

    /// <summary>After a change to the vault: refresh the list and write the vault back to its document.</summary>
    async Task Changed()
    {
        Refresh();
        try
        {
            await _session.SaveAsync(_main);
        }
        catch (Exception e)
        {
            await _main.AlertAsync(Strings.ErrorTitle, MobileStrings.CouldNotSave + "\n\n" + e.Message);
        }
    }

    async Task<string> DecryptToTemp(VaultItem item)
    {
        string folder = _main.NewTempFolder();
        await _main.RunAsync(Strings.Decrypting, () => _session.Vault.Extract(item.Path, folder, overwrite: true));
        return Path.Combine(folder, item.Name);
    }

    async void OpenFile(VaultItem item) => await Guard(async () =>
    {
        string path = await DecryptToTemp(item);
        _main.Platform.OpenFile(path);
    });

    async void SaveToDevice(VaultItem item) => await Guard(async () =>
    {
        string path = await DecryptToTemp(item);
        try
        {
            if (await _main.Platform.SaveFileAsAsync(path))
                _main.ShowToast(MobileStrings.FileSaved);
        }
        finally
        {
            Directory.Delete(Path.GetDirectoryName(path)!, recursive: true);
        }
    });

    async void Rename(VaultItem item) => await Guard(async () =>
    {
        string? name = await _main.PromptAsync(Strings.RenameTitle, Ui.Format(Strings.RenamePrompt, item.Name), item.Name);
        name = name?.Trim();
        if (string.IsNullOrEmpty(name) || name == item.Name)
            return;
        string target = VaultPath.Combine(VaultPath.Parent(item.Path), name);
        await _main.RunAsync(Strings.Renaming, () => _session.Vault.Move(item.Path, target));
        await Changed();
    });

    async void Delete(VaultItem item) => await Guard(async () =>
    {
        if (!await _main.ConfirmAsync(Ui.Format(Strings.DeleteOne, item.Name), Strings.Delete))
            return;
        await _main.RunAsync(Strings.Deleting, () => _session.Vault.Remove(item.Path));
        await Changed();
    });

    async void AddFiles() => await Guard(async () =>
    {
        var files = await _main.Platform.PickFilesToAddAsync();
        if (files.Count == 0)
            return;
        string folder = _folder;
        int added;
        try
        {
            added = await _main.RunAsync(Strings.Encrypting, () => files.Sum(file => _session.Vault.Add(file, folder)));
        }
        finally
        {
            foreach (var file in files)
            {
                try
                {
                    File.Delete(file);
                }
                catch (IOException)
                {
                }
            }
        }
        await Changed();
        _main.ShowToast(Ui.Format(Strings.EncryptedInfo, added));
    });

    async void Lock() => await Guard(_main.LockAsync);
}
