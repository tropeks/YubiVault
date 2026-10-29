using System.IO;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Platform.Storage;
using YubiVault.App.Resources;
using YubiVault.Core;

namespace YubiVault.App.Pages;

public partial class VaultPage : UserControl
{
    readonly MainWindow _main;
    readonly Vault _vault;
    string _folder = "";

    public VaultPage() : this(null!, null!) { }

    public VaultPage(MainWindow main, Vault vault)
    {
        _main = main;
        _vault = vault;
        InitializeComponent();
        if (vault is null)
            return; // designer
        VaultName.Text = Path.GetFileNameWithoutExtension(vault.FilePath);
        VaultLocation.Text = vault.IsHidden ? Strings.HiddenVault + "  ·  " + vault.FilePath : vault.FilePath;
        KeysButton.IsVisible = !vault.IsHidden; // its keys are fixed, and listing them would give it away
        AddHandler(DragDrop.DragOverEvent, OnDragOver);
        AddHandler(DragDrop.DropEvent, OnDrop);
        AddHandler(DragDrop.DragLeaveEvent, (_, _) => DropOverlay.IsVisible = false);
        Refresh();
    }

    IEnumerable<VaultItem> Selected => ItemsList.SelectedItems?.OfType<VaultItem>() ?? [];

    internal void Refresh()
    {
        // The folder may have disappeared (everything in it deleted or moved): climb to one that exists.
        while (_folder.Length > 0 && !_vault.Entries.Any(e => VaultPath.IsWithin(e.Path, _folder) && e.Path != _folder))
            _folder = VaultPath.Parent(_folder);

        ItemsList.ItemsSource = VaultItem.ListFolder(_vault.Entries, _folder);
        EmptyState.IsVisible = _vault.Entries.Count == 0;
        Breadcrumbs.ItemsSource = Breadcrumb.For(_folder);
        UpButton.IsEnabled = _folder.Length > 0;
        StatusText.Text = Localization.Format(Strings.StatusFiles, _vault.Entries.Count, Format.Size(_vault.Entries.Sum(e => e.Size)));
        if (_vault.HiddenFreeBytes is long free)
            StatusText.Text += "  ·  " + Localization.Format(Strings.StatusHiddenFree, Format.Size(free), Format.Size(_vault.HiddenCapacity!.Value));
        int minutes = _main.Settings.AutoLockMinutes;
        AutoLockText.Text = minutes > 0 ? Localization.Format(Strings.AutoLockAfter, minutes) : Strings.AutoLockOff;
        UpdateButtons();
    }

    void OnSelectionChanged(object? sender, SelectionChangedEventArgs e) => UpdateButtons();

    void UpdateButtons()
    {
        int count = Selected.Count();
        ExtractButton.IsEnabled = _vault.Entries.Count > 0;
        RenameButton.IsEnabled = count == 1;
        DeleteButton.IsEnabled = count > 0;
    }

    void OnUp(object? sender, RoutedEventArgs e)
    {
        _folder = VaultPath.Parent(_folder);
        Refresh();
    }

    void OnBreadcrumb(object? sender, RoutedEventArgs e)
    {
        if (sender is Control { Tag: string folder })
        {
            _folder = folder;
            Refresh();
        }
    }

    void OnLock(object? sender, RoutedEventArgs e) => _main.Lock();

    void OnKeys(object? sender, RoutedEventArgs e) => _main.Host.Content = new KeysPage(_main, _vault, this);

    // ---- Adding ----

    async void OnAddFiles(object? sender, RoutedEventArgs e)
    {
        var files = await _main.StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
        {
            Title = Strings.ChooseFilesTitle, AllowMultiple = true,
        });
        await AddAsync(LocalPaths(files));
    }

    async void OnAddFolder(object? sender, RoutedEventArgs e)
    {
        var folders = await _main.StorageProvider.OpenFolderPickerAsync(new FolderPickerOpenOptions
        {
            Title = Strings.ChooseFoldersTitle, AllowMultiple = true,
        });
        await AddAsync(LocalPaths(folders));
    }

    static List<string> LocalPaths(IEnumerable<IStorageItem> items) =>
        items.Select(i => i.TryGetLocalPath()).OfType<string>().ToList();

    void OnDragOver(object? sender, DragEventArgs e)
    {
        bool files = e.Data.Contains(DataFormats.Files);
        e.DragEffects = files ? DragDropEffects.Copy : DragDropEffects.None;
        DropOverlay.IsVisible = files;
        e.Handled = true;
    }

    async void OnDrop(object? sender, DragEventArgs e)
    {
        DropOverlay.IsVisible = false;
        if (e.Data.GetFiles() is { } items)
            await AddAsync(LocalPaths(items));
    }

    async Task AddAsync(IReadOnlyList<string> paths)
    {
        if (paths.Count == 0)
            return;
        string target = _folder;
        var progress = _main.BusyProgress;
        await Guard(async () =>
        {
            int added = await _main.RunAsync(Strings.Encrypting, () => paths.Sum(p => _vault.Add(p, target, progress)));
            Refresh();
            ShowInfo(Localization.Format(Strings.EncryptedInfo, added));
        });
    }

    // ---- Opening and extracting ----

    void OnItemDoubleTapped(object? sender, TappedEventArgs e) => OpenSelected();

    void OpenSelected()
    {
        if (ItemsList.SelectedItem is not VaultItem item)
            return;
        if (item.IsFolder)
        {
            _folder = item.Path;
            Refresh();
        }
        else
        {
            _ = OpenFileAsync(item);
        }
    }

    void OnListKeyDown(object? sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter)
            OpenSelected();
        else if (e.Key == Key.Delete)
            OnDelete(sender, e);
        else if (e.Key == Key.Back && _folder.Length > 0)
            OnUp(sender, e);
    }

    async Task OpenFileAsync(VaultItem item)
    {
        string tempFolder = _main.TempFiles.NewFolder();
        await Guard(async () =>
        {
            await _main.RunAsync(Strings.Decrypting, () => _vault.Extract(item.Path, tempFolder));
            await _main.Launcher.LaunchFileInfoAsync(new FileInfo(Path.Combine(tempFolder, item.Name)));
        });
    }

    async void OnExtract(object? sender, RoutedEventArgs e)
    {
        var selected = Selected.ToList();
        var folders = await _main.StorageProvider.OpenFolderPickerAsync(new FolderPickerOpenOptions
        {
            Title = selected.Count > 0 ? Strings.ExtractSelectedTitle : Strings.ExtractAllTitle,
        });
        if (folders.Count == 0 || folders[0].TryGetLocalPath() is not { } destination)
            return;
        var paths = selected.Count > 0 ? selected.Select(i => i.Path).ToList() : [_folder];
        var progress = _main.BusyProgress;

        await Guard(async () =>
        {
            int extracted;
            try
            {
                extracted = await _main.RunAsync(Strings.Decrypting, () => paths.Sum(p => _vault.Extract(p, destination, false, progress)));
            }
            catch (VaultException ex) when (ex.Message.EndsWith("already exists."))
            {
                if (!await Dialogs.ConfirmAsync(_main, Localization.Format(Strings.ReplaceExisting, ex.Message), Strings.Yes))
                    return;
                extracted = await _main.RunAsync(Strings.Decrypting, () => paths.Sum(p => _vault.Extract(p, destination, true, progress)));
            }
            ShowInfo(Localization.Format(Strings.ExtractedInfo, extracted, destination));
        });
    }

    // ---- Changing ----

    async void OnRename(object? sender, RoutedEventArgs e)
    {
        if (ItemsList.SelectedItem is not VaultItem item)
            return;
        string? name = await Dialogs.AskTextAsync(_main, Strings.RenameTitle, Localization.Format(Strings.RenamePrompt, item.Name), item.Name);
        if (string.IsNullOrWhiteSpace(name) || name == item.Name)
            return;
        await Guard(async () =>
        {
            string target = VaultPath.Combine(VaultPath.Parent(item.Path), name.Trim());
            await _main.RunAsync(Strings.Renaming, () => _vault.Move(item.Path, target));
            Refresh();
        });
    }

    async void OnDelete(object? sender, RoutedEventArgs e)
    {
        var selected = Selected.ToList();
        if (selected.Count == 0)
            return;
        string question = selected.Count == 1
            ? Localization.Format(Strings.DeleteOne, selected[0].Name)
            : Localization.Format(Strings.DeleteMany, selected.Count);
        if (!await Dialogs.ConfirmAsync(_main, question, Strings.Delete))
            return;
        await Guard(async () =>
        {
            await _main.RunAsync(Strings.Deleting, () => selected.Sum(i => _vault.Remove(i.Path)));
            Refresh();
        });
    }

    async Task Guard(Func<Task> action)
    {
        try
        {
            await action();
        }
        catch (Exception ex) when (ex is VaultException or IOException or UnauthorizedAccessException or ArgumentException
                                       or ObjectDisposedException or System.ComponentModel.Win32Exception)
        {
            if (ex is ObjectDisposedException)
                return; // the vault was locked meanwhile
            Refresh();
            await Dialogs.AlertAsync(_main, "YubiVault", ex.Message);
        }
    }

    void ShowInfo(string message) => StatusText.Text = message;
}

/// <summary>One step of the path shown above the list: "All files", then each folder down to the current one.</summary>
public sealed class Breadcrumb
{
    public required string Name { get; init; }
    public required string Path { get; init; }
    public bool IsFirst { get; init; }
    public bool IsLast { get; init; }
    public Avalonia.Media.FontWeight Weight => IsLast ? Avalonia.Media.FontWeight.SemiBold : Avalonia.Media.FontWeight.Normal;

    public static List<Breadcrumb> For(string folder)
    {
        var parts = folder.Length == 0 ? [] : folder.Split('/');
        var crumbs = new List<Breadcrumb> { new() { Name = Strings.AllFiles, Path = "", IsFirst = true, IsLast = parts.Length == 0 } };
        for (int i = 0; i < parts.Length; i++)
            crumbs.Add(new() { Name = parts[i], Path = string.Join('/', parts[..(i + 1)]), IsLast = i == parts.Length - 1 });
        return crumbs;
    }
}
