using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using Microsoft.Win32;
using YubiVault.Core;

namespace YubiVault.App.Pages;

public partial class VaultPage : UserControl
{
    readonly MainWindow _main;
    readonly Vault _vault;
    string _folder = "";

    public VaultPage(MainWindow main, Vault vault)
    {
        _main = main;
        _vault = vault;
        InitializeComponent();
        VaultName.Text = Path.GetFileNameWithoutExtension(vault.FilePath);
        VaultLocation.Text = vault.FilePath;
        Refresh();
    }

    IEnumerable<VaultItem> Selected => ItemsList.SelectedItems.Cast<VaultItem>();

    void Refresh()
    {
        // The folder may have disappeared (everything in it deleted or moved): climb to one that exists.
        while (_folder.Length > 0 && !_vault.Entries.Any(e => VaultPath.IsWithin(e.Path, _folder) && e.Path != _folder))
            _folder = VaultPath.Parent(_folder);

        var items = VaultItem.ListFolder(_vault.Entries, _folder);
        ItemsList.ItemsSource = items;
        EmptyState.Visibility = _vault.Entries.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        FolderText.Text = _folder.Length == 0 ? "All files" : _folder.Replace("/", "  ›  ");
        UpButton.IsEnabled = _folder.Length > 0;
        StatusText.Text = $"{_vault.Entries.Count} files, {Format.Size(_vault.Entries.Sum(e => e.Size))} encrypted";
        int minutes = _main.Settings.AutoLockMinutes;
        AutoLockText.Text = minutes > 0 ? $"Locks after {minutes} min without use" : "Auto-lock off";
        OnSelectionChanged(this, null!);
    }

    void OnSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        int count = ItemsList.SelectedItems.Count;
        ExtractButton.IsEnabled = _vault.Entries.Count > 0;
        RenameButton.IsEnabled = count == 1;
        DeleteButton.IsEnabled = count > 0;
    }

    void OnUp(object sender, RoutedEventArgs e)
    {
        _folder = VaultPath.Parent(_folder);
        Refresh();
    }

    void OnLock(object sender, RoutedEventArgs e) => _main.Lock();

    void OnKeys(object sender, RoutedEventArgs e)
    {
        new KeysWindow(_main, _vault) { Owner = _main }.ShowDialog();
        Refresh();
    }

    // ---- Adding ----

    void OnAddFiles(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { Title = "Choose files to encrypt", Multiselect = true };
        if (dialog.ShowDialog(_main) == true)
            _ = AddAsync(dialog.FileNames);
    }

    void OnAddFolder(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFolderDialog { Title = "Choose folders to encrypt", Multiselect = true };
        if (dialog.ShowDialog(_main) == true)
            _ = AddAsync(dialog.FolderNames);
    }

    void OnDragOver(object sender, DragEventArgs e)
    {
        e.Effects = e.Data.GetDataPresent(DataFormats.FileDrop) ? DragDropEffects.Copy : DragDropEffects.None;
        e.Handled = true;
    }

    void OnDrop(object sender, DragEventArgs e)
    {
        if (e.Data.GetData(DataFormats.FileDrop) is string[] paths && paths.Length > 0)
            _ = AddAsync(paths);
    }

    async Task AddAsync(IReadOnlyList<string> paths)
    {
        string target = _folder;
        var progress = _main.BusyProgress;
        await Guard(async () =>
        {
            int added = await _main.RunAsync("Encrypting...", () => paths.Sum(p => _vault.Add(p, target, progress)));
            Refresh();
            ShowInfo($"Encrypted {added} file(s). The originals were not changed; delete them yourself if you no longer need them.");
        });
    }

    // ---- Opening and extracting ----

    void OnItemDoubleClick(object sender, MouseButtonEventArgs e)
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

    void OnListKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter)
            OnItemDoubleClick(sender, null!);
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
            await _main.RunAsync("Decrypting...", () => _vault.Extract(item.Path, tempFolder));
            TempFiles.Open(Path.Combine(tempFolder, item.Name));
        });
    }

    async void OnExtract(object sender, RoutedEventArgs e)
    {
        var selected = Selected.ToList();
        var dialog = new OpenFolderDialog
        {
            Title = selected.Count > 0 ? "Extract the selected items to..." : "Extract everything in this folder to...",
        };
        if (dialog.ShowDialog(_main) != true)
            return;
        var paths = selected.Count > 0 ? selected.Select(i => i.Path).ToList() : [_folder];
        string destination = dialog.FolderName;
        var progress = _main.BusyProgress;

        await Guard(async () =>
        {
            int extracted;
            try
            {
                extracted = await _main.RunAsync("Decrypting...", () => paths.Sum(p => _vault.Extract(p, destination, false, progress)));
            }
            catch (VaultException ex) when (ex.Message.EndsWith("already exists."))
            {
                if (MessageBox.Show(_main, $"{ex.Message}\n\nReplace existing files?", "YubiVault",
                        MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes)
                    return;
                extracted = await _main.RunAsync("Decrypting...", () => paths.Sum(p => _vault.Extract(p, destination, true, progress)));
            }
            ShowInfo($"Extracted {extracted} file(s) to {destination}.");
        });
    }

    // ---- Changing ----

    async void OnRename(object sender, RoutedEventArgs e)
    {
        if (ItemsList.SelectedItem is not VaultItem item)
            return;
        string? name = TextPromptWindow.Ask(_main, "Rename", $"New name for \"{item.Name}\"", item.Name);
        if (string.IsNullOrWhiteSpace(name) || name == item.Name)
            return;
        await Guard(async () =>
        {
            string target = VaultPath.Combine(VaultPath.Parent(item.Path), name.Trim());
            await _main.RunAsync("Renaming...", () => _vault.Move(item.Path, target));
            Refresh();
        });
    }

    async void OnDelete(object sender, RoutedEventArgs e)
    {
        var selected = Selected.ToList();
        if (selected.Count == 0)
            return;
        string what = selected.Count == 1 ? $"\"{selected[0].Name}\"" : $"{selected.Count} items";
        if (MessageBox.Show(_main, $"Delete {what} from the vault? This cannot be undone.", "YubiVault",
                MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes)
            return;
        await Guard(async () =>
        {
            await _main.RunAsync("Deleting...", () => selected.Sum(i => _vault.Remove(i.Path)));
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
            MessageBox.Show(_main, ex.Message, "YubiVault", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    void ShowInfo(string message) => StatusText.Text = message;
}
