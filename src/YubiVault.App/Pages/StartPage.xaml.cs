using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using Microsoft.Win32;
using YubiVault.Core;

namespace YubiVault.App.Pages;

public partial class StartPage : UserControl
{
    readonly MainWindow _main;
    string? _folder;
    bool _fido2;
    bool _recoveryMode;

    public StartPage(MainWindow main, string? vaultFolder)
    {
        _main = main;
        InitializeComponent();
        var recent = main.Settings.RecentVaults.Where(Directory.Exists).ToList();
        RecentList.ItemsSource = recent;
        RecentHeader.Visibility = recent.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
        if (vaultFolder is not null)
            SelectVault(vaultFolder);
    }

    void OnOpenVault(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFolderDialog { Title = "Choose the vault folder" };
        if (dialog.ShowDialog(_main) == true)
            SelectVault(dialog.FolderName);
    }

    void OnCreateVault(object sender, RoutedEventArgs e) => _main.ShowCreate();

    void OnRecentClick(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { Tag: string folder })
            SelectVault(folder);
    }

    void SelectVault(string folder)
    {
        ErrorBar.IsOpen = false;
        if (!Vault.Exists(folder))
        {
            ShowError($"There is no vault in {folder}.");
            return;
        }
        IReadOnlyList<KeySlot> slots;
        try
        {
            slots = Vault.ReadKeySlots(folder);
        }
        catch (VaultException ex)
        {
            ShowError(ex.Message);
            return;
        }

        _folder = folder;
        _fido2 = Keys.PreferFido2(slots);
        VaultName.Text = Path.GetFileName(folder.TrimEnd('\\', '/'));
        VaultLocation.Text = folder;
        bool needsPassword = !_fido2 && slots.Any(s => s.RequiresPassword);
        PasswordInput.Visibility = needsPassword ? Visibility.Visible : Visibility.Collapsed;
        PasswordInput.Password = "";
        SetRecoveryMode(false);
        UnlockHint.Text = _fido2
            ? "Plug in your security key and click Unlock. Windows will ask for the key's PIN and a touch."
            : "Plug in your YubiKey and click Unlock, then touch the key when it blinks.";
        UnlockPanel.Visibility = Visibility.Visible;
        (needsPassword ? PasswordInput : (Control)UnlockButton).Focus();
    }

    void OnToggleRecovery(object sender, RoutedEventArgs e) => SetRecoveryMode(!_recoveryMode);

    void SetRecoveryMode(bool on)
    {
        _recoveryMode = on;
        RecoveryInput.Text = "";
        RecoveryInput.Visibility = on ? Visibility.Visible : Visibility.Collapsed;
        RecoveryToggle.Content = on ? "Use my key instead" : "Lost your key? Use the recovery code";
        if (on)
        {
            PasswordInput.Visibility = Visibility.Collapsed;
            UnlockHint.Text = "Type the recovery code you saved when the vault was created.";
            RecoveryInput.Focus();
        }
        else if (_folder is not null && UnlockPanel.Visibility == Visibility.Visible)
        {
            SelectVault(_folder);
        }
    }

    void OnUnlockKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter)
            OnUnlock(sender, e);
    }

    async void OnUnlock(object sender, RoutedEventArgs e)
    {
        if (_folder is null)
            return;
        ErrorBar.IsOpen = false;
        string folder = _folder;
        try
        {
            if (_recoveryMode)
            {
                string code = RecoveryInput.Text;
                var vault = await _main.RunAsync("Unlocking with the recovery code...", () => Vault.OpenWithRecoveryCode(folder, code));
                _main.ShowVault(vault);
            }
            else if (_fido2)
            {
                var key = Keys.SecurityKey(_main);
                var vault = await _main.RunAsync("Waiting for your security key...", () => Vault.OpenWithFido2(folder, key));
                _main.ShowVault(vault);
            }
            else
            {
                string password = PasswordInput.Password;
                var vault = await _main.RunAsync("Unlocking...", () =>
                    Vault.OpenWithYubiKey(folder, Keys.OtpYubiKey(_main.ShowTouchPrompt), () => password));
                _main.ShowVault(vault, openedWithOtpKey: true);
            }
        }
        catch (Exception ex) when (ex is VaultException or FormatException or IOException or UnauthorizedAccessException)
        {
            ShowError(ex is FormatException ? "That is not a valid recovery code." : ex.Message);
        }
    }

    void ShowError(string message)
    {
        ErrorBar.Title = "Could not open the vault";
        ErrorBar.Message = message;
        ErrorBar.IsOpen = true;
        if (UnlockPanel.Visibility != Visibility.Visible)
            MessageBox.Show(_main, message, "YubiVault", MessageBoxButton.OK, MessageBoxImage.Warning);
    }
}
