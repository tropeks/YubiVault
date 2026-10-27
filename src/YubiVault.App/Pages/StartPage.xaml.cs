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
    string? _vaultFile;
    bool _fido2;
    bool _recoveryMode;

    public StartPage(MainWindow main, string? vaultFile)
    {
        _main = main;
        InitializeComponent();
        var recent = main.Settings.RecentVaults.Where(File.Exists).ToList();
        RecentList.ItemsSource = recent;
        RecentHeader.Visibility = recent.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
        if (vaultFile is not null)
            SelectVault(vaultFile);
    }

    void OnOpenVault(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Title = "Choose the vault",
            Filter = $"YubiVault vaults (*{Vault.FileExtension})|*{Vault.FileExtension}|All files (*.*)|*.*",
        };
        if (dialog.ShowDialog(_main) == true)
            SelectVault(dialog.FileName);
    }

    void OnCreateVault(object sender, RoutedEventArgs e) => _main.ShowCreate();

    void OnRecentClick(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { Tag: string path })
            SelectVault(path);
    }

    void SelectVault(string path)
    {
        ErrorBar.IsOpen = false;
        if (!Vault.Exists(path))
        {
            ShowError($"{path} is not a YubiVault vault.");
            return;
        }
        IReadOnlyList<KeySlot> slots;
        try
        {
            slots = Vault.ReadKeySlots(path);
        }
        catch (VaultException ex)
        {
            ShowError(ex.Message);
            return;
        }

        _vaultFile = path;
        _fido2 = Keys.PreferFido2(slots);
        VaultName.Text = Path.GetFileNameWithoutExtension(path);
        VaultLocation.Text = path;
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
        else if (_vaultFile is not null && UnlockPanel.Visibility == Visibility.Visible)
        {
            SelectVault(_vaultFile);
        }
    }

    void OnUnlockKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter)
            OnUnlock(sender, e);
    }

    async void OnUnlock(object sender, RoutedEventArgs e)
    {
        if (_vaultFile is null)
            return;
        ErrorBar.IsOpen = false;
        string path = _vaultFile;
        try
        {
            if (_recoveryMode)
            {
                string code = RecoveryInput.Text;
                var vault = await _main.RunAsync("Unlocking with the recovery code...", () => Vault.OpenWithRecoveryCode(path, code));
                _main.ShowVault(vault);
            }
            else if (_fido2)
            {
                var key = Keys.SecurityKey(_main);
                var vault = await _main.RunAsync("Waiting for your security key...", () => Vault.OpenWithFido2(path, key));
                _main.ShowVault(vault);
            }
            else
            {
                string password = PasswordInput.Password;
                var vault = await _main.RunAsync("Unlocking...", () =>
                    Vault.OpenWithYubiKey(path, Keys.OtpYubiKey(_main.ShowTouchPrompt), () => password));
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
