using System.IO;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Platform.Storage;
using YubiVault.App.Resources;
using YubiVault.Core;

namespace YubiVault.App.Pages;

public partial class StartPage : UserControl
{
    readonly MainWindow _main;
    string? _vaultFile;
    bool _fido2;
    bool _recoveryMode;
    bool _loadingLanguages;

    public StartPage() : this(null!, null) { }

    public StartPage(MainWindow main, string? vaultFile)
    {
        _main = main;
        InitializeComponent();
        if (main is null)
            return; // designer
        var recent = main.Settings.RecentVaults.Where(File.Exists).ToList();
        RecentList.ItemsSource = recent;
        RecentHeader.IsVisible = recent.Count > 0;
        AssociateButton.IsVisible = FileAssociation.IsSupported && !FileAssociation.IsRegistered;
        LoadLanguages();
        if (vaultFile is not null)
            SelectVault(vaultFile);
    }

    void LoadLanguages()
    {
        _loadingLanguages = true;
        var names = new List<string> { Strings.LanguageSystem };
        names.AddRange(Localization.Languages.Select(l => l.Name));
        LanguageCombo.ItemsSource = names;
        int index = Localization.Languages.ToList().FindIndex(l => l.Code == _main.Settings.Language);
        LanguageCombo.SelectedIndex = index + 1;
        _loadingLanguages = false;
    }

    void OnLanguageChanged(object? sender, SelectionChangedEventArgs e)
    {
        if (_loadingLanguages || LanguageCombo.SelectedIndex < 0)
            return;
        string code = LanguageCombo.SelectedIndex == 0 ? "" : Localization.Languages[LanguageCombo.SelectedIndex - 1].Code;
        if (code != _main.Settings.Language)
            _main.ChangeLanguage(code);
    }

    async void OnOpenVault(object? sender, RoutedEventArgs e)
    {
        var files = await _main.StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
        {
            Title = Strings.ChooseVaultTitle,
            FileTypeFilter =
            [
                new FilePickerFileType(Strings.VaultFileType) { Patterns = ["*" + Vault.FileExtension] },
                FilePickerFileTypes.All,
            ],
        });
        if (files.Count > 0 && files[0].TryGetLocalPath() is { } path)
            SelectVault(path);
    }

    void OnCreateVault(object? sender, RoutedEventArgs e) => _main.ShowCreate();

    void OnRecentClick(object? sender, RoutedEventArgs e)
    {
        if (sender is Control { Tag: string path })
            SelectVault(path);
    }

    async void OnAssociate(object? sender, RoutedEventArgs e)
    {
        try
        {
            FileAssociation.Register();
            AssociateButton.IsVisible = false;
            await Dialogs.AlertAsync(_main, "YubiVault", Strings.AssociateDone);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException or IOException
                                       or InvalidOperationException)
        {
            await Dialogs.AlertAsync(_main, "YubiVault", ex.Message);
        }
    }

    void SelectVault(string path)
    {
        ErrorBar.IsOpen = false;
        if (!Vault.Exists(path))
        {
            ShowError(Localization.Format(Strings.NotAVault, path));
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
        PasswordInput.IsVisible = needsPassword;
        PasswordInput.Text = "";
        SetRecoveryMode(false);
        UnlockHint.Text = !_fido2 ? Strings.UnlockHintOtp
            : Keys.SystemAsksForPin ? Strings.UnlockHintFido2Windows : Strings.UnlockHintFido2;
        UnlockPanel.IsVisible = true;
        (needsPassword ? PasswordInput : (Control)UnlockButton).Focus();
    }

    void OnToggleRecovery(object? sender, RoutedEventArgs e) => SetRecoveryMode(!_recoveryMode);

    void SetRecoveryMode(bool on)
    {
        _recoveryMode = on;
        RecoveryInput.Text = "";
        RecoveryInput.IsVisible = on;
        RecoveryToggle.Content = on ? Strings.UseKeyInstead : Strings.UseRecoveryCode;
        if (on)
        {
            PasswordInput.IsVisible = false;
            UnlockHint.Text = Strings.UnlockHintRecovery;
            RecoveryInput.Focus();
        }
        else if (_vaultFile is not null && UnlockPanel.IsVisible)
        {
            SelectVault(_vaultFile);
        }
    }

    void OnUnlockKeyDown(object? sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter)
            OnUnlock(sender, e);
    }

    async void OnUnlock(object? sender, RoutedEventArgs e)
    {
        if (_vaultFile is null)
            return;
        ErrorBar.IsOpen = false;
        string path = _vaultFile;
        try
        {
            if (_recoveryMode)
            {
                string code = RecoveryInput.Text ?? "";
                var vault = await _main.RunAsync(Strings.UnlockingRecovery, () => Vault.OpenWithRecoveryCode(path, code));
                _main.ShowVault(vault);
            }
            else if (_fido2)
            {
                var key = Keys.SecurityKey(_main, _main);
                var vault = await _main.RunAsync(Strings.WaitingForKey, () => Vault.OpenWithFido2(path, key));
                _main.ShowVault(vault);
            }
            else
            {
                string password = PasswordInput.Text ?? "";
                var vault = await _main.RunAsync(Strings.Unlocking, () =>
                    Vault.OpenWithYubiKey(path, Keys.OtpYubiKey(() => _main.ShowTouchPrompt()), () => password));
                _main.ShowVault(vault, openedWithOtpKey: true);
            }
        }
        catch (Exception ex) when (ex is VaultException or FormatException or IOException or UnauthorizedAccessException)
        {
            ShowError(ex is FormatException ? Strings.InvalidRecoveryCode : ex.Message);
        }
    }

    void ShowError(string message)
    {
        if (!UnlockPanel.IsVisible)
        {
            _ = Dialogs.AlertAsync(_main, Strings.CouldNotOpen, message);
            return;
        }
        ErrorBar.Message = message;
        ErrorBar.IsOpen = true;
    }
}
