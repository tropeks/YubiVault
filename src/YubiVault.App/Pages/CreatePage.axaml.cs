using System.IO;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Platform.Storage;
using YubiVault.App.Resources;
using YubiVault.Core;
using YubiVault.Core.Keys;

namespace YubiVault.App.Pages;

public partial class CreatePage : UserControl
{
    readonly MainWindow _main;

    public CreatePage() : this(null!) { }

    public CreatePage(MainWindow main)
    {
        _main = main;
        InitializeComponent();
    }

    void OnBack(object? sender, RoutedEventArgs e) => _main.ShowStart();

    async void OnBrowse(object? sender, RoutedEventArgs e)
    {
        var folders = await _main.StorageProvider.OpenFolderPickerAsync(new FolderPickerOpenOptions
        {
            Title = Strings.ChooseLocationTitle,
        });
        if (folders.Count > 0 && folders[0].TryGetLocalPath() is { } path)
            LocationInput.Text = path;
    }

    void OnKeyTypeChanged(object? sender, RoutedEventArgs e)
    {
        if (OtpPanel is not null)
            OtpPanel.IsVisible = OtpOption.IsChecked == true;
    }

    async void OnCreate(object? sender, RoutedEventArgs e)
    {
        ErrorBar.IsOpen = false;
        string name = (NameInput.Text ?? "").Trim();
        string location = LocationInput.Text ?? "";
        if (location.Length == 0)
        {
            ShowError(Strings.ChooseLocation);
            return;
        }
        if (name.Length == 0 || name.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
        {
            ShowError(Strings.InvalidName);
            return;
        }
        string path = Path.Combine(location, name + Vault.FileExtension);
        bool otp = OtpOption.IsChecked == true;
        string? password = null;
        if (otp)
        {
            if (PasswordInput.Text != PasswordRepeat.Text)
            {
                ShowError(Strings.PasswordsDiffer);
                return;
            }
            password = string.IsNullOrEmpty(PasswordInput.Text) ? null : PasswordInput.Text;
        }

        try
        {
            (Vault Vault, string RecoveryCode) created;
            if (otp)
            {
                bool replace = ReplaceSlot.IsChecked == true;
                created = await _main.RunAsync(Strings.CreatingVault, () =>
                {
                    var key = Keys.OtpYubiKey(() => _main.ShowTouchPrompt());
                    if (replace || !key.IsSlotConfigured)
                        key.ProgramSlot();
                    return Vault.Create(path, key, password);
                });
            }
            else
            {
                IFido2Authenticator key = Keys.SecurityKey(_main, _main);
                created = await _main.RunAsync(Strings.RegisteringKey, () => Vault.Create(path, key));
            }

            await Dialogs.ShowRecoveryCodeAsync(_main, created.RecoveryCode);
            _main.ShowVault(created.Vault, openedWithOtpKey: otp);
        }
        catch (Exception ex) when (ex is VaultException or IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            ShowError(ex.Message);
        }
    }

    void ShowError(string message)
    {
        ErrorBar.Message = message;
        ErrorBar.IsOpen = true;
    }
}
