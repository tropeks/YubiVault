using System.IO;
using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;
using YubiVault.Core;
using YubiVault.Core.Keys;

namespace YubiVault.App.Pages;

public partial class CreatePage : UserControl
{
    readonly MainWindow _main;

    public CreatePage(MainWindow main)
    {
        _main = main;
        InitializeComponent();
    }

    void OnBack(object sender, RoutedEventArgs e) => _main.ShowStart();

    void OnBrowse(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFolderDialog { Title = "Choose where to create the vault" };
        if (dialog.ShowDialog(_main) == true)
            LocationInput.Text = dialog.FolderName;
    }

    void OnKeyTypeChanged(object sender, RoutedEventArgs e)
    {
        if (OtpPanel is not null)
            OtpPanel.Visibility = OtpOption.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
    }

    async void OnCreate(object sender, RoutedEventArgs e)
    {
        ErrorBar.IsOpen = false;
        string name = NameInput.Text.Trim();
        if (LocationInput.Text.Length == 0)
        {
            ShowError("Choose where to create the vault.");
            return;
        }
        if (name.Length == 0 || name.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
        {
            ShowError("Give the vault a name that is valid as a file name.");
            return;
        }
        string path = Path.Combine(LocationInput.Text, name + Vault.FileExtension);
        bool otp = OtpOption.IsChecked == true;
        string? password = null;
        if (otp)
        {
            if (PasswordInput.Password != PasswordRepeat.Password)
            {
                ShowError("The passwords do not match.");
                return;
            }
            password = PasswordInput.Password.Length > 0 ? PasswordInput.Password : null;
        }

        try
        {
            (Vault Vault, string RecoveryCode) created;
            if (otp)
            {
                bool replace = ReplaceSlot.IsChecked == true;
                created = await _main.RunAsync("Creating the vault...", () =>
                {
                    var key = Keys.OtpYubiKey(_main.ShowTouchPrompt);
                    if (replace || !key.IsSlotConfigured)
                        key.ProgramSlot();
                    return Vault.Create(path, key, password);
                });
            }
            else
            {
                IFido2Authenticator key = Keys.SecurityKey(_main);
                created = await _main.RunAsync("Registering your security key...", () => Vault.Create(path, key));
            }

            new RecoveryCodeWindow(created.RecoveryCode) { Owner = _main }.ShowDialog();
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
