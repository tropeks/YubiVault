using System.IO;
using System.Windows;
using System.Windows.Controls;
using Wpf.Ui.Controls;
using YubiVault.Core;
using MessageBox = System.Windows.MessageBox;
using MessageBoxButton = System.Windows.MessageBoxButton;
using MessageBoxResult = System.Windows.MessageBoxResult;

namespace YubiVault.App;

public partial class KeysWindow : FluentWindow
{
    static readonly int[] AutoLockChoices = [0, 1, 5, 15, 30, 60];

    readonly MainWindow _main;
    readonly Vault _vault;

    public KeysWindow(MainWindow main, Vault vault)
    {
        _main = main;
        _vault = vault;
        InitializeComponent();
        AutoLockCombo.ItemsSource = AutoLockChoices.Select(m => m == 0 ? "Never" : $"{m} minute{(m == 1 ? "" : "s")}").ToList();
        int current = Array.IndexOf(AutoLockChoices, main.Settings.AutoLockMinutes);
        AutoLockCombo.SelectedIndex = current >= 0 ? current : 2;
        RefreshSlots();
    }

    sealed record SlotRow(string Id, string Label, string Kind, string Added);

    void RefreshSlots()
    {
        SlotsList.ItemsSource = _vault.Slots.Select(s => new SlotRow(
            s.Id,
            s.Label,
            s.Type switch
            {
                KeySlotType.Fido2 => "FIDO2 + PIN",
                KeySlotType.YubiKey => s.RequiresPassword ? "OTP + password" : "OTP",
                _ => "Recovery code",
            },
            s.CreatedUtc.ToLocalTime().ToString("d"))).ToList();
    }

    void OnSelectionChanged(object sender, SelectionChangedEventArgs e) => RemoveButton.IsEnabled = SlotsList.SelectedItem is not null;

    async void OnAddSecurityKey(object sender, RoutedEventArgs e)
    {
        if (!Confirm("Plug in the new security key and remove the others. Windows will ask for the new key's PIN and a touch, twice."))
            return;
        await Guard(async () =>
        {
            var key = Keys.SecurityKey(this);
            await RunAsync("Registering the security key...", () => _vault.AddSecurityKey(key));
            RefreshSlots();
        });
    }

    async void OnAddOtpKey(object sender, RoutedEventArgs e)
    {
        if (!Confirm("Plug in the new YubiKey 5 and remove the others. If its slot 2 is empty, it will be programmed for challenge-response."))
            return;
        string? password = TextPromptWindow.Ask(this, "Password", "Optional password to use together with this YubiKey (leave empty for none):");
        if (password is null)
            return;
        await Guard(async () =>
        {
            await RunAsync("Registering the YubiKey...", () =>
            {
                var key = Keys.OtpYubiKey(_main.ShowTouchPrompt);
                if (!key.IsSlotConfigured)
                    key.ProgramSlot();
                return _vault.AddYubiKey(key, password.Length > 0 ? password : null);
            });
            RefreshSlots();
        });
    }

    async void OnRemove(object sender, RoutedEventArgs e)
    {
        if (SlotsList.SelectedItem is not SlotRow row)
            return;
        if (!Confirm($"Remove \"{row.Label}\"? It will no longer open this vault."))
            return;
        await Guard(async () =>
        {
            await RunAsync("Removing...", () => { _vault.RemoveSlot(row.Id); return true; });
            RefreshSlots();
        });
    }

    async void OnNewRecoveryCode(object sender, RoutedEventArgs e)
    {
        if (!Confirm("Create a new recovery code? The old one will stop working."))
            return;
        await Guard(async () =>
        {
            string code = await RunAsync("Creating a new recovery code...", () => _vault.RegenerateRecoveryCode());
            RefreshSlots();
            new RecoveryCodeWindow(code) { Owner = this }.ShowDialog();
        });
    }

    void OnAutoLockChanged(object sender, SelectionChangedEventArgs e)
    {
        if (AutoLockCombo.SelectedIndex < 0)
            return;
        _main.Settings.AutoLockMinutes = AutoLockChoices[AutoLockCombo.SelectedIndex];
        _main.Settings.Save();
    }

    Task<T> RunAsync<T>(string title, Func<T> work) => _main.RunAsync(title, work);

    bool Confirm(string message) =>
        MessageBox.Show(this, message, "YubiVault", MessageBoxButton.OKCancel, System.Windows.MessageBoxImage.Question) == MessageBoxResult.OK;

    async Task Guard(Func<Task> action)
    {
        ErrorBar.IsOpen = false;
        try
        {
            await action();
        }
        catch (Exception ex) when (ex is VaultException or IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            ErrorBar.Message = ex.Message;
            ErrorBar.IsOpen = true;
        }
    }
}
