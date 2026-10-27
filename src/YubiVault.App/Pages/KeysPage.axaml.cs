using System.IO;
using Avalonia.Controls;
using Avalonia.Interactivity;
using YubiVault.App.Resources;
using YubiVault.Core;

namespace YubiVault.App.Pages;

public sealed record SlotRow(string Id, string Label, string Kind, string Added);

/// <summary>The keys that open the vault, the recovery code and the auto-lock setting.</summary>
public partial class KeysPage : UserControl
{
    static readonly int[] AutoLockChoices = [0, 1, 5, 15, 30, 60];

    readonly MainWindow _main;
    readonly Vault _vault;
    readonly VaultPage _back;

    public KeysPage() : this(null!, null!, null!) { }

    public KeysPage(MainWindow main, Vault vault, VaultPage back)
    {
        _main = main;
        _vault = vault;
        _back = back;
        InitializeComponent();
        if (vault is null)
            return; // designer
        AutoLockCombo.ItemsSource = AutoLockChoices
            .Select(m => m == 0 ? Strings.Never : Localization.Format(Strings.Minutes, m)).ToList();
        int current = Array.IndexOf(AutoLockChoices, main.Settings.AutoLockMinutes);
        AutoLockCombo.SelectedIndex = current >= 0 ? current : 2;
        RefreshSlots();
    }

    void RefreshSlots()
    {
        SlotsList.ItemsSource = _vault.Slots.Select(s => new SlotRow(
            s.Id,
            s.Label,
            s.Type switch
            {
                KeySlotType.Fido2 => Strings.KindFido2,
                KeySlotType.YubiKey => s.RequiresPassword ? Strings.KindOtpPassword : Strings.KindOtp,
                _ => Strings.KindRecovery,
            },
            s.CreatedUtc.ToLocalTime().ToString("d"))).ToList();
    }

    void OnBack(object? sender, RoutedEventArgs e)
    {
        _main.Host.Content = _back;
        _back.Refresh();
    }

    void OnSelectionChanged(object? sender, SelectionChangedEventArgs e) => RemoveButton.IsEnabled = SlotsList.SelectedItem is not null;

    async void OnAddSecurityKey(object? sender, RoutedEventArgs e)
    {
        if (!await Dialogs.ConfirmAsync(_main, Strings.ConfirmAddSecurityKey))
            return;
        await Guard(async () =>
        {
            var key = Keys.SecurityKey(_main, _main);
            await _main.RunAsync(Strings.RegisteringKey, () => _vault.AddSecurityKey(key));
            RefreshSlots();
        });
    }

    async void OnAddOtpKey(object? sender, RoutedEventArgs e)
    {
        if (!await Dialogs.ConfirmAsync(_main, Strings.ConfirmAddOtpKey))
            return;
        string? password = await Dialogs.AskTextAsync(_main, Strings.Password, Strings.OtpPasswordPrompt, secret: true);
        if (password is null)
            return;
        await Guard(async () =>
        {
            await _main.RunAsync(Strings.RegisteringYubiKey, () =>
            {
                var key = Keys.OtpYubiKey(() => _main.ShowTouchPrompt());
                if (!key.IsSlotConfigured)
                    key.ProgramSlot();
                return _vault.AddYubiKey(key, password.Length > 0 ? password : null);
            });
            RefreshSlots();
        });
    }

    async void OnRemove(object? sender, RoutedEventArgs e)
    {
        if (SlotsList.SelectedItem is not SlotRow row)
            return;
        if (!await Dialogs.ConfirmAsync(_main, Localization.Format(Strings.ConfirmRemoveKey, row.Label), Strings.Remove))
            return;
        await Guard(async () =>
        {
            await _main.RunAsync(Strings.Removing, () => _vault.RemoveSlot(row.Id));
            RefreshSlots();
        });
    }

    async void OnNewRecoveryCode(object? sender, RoutedEventArgs e)
    {
        if (!await Dialogs.ConfirmAsync(_main, Strings.ConfirmNewRecovery))
            return;
        await Guard(async () =>
        {
            string code = await _main.RunAsync(Strings.CreatingRecovery, () => _vault.RegenerateRecoveryCode());
            RefreshSlots();
            await Dialogs.ShowRecoveryCodeAsync(_main, code);
        });
    }

    void OnAutoLockChanged(object? sender, SelectionChangedEventArgs e)
    {
        if (AutoLockCombo.SelectedIndex < 0 || _main is null)
            return;
        _main.Settings.AutoLockMinutes = AutoLockChoices[AutoLockCombo.SelectedIndex];
        _main.Settings.Save();
    }

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
