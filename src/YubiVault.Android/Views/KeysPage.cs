using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Media;
using YubiVault.Android.Resources;
using YubiVault.Core;

namespace YubiVault.Android.Views;

/// <summary>The keys that open the vault: add a backup security key, remove one, or replace the recovery code.</summary>
sealed class KeysPage : UserControl, IBackHandler
{
    readonly MainView _main;
    readonly VaultSession _session;
    readonly StackPanel _slots = new() { Spacing = 8 };
    bool _busy;

    public KeysPage(MainView main, VaultSession session)
    {
        _main = main;
        _session = session;
        Content = Ui.Page(
            Ui.TopBar(Strings.KeysTitle, session.Name, () => OnBack()),
            Ui.Column(
                Ui.Hint(Strings.KeysIntro),
                _slots,
                Ui.Button(Strings.AddSecurityKey, AddKey, accent: true, icon: Ui.KeyIcon),
                Ui.Button(Strings.NewRecoveryCode, NewRecoveryCode),
                Ui.Button(Strings.CreateHiddenVault, () => { if (!_busy) _main.Show(new CreateHiddenPage(_main, session)); }, icon: Ui.LockIcon)));
        Refresh();
    }

    public bool OnBack()
    {
        if (!_busy)
            _main.ShowVault(_session);
        return true;
    }

    void Refresh()
    {
        _slots.Children.Clear();
        foreach (var slot in _session.Vault.Slots)
            _slots.Children.Add(Row(slot));
    }

    Control Row(KeySlot slot)
    {
        string kind = slot.Type switch
        {
            KeySlotType.Fido2 => Strings.KindFido2,
            KeySlotType.YubiKey => slot.RequiresPassword ? Strings.KindOtpPassword : Strings.KindOtp,
            KeySlotType.Recovery => Strings.KindRecovery,
            _ => slot.Type,
        };
        string label = slot.Type == KeySlotType.Recovery ? Strings.KindRecovery : slot.Label;
        var text = new StackPanel
        {
            VerticalAlignment = VerticalAlignment.Center,
            Children =
            {
                new TextBlock { Text = label, FontSize = 16, TextTrimming = TextTrimming.CharacterEllipsis },
                new TextBlock { Text = kind + " · " + slot.CreatedUtc.ToLocalTime().ToString("d"), FontSize = 13, Opacity = 0.7 },
            },
        };
        var row = new Grid { ColumnDefinitions = new ColumnDefinitions("Auto,*,Auto"), MinHeight = 56 };
        var badge = Ui.IconBadge(slot.Type == KeySlotType.Recovery ? Ui.LockIcon : Ui.KeyIcon, 44);
        badge.VerticalAlignment = VerticalAlignment.Center;
        badge.Margin = new Thickness(0, 0, 14, 0);
        row.Children.Add(badge);
        Grid.SetColumn(text, 1);
        row.Children.Add(text);
        if (slot.Type != KeySlotType.Recovery)
        {
            var remove = Ui.TextButton(Strings.Remove, () => Remove(slot, label));
            remove.VerticalAlignment = VerticalAlignment.Center;
            Grid.SetColumn(remove, 2);
            row.Children.Add(remove);
        }
        return Ui.Card(row, 12);
    }

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

    async Task Save()
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

    async void AddKey() => await Guard(async () =>
    {
        if (!await _main.ConfirmAsync(Strings.ConfirmAddSecurityKey, Strings.AddSecurityKey))
            return;
        var (done, _) = await _main.WithSecurityKeyAsync(Strings.RegisteringKey, key => _session.Vault.AddSecurityKey(key));
        if (done)
            await Save();
    });

    async void Remove(KeySlot slot, string label) => await Guard(async () =>
    {
        if (!await _main.ConfirmAsync(Ui.Format(Strings.ConfirmRemoveKey, label), Strings.Remove))
            return;
        await _main.RunAsync(Strings.Removing, () => _session.Vault.RemoveSlot(slot.Id));
        await Save();
    });

    async void NewRecoveryCode() => await Guard(async () =>
    {
        if (!await _main.ConfirmAsync(Strings.ConfirmNewRecovery, Strings.NewRecoveryCode))
            return;
        string code = await _main.RunAsync(Strings.CreatingRecovery, () => _session.Vault.RegenerateRecoveryCode());
        await Save();
        // The vault may have locked while the code was on screen (the user left the app to store it).
        _main.Show(new RecoveryCodePage(_main, code, () =>
        {
            if (_main.Session == _session)
                _main.Show(new KeysPage(_main, _session));
            else
                _main.ShowStart();
        }));
    });
}
