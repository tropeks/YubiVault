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
                Ui.Button(Strings.NewRecoveryCode, NewRecoveryCode)));
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
        row.Children.Add(new PathIcon
        {
            Data = slot.Type == KeySlotType.Recovery ? Ui.LockIcon : Ui.KeyIcon,
            Width = 24,
            Height = 24,
            Margin = new Thickness(4, 0, 14, 0),
        });
        Grid.SetColumn(text, 1);
        row.Children.Add(text);
        if (slot.Type != KeySlotType.Recovery)
        {
            var remove = new Button { Content = Strings.Remove, MinHeight = Ui.TouchSize, VerticalAlignment = VerticalAlignment.Center };
            remove.Click += (_, _) => Remove(slot, label);
            Grid.SetColumn(remove, 2);
            row.Children.Add(remove);
        }
        return new Border { Child = row, Padding = new Thickness(8), CornerRadius = new CornerRadius(8) }
            .WithBackground("SystemControlBackgroundBaseLowBrush");
    }

    async Task Guard(Func<Task> step)
    {
        if (_busy)
            return;
        _busy = true;
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
        _main.Show(new RecoveryCodePage(_main, code, () => _main.Show(new KeysPage(_main, _session))));
    });
}
