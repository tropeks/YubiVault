using Avalonia.Controls;
using YubiVault.Android.Platform;
using YubiVault.Android.Resources;
using YubiVault.Core;

namespace YubiVault.Android.Views;

/// <summary>Unlocks a vault with the security key (PIN, then USB or NFC) or with the recovery code.</summary>
sealed class UnlockPage : UserControl, IBackHandler
{
    readonly MainView _main;
    readonly VaultDocument _document;
    readonly TextBlock _hint = Ui.Hint("");
    readonly TextBlock _error = Ui.Error();
    readonly TextBox _recoveryInput = new() { FontFamily = "monospace", IsVisible = false, HorizontalContentAlignment = Avalonia.Layout.HorizontalAlignment.Center };
    readonly Button _unlock;
    readonly Button _toggle;
    string? _workingPath;
    bool _hasFido2 = true;
    bool _recoveryMode;
    bool _busy;

    public UnlockPage(MainView main, VaultDocument document)
    {
        _main = main;
        _document = document;
        _recoveryInput.Watermark = "XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX";
        _recoveryInput.KeyDown += (_, e) =>
        {
            if (e.Key == Avalonia.Input.Key.Enter)
                Unlock();
        };
        _unlock = Ui.Button(Strings.Unlock, Unlock, accent: true, icon: Ui.KeyIcon);
        _toggle = Ui.TextButton(Strings.UseRecoveryCode, () => SetRecoveryMode(!_recoveryMode));

        var badge = Ui.IconBadge(Ui.ShieldLockIcon, 112);
        badge.Margin = new Avalonia.Thickness(0, 8, 0, 4);
        var name = Ui.Text(Path.GetFileNameWithoutExtension(document.DisplayName), 26, Avalonia.Media.FontWeight.Bold);
        name.TextAlignment = Avalonia.Media.TextAlignment.Center;
        var file = Ui.Hint(document.DisplayName);
        file.TextAlignment = Avalonia.Media.TextAlignment.Center;
        file.Margin = new Avalonia.Thickness(0, -10, 0, 8);
        _hint.TextAlignment = Avalonia.Media.TextAlignment.Center;
        var column = Ui.Column(badge, name, file, _hint, _recoveryInput, _error, _unlock, _toggle);
        column.MaxWidth = 560;
        Content = Ui.Page(Ui.TopBar("", null, () => OnBack()), column);
        SetRecoveryMode(false);
        AttachedToVisualTree += (_, _) => _ = PrepareAsync();
    }

    public bool OnBack()
    {
        if (!_busy)
            _main.ShowStart();
        return true;
    }

    /// <summary>Copies the document to the working file and reads which keys open it.</summary>
    async Task PrepareAsync()
    {
        if (_workingPath is not null)
            return;
        _busy = true;
        try
        {
            string path = await _main.RunAsync(MobileStrings.OpeningVault, () => _main.Platform.CopyToWorkingFileAsync(_document));
            if (!Vault.Exists(path))
            {
                ShowFatal(Ui.Format(Strings.NotAVault, _document.DisplayName));
                return;
            }
            var slots = await Task.Run(() => Vault.ReadKeySlots(path));
            _hasFido2 = slots.Any(s => s.Type == KeySlotType.Fido2);
            _workingPath = path;
            _main.Platform.AddRecent(_document);
            SetRecoveryMode(!_hasFido2);
        }
        catch (Exception e)
        {
            ShowFatal(e.Message);
        }
        finally
        {
            _busy = false;
        }
    }

    void ShowFatal(string message)
    {
        Ui.ShowError(_error, message);
        _unlock.IsEnabled = false;
        _toggle.IsVisible = false;
        _recoveryInput.IsVisible = false;
    }

    void SetRecoveryMode(bool on)
    {
        _recoveryMode = on;
        Ui.ShowError(_error, null);
        _recoveryInput.IsVisible = on;
        _recoveryInput.Text = "";
        _toggle.IsVisible = _hasFido2;
        _toggle.Content = Ui.ButtonText(on ? Strings.UseKeyInstead : Strings.UseRecoveryCode);
        _hint.Text = on
            ? (_hasFido2 ? Strings.UnlockHintRecovery : MobileStrings.OtpNotSupported + "\n\n" + Strings.UnlockHintRecovery)
            : MobileStrings.UnlockHintMobile;
        if (on)
            _recoveryInput.Focus();
    }

    async void Unlock()
    {
        if (_workingPath is null || _busy)
            return;
        string path = _workingPath;
        Ui.ShowError(_error, null);
        _busy = true;
        try
        {
            Vault vault;
            if (_recoveryMode)
            {
                string code = _recoveryInput.Text ?? "";
                vault = await _main.RunAsync(Strings.UnlockingRecovery, () => Vault.OpenWithRecoveryCode(path, code));
            }
            else
            {
                var (done, opened) = await _main.WithSecurityKeyAsync(Strings.Unlocking, key => Vault.OpenWithFido2(path, key));
                if (!done)
                    return;
                vault = opened;
            }
            _main.ShowVault(new VaultSession(vault, _document, path));
        }
        catch (FormatException)
        {
            Ui.ShowError(_error, Strings.InvalidRecoveryCode);
        }
        catch (Exception e)
        {
            Ui.ShowError(_error, e.Message);
        }
        finally
        {
            _busy = false;
        }
    }
}
