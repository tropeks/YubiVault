using Avalonia.Controls;
using YubiVault.Android.Resources;

namespace YubiVault.Android.Views;

/// <summary>Creates a hidden vault inside the open vault's file: its size and its own password.</summary>
sealed class CreateHiddenPage : UserControl, IBackHandler
{
    readonly MainView _main;
    readonly VaultSession _session;
    readonly NumericUpDown _size = new() { Minimum = 1, Maximum = 1 << 20, Value = 256, Increment = 64, FormatString = "0" };
    readonly TextBox _password = new() { PasswordChar = '•' };
    readonly TextBox _repeat = new() { PasswordChar = '•' };
    readonly TextBlock _error = Ui.Error();
    bool _busy;

    public CreateHiddenPage(MainView main, VaultSession session)
    {
        _main = main;
        _session = session;
        _password.Watermark = Strings.HiddenPassword;
        _repeat.Watermark = Strings.RepeatPassword;
        Content = Ui.Page(
            Ui.TopBar(Strings.CreateHiddenVault, session.Name, () => OnBack()),
            Ui.Column(
                Ui.Hint(Strings.HiddenVaultIntro),
                Ui.Hint(Strings.HiddenVaultWarning),
                Ui.Text(Strings.HiddenVaultSize, 14),
                _size,
                _password,
                _repeat,
                _error,
                Ui.Button(Strings.CreateHiddenVault, Create, accent: true, icon: Ui.KeyIcon)));
    }

    public bool OnBack()
    {
        if (!_busy)
            _main.Show(new KeysPage(_main, _session));
        return true;
    }

    async void Create()
    {
        if (_busy)
            return;
        string password = _password.Text ?? "";
        string? problem = _size.Value is not >= 1 ? Strings.InvalidSize
            : password.Length < 8 ? Strings.PasswordTooShort
            : password != _repeat.Text ? Strings.PasswordsDiffer
            : null;
        Ui.ShowError(_error, problem);
        if (problem is not null)
            return;
        long size = (long)_size.Value!.Value << 20;
        _busy = true;
        try
        {
            var (done, code) = await _main.WithSecurityKeyAsync(Strings.CreatingHiddenVault,
                key => _session.Vault.CreateHiddenVault(password, key, size));
            if (!done)
                return;
            try
            {
                await _session.SaveAsync(_main);
            }
            catch (Exception e)
            {
                await _main.AlertAsync(Strings.ErrorTitle, MobileStrings.CouldNotSave + "\n\n" + e.Message);
            }
            _main.Show(new RecoveryCodePage(_main, code, async () =>
            {
                await _main.AlertAsync(Strings.HiddenVault, Strings.HiddenVaultCreated);
                _main.ShowVault(_session);
            }));
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
