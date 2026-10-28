using Avalonia.Controls;
using Avalonia.Media;
using YubiVault.Android.Resources;
using YubiVault.Core;

namespace YubiVault.Android.Views;

/// <summary>Creates a vault: name, where to save it, then the security key; ends on the recovery code.</summary>
sealed class CreatePage : UserControl, IBackHandler
{
    readonly MainView _main;
    readonly TextBox _name = new();
    readonly TextBlock _error = Ui.Error();
    bool _busy;

    public CreatePage(MainView main)
    {
        _main = main;
        _name.Text = Strings.DefaultVaultName;
        _name.Watermark = Strings.VaultNamePlaceholder;
        var notice = new Border
        {
            Padding = new Avalonia.Thickness(14),
            CornerRadius = new Avalonia.CornerRadius(16),
            Child = new StackPanel
            {
                Spacing = 6,
                Children = { Ui.Text(Strings.RecoveryNoticeTitle, 15, FontWeight.SemiBold), Ui.Hint(Strings.RecoveryNoticeText) },
            },
        }.WithBackground("AppSurfaceBrush");

        Content = Ui.Page(
            Ui.TopBar(Strings.CreateTitle, null, () => OnBack()),
            Ui.Column(
                Ui.Hint(MobileStrings.CreateIntroMobile),
                _name,
                Ui.Hint(Strings.KeyFido2Detail),
                notice,
                _error,
                Ui.Button(Strings.CreateButton, Create, accent: true, icon: Ui.KeyIcon)));
    }

    public bool OnBack()
    {
        if (!_busy)
            _main.ShowStart();
        return true;
    }

    async void Create()
    {
        if (_busy)
            return;
        Ui.ShowError(_error, null);
        string name = (_name.Text ?? "").Trim();
        if (name.EndsWith(Vault.FileExtension, StringComparison.OrdinalIgnoreCase))
            name = name[..^Vault.FileExtension.Length];
        if (name.Length == 0 || name.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 || name.IndexOfAny(['\\', ':', '*', '?', '"', '<', '>', '|']) >= 0)
        {
            Ui.ShowError(_error, Strings.InvalidName);
            return;
        }

        _busy = true;
        string? workingFolder = null;
        try
        {
            var document = await _main.Platform.CreateVaultDocumentAsync(name);
            if (document is null)
                return;
            // Vault works on a path: build the vault privately, then copy it into the chosen document.
            workingFolder = Path.Combine(Path.GetTempPath(), "yubivault-new", Guid.NewGuid().ToString("N"));
            string path = Path.Combine(workingFolder, name + Vault.FileExtension);
            var (done, created) = await _main.WithSecurityKeyAsync(Strings.RegisteringKey, key => Vault.Create(path, key));
            if (!done)
                return;
            var session = new VaultSession(created.Vault, document, path);
            workingFolder = null; // the session owns the working file now
            try
            {
                await session.SaveAsync(_main);
            }
            catch (Exception e)
            {
                await _main.AlertAsync(Strings.ErrorTitle, MobileStrings.CouldNotSave + "\n\n" + e.Message);
            }
            _main.Platform.AddRecent(document);
            _main.Show(new RecoveryCodePage(_main, created.RecoveryCode, () => _main.ShowVault(session)));
        }
        catch (Exception e)
        {
            Ui.ShowError(_error, Strings.CouldNotCreate + ": " + e.Message);
        }
        finally
        {
            _busy = false;
            if (workingFolder is not null)
            {
                try
                {
                    Directory.Delete(workingFolder, recursive: true);
                }
                catch (IOException)
                {
                }
            }
        }
    }
}
