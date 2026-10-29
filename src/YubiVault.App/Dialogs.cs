using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Threading;
using FluentAvalonia.UI.Controls;
using YubiVault.App.Resources;

namespace YubiVault.App;

/// <summary>Message boxes and small prompts, drawn inside the window that asks.</summary>
static class Dialogs
{
    static ContentDialog? _open;

    /// <summary>Closes the dialog that is showing, if any (e.g. when the vault locks).</summary>
    public static void CloseAll() => _open?.Hide();

    /// <summary>
    /// What to tell the user about <paramref name="e"/>: its message, and, when that says nothing,
    /// its type and code, so a report still shows what went wrong.
    /// </summary>
    public static string Describe(Exception e)
    {
        var inner = e is AggregateException { InnerException: { } first } ? first : e;
        string message = inner.Message.Trim();
        string what = $"{inner.GetType().Name} (0x{inner.HResult:X8})";
        return message.Length == 0 ? what : $"{message}\n\n{what}";
    }

    public static Task AlertAsync(TopLevel owner, string title, string message) =>
        ShowAsync(owner, new ContentDialog
        {
            Title = title,
            Content = Text(message),
            CloseButtonText = Strings.OK,
            DefaultButton = ContentDialogButton.Close,
        });

    public static async Task<bool> ConfirmAsync(TopLevel owner, string message, string? yes = null) =>
        await ShowAsync(owner, new ContentDialog
        {
            Title = "YubiVault",
            Content = Text(message),
            PrimaryButtonText = yes ?? Strings.OK,
            CloseButtonText = Strings.Cancel,
            DefaultButton = ContentDialogButton.Primary,
        }) == ContentDialogResult.Primary;

    /// <returns>The text entered, or null when cancelled.</returns>
    public static async Task<string?> AskTextAsync(TopLevel owner, string title, string prompt, string initial = "",
        bool secret = false)
    {
        var input = new TextBox { Text = initial, MinWidth = 320 };
        if (secret)
        {
            input.PasswordChar = '●';
            input.Classes.Add("revealPasswordButton");
        }
        var dialog = new ContentDialog
        {
            Title = title,
            Content = new StackPanel { Spacing = 10, Children = { Text(prompt), input } },
            PrimaryButtonText = Strings.OK,
            CloseButtonText = Strings.Cancel,
            DefaultButton = ContentDialogButton.Primary,
        };
        dialog.Opened += (_, _) =>
        {
            input.Focus();
            input.SelectAll();
        };
        input.KeyDown += (_, e) =>
        {
            if (e.Key == Key.Enter)
            {
                dialog.Hide(ContentDialogResult.Primary);
                e.Handled = true;
            }
        };
        return await ShowAsync(owner, dialog) == ContentDialogResult.Primary ? input.Text ?? "" : null;
    }

    /// <summary>Asks the size and password of a new hidden vault, with what the user must know first.</summary>
    /// <returns>The size in MiB and the password, or null when cancelled.</returns>
    public static async Task<(long SizeMiB, string Password)?> AskHiddenVaultAsync(TopLevel owner)
    {
        var size = new NumericUpDown { Minimum = 1, Maximum = 1 << 20, Value = 256, Increment = 64, FormatString = "0", MinWidth = 160 };
        var password = new TextBox { Watermark = Strings.HiddenPassword, PasswordChar = '●', Classes = { "revealPasswordButton" } };
        var repeat = new TextBox { Watermark = Strings.RepeatPassword, PasswordChar = '●', Classes = { "revealPasswordButton" } };
        var error = new TextBlock { TextWrapping = TextWrapping.Wrap, IsVisible = false, Foreground = Brushes.IndianRed, MaxWidth = 480 };
        var dialog = new ContentDialog
        {
            Title = Strings.CreateHiddenVault,
            Content = new StackPanel
            {
                Spacing = 10,
                MaxWidth = 480,
                Children =
                {
                    Text(Strings.HiddenVaultIntro),
                    Text(Strings.HiddenVaultWarning),
                    new StackPanel
                    {
                        Orientation = Orientation.Horizontal, Spacing = 10, Margin = new(0, 6, 0, 0),
                        Children = { new TextBlock { Text = Strings.HiddenVaultSize, VerticalAlignment = VerticalAlignment.Center }, size },
                    },
                    password,
                    repeat,
                    error,
                },
            },
            PrimaryButtonText = Strings.CreateHiddenVault,
            CloseButtonText = Strings.Cancel,
            DefaultButton = ContentDialogButton.Primary,
        };
        dialog.PrimaryButtonClick += (_, e) =>
        {
            string? problem = size.Value is not >= 1 ? Strings.InvalidSize
                : (password.Text ?? "").Length < 8 ? Strings.PasswordTooShort
                : password.Text != repeat.Text ? Strings.PasswordsDiffer
                : null;
            error.Text = problem;
            error.IsVisible = problem is not null;
            e.Cancel = problem is not null;
        };
        dialog.Opened += (_, _) => password.Focus();
        if (await ShowAsync(owner, dialog) != ContentDialogResult.Primary)
            return null;
        return ((long)size.Value!.Value, password.Text!);
    }

    /// <summary>
    /// Asks for the security key's PIN from a background thread (the Yubico SDK asks while it works).
    /// </summary>
    /// <returns>The PIN, or null when cancelled.</returns>
    public static string? AskPinFromWorker(TopLevel owner, int? retriesLeft)
    {
        string prompt = retriesLeft is int left ? Localization.Format(Strings.PinRetry, left) : Strings.PinPrompt;
        return Dispatcher.UIThread.InvokeAsync(() => AskTextAsync(owner, Strings.PinTitle, prompt, secret: true))
            .GetAwaiter().GetResult();
    }

    /// <summary>Shows a new recovery code once; the dialog can only be closed after the user confirms saving it.</summary>
    public static async Task ShowRecoveryCodeAsync(TopLevel owner, string code)
    {
        var codeText = new SelectableTextBlock
        {
            Text = code, FontFamily = new FontFamily("Consolas, Menlo, DejaVu Sans Mono, monospace"), FontSize = 20,
            TextAlignment = TextAlignment.Center, TextWrapping = TextWrapping.Wrap,
        };
        bool copied = false;
        var copy = new Button { Content = Strings.Copy, Margin = new(0, 8, 0, 0) };
        copy.Click += async (_, _) =>
        {
            if (owner.Clipboard is { } clipboard)
            {
                await clipboard.SetTextAsync(code);
                copied = true;
            }
        };
        var saved = new CheckBox { Content = Strings.RecoverySaved, Margin = new(0, 16, 0, 0) };
        var dialog = new ContentDialog
        {
            Title = Strings.RecoveryTitle,
            Content = new StackPanel
            {
                MaxWidth = 480,
                Children =
                {
                    Text(Strings.RecoveryText),
                    Card(codeText),
                    copy,
                    saved,
                },
            },
            PrimaryButtonText = Strings.Continue,
            IsPrimaryButtonEnabled = false,
            DefaultButton = ContentDialogButton.Primary,
        };
        saved.IsCheckedChanged += (_, _) => dialog.IsPrimaryButtonEnabled = saved.IsChecked == true;
        // The code is shown only once: closing without confirming would lose it.
        dialog.Closing += (_, e) =>
        {
            if (saved.IsChecked != true)
                e.Cancel = true;
        };
        await ShowAsync(owner, dialog);
        if (copied && owner.Clipboard is { } board)
            await board.ClearAsync(); // don't leave the code on the clipboard
    }

    static async Task<ContentDialogResult> ShowAsync(TopLevel owner, ContentDialog dialog)
    {
        _open?.Hide();
        if (Localization.IsRightToLeft)
            dialog.FlowDirection = FlowDirection.RightToLeft;
        _open = dialog;
        try
        {
            return await dialog.ShowAsync(owner);
        }
        finally
        {
            if (_open == dialog)
                _open = null;
        }
    }

    static Border Card(Control child)
    {
        var border = new Border
        {
            Margin = new(0, 16, 0, 0), Padding = new(16), CornerRadius = new(8), BorderThickness = new(1), Child = child,
        };
        border.Bind(Border.BackgroundProperty, border.GetResourceObservable("CardBackgroundFillColorDefaultBrush"));
        border.Bind(Border.BorderBrushProperty, border.GetResourceObservable("CardStrokeColorDefaultBrush"));
        return border;
    }

    static TextBlock Text(string text) => new() { Text = text, TextWrapping = TextWrapping.Wrap, MaxWidth = 480 };
}
