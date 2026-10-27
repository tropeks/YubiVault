using Avalonia;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Threading;
using YubiVault.Android.Platform;
using YubiVault.Android.Resources;
using YubiVault.Core;
using YubiVault.Core.Keys;
using YubiVault.Fido2;

namespace YubiVault.Android.Views;

/// <summary>A page that wants to handle the Android back gesture itself; returns false to let it close the app.</summary>
interface IBackHandler
{
    bool OnBack();
}

/// <summary>
/// The app's only view: shows one page at a time and draws dialogs, progress and security key prompts
/// as cards over it (Android has no separate dialog windows here).
/// </summary>
public partial class MainView : UserControl
{
    readonly List<(Control Card, Action? OnBack)> _overlays = [];
    CancellationTokenSource? _toastTimer;
    TopLevel? _topLevel;

    public MainView(IPlatform platform)
    {
        Platform = platform;
        InitializeComponent();
        FlowDirection = Ui.IsRightToLeft ? FlowDirection.RightToLeft : FlowDirection.LeftToRight;
        WipeTempFolder();
        ShowStart();
        if (platform is AndroidPlatform android)
        {
            // A .yvault file opened from another app (Files, Drive, a mail attachment).
            android.OpenRequested += OpenFromOtherApp;
            if (android.TakePendingOpen() is { } document)
                OpenFromOtherApp(document);
        }
    }

    void OpenFromOtherApp(VaultDocument document)
    {
        // An unlocked vault stays as it is; the user can lock it and open the other one.
        if (Session is null)
            Show(new UnlockPage(this, document));
    }

    internal IPlatform Platform { get; }

    /// <summary>The vault that is unlocked right now, if any.</summary>
    internal VaultSession? Session { get; set; }

    // ---- Navigation ----

    internal void Show(Control page) => PageHost.Content = page;

    internal void ShowStart() => Show(new StartPage(this));

    internal void ShowVault(VaultSession session)
    {
        Session = session;
        Show(new VaultPage(this, session));
    }

    protected override void OnAttachedToVisualTree(VisualTreeAttachmentEventArgs e)
    {
        base.OnAttachedToVisualTree(e);
        _topLevel = TopLevel.GetTopLevel(this);
        if (_topLevel is null)
            return;
        _topLevel.BackRequested += OnBackRequested;
        if (_topLevel.InsetsManager is { } insets)
        {
            Root.Margin = insets.SafeAreaPadding;
            insets.SafeAreaChanged += (_, args) => Root.Margin = args.SafeAreaPadding;
        }
    }

    protected override void OnDetachedFromVisualTree(VisualTreeAttachmentEventArgs e)
    {
        if (_topLevel is not null)
            _topLevel.BackRequested -= OnBackRequested;
        base.OnDetachedFromVisualTree(e);
    }

    void OnBackRequested(object? sender, RoutedEventArgs e)
    {
        if (_overlays.Count > 0)
        {
            // Back closes the topmost card when it can be dismissed; progress cards cannot.
            _overlays[^1].OnBack?.Invoke();
            e.Handled = true;
            return;
        }
        if (PageHost.Content is IBackHandler handler && handler.OnBack())
            e.Handled = true;
    }

    // ---- Cards over the page ----

    void PushOverlay(Control card, Action? onBack)
    {
        if (_overlays.Count > 0)
            _overlays[^1].Card.IsVisible = false;
        _overlays.Add((card, onBack));
        OverlayHost.Children.Add(card);
        OverlayHost.IsVisible = true;
    }

    void PopOverlay(Control card)
    {
        int index = _overlays.FindIndex(o => o.Card == card);
        if (index < 0)
            return;
        _overlays.RemoveAt(index);
        OverlayHost.Children.Remove(card);
        if (_overlays.Count > 0)
            _overlays[^1].Card.IsVisible = true;
        else
            OverlayHost.IsVisible = false;
    }

    static Border Card(params Control[] children)
    {
        var panel = new StackPanel { Spacing = 14 };
        foreach (var child in children)
            panel.Children.Add(child);
        return new Border
        {
            Child = panel,
            Padding = new Thickness(20),
            Margin = new Thickness(20),
            CornerRadius = new CornerRadius(12),
            MaxWidth = 460,
            VerticalAlignment = VerticalAlignment.Center,
            HorizontalAlignment = HorizontalAlignment.Stretch,
        }.WithBackground("SystemControlBackgroundAltHighBrush");
    }

    static StackPanel ButtonRow(params Button[] buttons)
    {
        var row = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8, HorizontalAlignment = HorizontalAlignment.Right };
        foreach (var button in buttons)
        {
            button.HorizontalAlignment = HorizontalAlignment.Right;
            button.MinWidth = 96;
            row.Children.Add(button);
        }
        return row;
    }

    internal Task AlertAsync(string title, string message)
    {
        var done = new TaskCompletionSource();
        Border? card = null;
        void Close()
        {
            PopOverlay(card!);
            done.TrySetResult();
        }
        card = Card(Ui.Text(title, 18, FontWeight.SemiBold), Ui.Text(message), ButtonRow(Ui.Button(Strings.OK, Close, accent: true)));
        PushOverlay(card, Close);
        return done.Task;
    }

    internal Task ShowErrorAsync(Exception e) => AlertAsync(Strings.ErrorTitle, e.Message);

    internal Task<bool> ConfirmAsync(string message, string? yes = null, string? title = null)
    {
        var done = new TaskCompletionSource<bool>();
        Border? card = null;
        void Close(bool result)
        {
            PopOverlay(card!);
            done.TrySetResult(result);
        }
        var children = new List<Control>();
        if (title is not null)
            children.Add(Ui.Text(title, 18, FontWeight.SemiBold));
        children.Add(Ui.Text(message));
        children.Add(ButtonRow(Ui.Button(Strings.Cancel, () => Close(false)), Ui.Button(yes ?? Strings.OK, () => Close(true), accent: true)));
        card = Card([.. children]);
        PushOverlay(card, () => Close(false));
        return done.Task;
    }

    /// <summary>Asks for one line of text; null if cancelled.</summary>
    internal Task<string?> PromptAsync(string title, string message, string initial = "", bool secret = false, string? error = null)
    {
        var done = new TaskCompletionSource<string?>();
        var input = new TextBox { Text = initial, MinHeight = Ui.TouchSize, FontSize = 16 };
        if (secret)
            input.PasswordChar = '•';
        Border? card = null;
        void Close(string? result)
        {
            PopOverlay(card!);
            done.TrySetResult(result);
        }
        input.KeyDown += (_, e) =>
        {
            if (e.Key == Avalonia.Input.Key.Enter && !string.IsNullOrEmpty(input.Text))
                Close(input.Text);
        };
        var errorText = Ui.Error();
        Ui.ShowError(errorText, error);
        card = Card(
            Ui.Text(title, 18, FontWeight.SemiBold),
            Ui.Text(message),
            errorText,
            input,
            ButtonRow(Ui.Button(Strings.Cancel, () => Close(null)), Ui.Button(Strings.OK, () =>
            {
                if (!string.IsNullOrEmpty(input.Text))
                    Close(input.Text);
            }, accent: true)));
        PushOverlay(card, () => Close(null));
        input.AttachedToVisualTree += (_, _) => Dispatcher.UIThread.Post(() =>
        {
            input.Focus();
            input.SelectAll();
        });
        return done.Task;
    }

    /// <summary>Runs <paramref name="work"/> off the UI thread behind a progress card.</summary>
    internal async Task<T> RunAsync<T>(string status, Func<T> work)
    {
        var card = Card(Ui.Text(status), new ProgressBar { IsIndeterminate = true });
        PushOverlay(card, null);
        try
        {
            return await Task.Run(work);
        }
        finally
        {
            PopOverlay(card);
        }
    }

    internal Task RunAsync(string status, Action work) => RunAsync(status, () =>
    {
        work();
        return true;
    });

    /// <summary>Awaits asynchronous <paramref name="work"/> (platform file copies) behind a progress card.</summary>
    internal async Task<T> RunAsync<T>(string status, Func<Task<T>> work)
    {
        var card = Card(Ui.Text(status), new ProgressBar { IsIndeterminate = true });
        PushOverlay(card, null);
        try
        {
            return await work();
        }
        finally
        {
            PopOverlay(card);
        }
    }

    internal async Task RunAsync(string status, Func<Task> work)
    {
        var card = Card(Ui.Text(status), new ProgressBar { IsIndeterminate = true });
        PushOverlay(card, null);
        try
        {
            await work();
        }
        finally
        {
            PopOverlay(card);
        }
    }

    internal void ShowToast(string message)
    {
        _toastTimer?.Cancel();
        var timer = _toastTimer = new CancellationTokenSource();
        ToastText.Text = message;
        Toast.IsVisible = true;
        DispatcherTimer.RunOnce(() =>
        {
            if (!timer.IsCancellationRequested)
                Toast.IsVisible = false;
        }, TimeSpan.FromSeconds(Math.Clamp(message.Length / 15.0, 2.5, 7)));
    }

    // ---- Security key ----

    /// <summary>
    /// Runs <paramref name="work"/> with the user's security key: asks the PIN, waits for the key over USB
    /// or NFC and shows when to touch it. Returns false if the user cancelled.
    /// </summary>
    internal async Task<(bool Done, T Result)> WithSecurityKeyAsync<T>(string status, Func<IFido2Authenticator, T> work)
    {
        using var cancel = new CancellationTokenSource();
        var title = Ui.Text(status, 18, FontWeight.SemiBold);
        var detail = Ui.Text("");
        var card = Card(title, detail, new ProgressBar { IsIndeterminate = true },
            ButtonRow(Ui.Button(Strings.Cancel, cancel.Cancel)));
        bool shown = false, finished = false;

        // Called from the worker thread; the card appears on the first update.
        void Update(string heading, string text) => Dispatcher.UIThread.Post(() =>
        {
            if (finished)
                return;
            title.Text = heading;
            detail.Text = text;
            if (!shown)
            {
                shown = true;
                PushOverlay(card, cancel.Cancel);
            }
        });

        var key = new CtapSecurityKey(token =>
        {
            Update(MobileStrings.ConnectKeyTitle, Platform.NfcAvailable ? MobileStrings.ConnectKeyDetail : MobileStrings.ConnectKeyDetailUsb);
            var connection = Platform.ConnectKeyAsync(token).GetAwaiter().GetResult();
            Update(status, connection.IsNfc ? MobileStrings.KeepHolding : MobileStrings.KeyWorking);
            return connection;
        })
        {
            CancellationToken = cancel.Token,
            AskPin = retries =>
            {
                string? pin = Dispatcher.UIThread.InvokeAsync(() => PromptAsync(Strings.PinTitle, Strings.PinPrompt, secret: true,
                    error: retries is int left ? Ui.Format(Strings.PinRetry, left) : null)).GetAwaiter().GetResult();
                if (pin is null)
                    cancel.Cancel();
                return pin;
            },
            TouchNotifier = waiting => Update(waiting ? Strings.TouchKeyTitle : status,
                waiting ? Strings.TouchKeyDetail : MobileStrings.KeyWorking),
        };

        try
        {
            return (true, await Task.Run(() => work(key)));
        }
        catch (Exception e) when (cancel.IsCancellationRequested && e is VaultException or OperationCanceledException or CtapException)
        {
            return (false, default!);
        }
        finally
        {
            finished = true;
            if (shown)
                PopOverlay(card);
        }
    }

    // ---- Temp files ----

    /// <summary>Deletes decrypted copies of files; called at start-up and whenever a vault locks.</summary>
    internal void WipeTempFolder()
    {
        try
        {
            var folder = new DirectoryInfo(Platform.TempFolder);
            if (!folder.Exists)
                return;
            foreach (var file in folder.EnumerateFiles())
                file.Delete();
            foreach (var directory in folder.EnumerateDirectories())
                directory.Delete(recursive: true);
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }

    /// <summary>A fresh empty folder inside the temp folder for one decrypted file.</summary>
    internal string NewTempFolder()
    {
        string path = Path.Combine(Platform.TempFolder, Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        return path;
    }
}
