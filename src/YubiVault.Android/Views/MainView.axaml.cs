using Avalonia;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Animation;
using Avalonia.Animation.Easings;
using Avalonia.Styling;
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
            android.Backgrounded += OnBackgrounded;
            android.Foregrounded += OnForegrounded;
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

    /// <summary>Redraws the start page in the language just chosen (pages read their texts when built).</summary>
    internal void Relocalize()
    {
        FlowDirection = Ui.IsRightToLeft ? FlowDirection.RightToLeft : FlowDirection.LeftToRight;
        ShowStart();
    }

    internal void ShowVault(VaultSession session)
    {
        Session = session;
        Show(new VaultPage(this, session));
        if (_inBackground)
            RequestLock(); // the unlock finished after the user had left the app
    }

    // ---- Locking ----

    /// <summary>How long a vault stays open while the user is in a picker or a viewer the app opened.</summary>
    static readonly TimeSpan OtherAppGrace = TimeSpan.FromMinutes(5);

    bool _inBackground, _lockPending;
    int _steps;
    DateTime _leftAt;
    IDisposable? _lockTimer;

    /// <summary>Locks the vault (writing back anything pending) and returns to the start page.</summary>
    internal async Task LockAsync()
    {
        _lockPending = false;
        var session = Session;
        if (session is null)
            return;
        Session = null;
        await session.LockAsync(this);
        // A new recovery code stays on screen until the user has stored it; it is not vault content.
        if (PageHost.Content is not RecoveryCodePage)
            ShowStart();
    }

    /// <summary>Pages call these around each step that uses the vault, so a lock never cuts one in half.</summary>
    internal void BeginStep() => _steps++;

    internal void EndStep()
    {
        if (--_steps == 0 && _lockPending)
            _ = LockAsync();
    }

    /// <summary>
    /// Leaving the app locks the vault at once. A trip the app started itself (picking files, viewing a
    /// decrypted file) gets a few minutes before it locks, or the file would vanish under the viewer.
    /// </summary>
    void OnBackgrounded()
    {
        _inBackground = true;
        bool otherApp = Platform is AndroidPlatform android && android.TakeOtherAppOpened();
        if (Session is null)
            return;
        if (otherApp)
        {
            _leftAt = DateTime.UtcNow;
            _lockTimer?.Dispose();
            _lockTimer = DispatcherTimer.RunOnce(RequestLock, OtherAppGrace);
        }
        else
        {
            RequestLock();
        }
    }

    void OnForegrounded()
    {
        _inBackground = false;
        if (_lockTimer is null)
            return;
        _lockTimer.Dispose();
        _lockTimer = null;
        // Android may freeze a cached app, so the timer alone cannot be trusted to have fired.
        if (DateTime.UtcNow - _leftAt >= OtherAppGrace)
            RequestLock();
    }

    void RequestLock()
    {
        _lockTimer?.Dispose();
        _lockTimer = null;
        if (Session is null)
            return;
        _lockPending = true;
        // Cancel what waits on the user (pickers, dialogs, the key sheet); work behind a progress card finishes first.
        if (Platform is AndroidPlatform android)
            android.CancelPendingResults();
        foreach (var (_, onBack) in _overlays.ToList())
            onBack?.Invoke();
        if (_steps == 0)
            _ = LockAsync();
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
            ApplySafeArea(insets.SafeAreaPadding);
            insets.SafeAreaChanged += (_, args) => ApplySafeArea(args.SafeAreaPadding);
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

    Thickness _safeArea;

    /// <summary>
    /// Keeps pages and notices clear of the status and navigation bars, while the scrim and the
    /// bottom sheet reach the screen edges so no strip of another color shows around them.
    /// </summary>
    void ApplySafeArea(Thickness safeArea)
    {
        _safeArea = safeArea;
        PageHost.Margin = safeArea;
        Toast.Margin = new Thickness(24, 0, 24, 96 + safeArea.Bottom);
        foreach (var (card, _) in _overlays)
            FitToSafeArea(card);
    }

    void FitToSafeArea(Control card)
    {
        if (card is Border { VerticalAlignment: VerticalAlignment.Bottom } sheet)
            sheet.Padding = new Thickness(24, 12, 24, 24 + _safeArea.Bottom);
        else
            card.Margin = new Thickness(24 + _safeArea.Left, 24 + _safeArea.Top, 24 + _safeArea.Right, 24 + _safeArea.Bottom);
    }

    void PushOverlay(Control card, Action? onBack)
    {
        FitToSafeArea(card);
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

    /// <summary>A dialog card in the middle of the screen.</summary>
    static Border Card(params Control[] children)
    {
        var panel = new StackPanel { Spacing = 16 };
        foreach (var child in children)
            panel.Children.Add(child);
        return new Border
        {
            Child = panel,
            Padding = new Thickness(24),
            Margin = new Thickness(24),
            CornerRadius = new CornerRadius(28),
            MaxWidth = 480,
            VerticalAlignment = VerticalAlignment.Center,
            HorizontalAlignment = HorizontalAlignment.Stretch,
            BoxShadow = BoxShadows.Parse("0 8 32 0 #40000000"),
        }.WithBackground("AppSurfaceHighBrush");
    }

    /// <summary>A sheet that rises from the bottom edge, for what the user does with the security key.</summary>
    static Border Sheet(params Control[] children)
    {
        var panel = new StackPanel { Spacing = 14 };
        panel.Children.Add(new Border
        {
            Width = 32,
            Height = 4,
            CornerRadius = new CornerRadius(2),
            HorizontalAlignment = HorizontalAlignment.Center,
            Margin = new Thickness(0, 0, 0, 8),
            Opacity = 0.4,
        }.WithBackground("SystemControlForegroundBaseMediumBrush"));
        foreach (var child in children)
            panel.Children.Add(child);
        return new Border
        {
            Child = panel,
            Padding = new Thickness(24, 12, 24, 24),
            CornerRadius = new CornerRadius(28, 28, 0, 0),
            MaxWidth = 560,
            VerticalAlignment = VerticalAlignment.Bottom,
            HorizontalAlignment = HorizontalAlignment.Stretch,
            BoxShadow = BoxShadows.Parse("0 -4 24 0 #30000000"),
        }.WithBackground("AppSurfaceHighBrush");
    }

    static TextBlock DialogTitle(string text) => Ui.Text(text, 22, FontWeight.SemiBold);

    static StackPanel ButtonRow(params Button[] buttons)
    {
        var row = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8, HorizontalAlignment = HorizontalAlignment.Right };
        foreach (var button in buttons)
        {
            button.HorizontalAlignment = HorizontalAlignment.Right;
            button.MinWidth = 88;
            button.MinHeight = Ui.TouchSize;
            row.Children.Add(button);
        }
        return row;
    }

    /// <summary>A small status card: a line of text over an indeterminate progress bar.</summary>
    static Border ProgressCard(string status) =>
        Card(Ui.Text(status, 16, FontWeight.SemiBold), new ProgressBar { IsIndeterminate = true, MinHeight = 4 });

    internal Task AlertAsync(string title, string message)
    {
        var done = new TaskCompletionSource();
        Border? card = null;
        void Close()
        {
            PopOverlay(card!);
            done.TrySetResult();
        }
        card = Card(DialogTitle(title), Ui.Text(message, opacity: 0.85), ButtonRow(Ui.Button(Strings.OK, Close, accent: true)));
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
            children.Add(DialogTitle(title));
        children.Add(Ui.Text(message, opacity: 0.85));
        children.Add(ButtonRow(Ui.TextButton(Strings.Cancel, () => Close(false)), Ui.Button(yes ?? Strings.OK, () => Close(true), accent: true)));
        card = Card([.. children]);
        PushOverlay(card, () => Close(false));
        return done.Task;
    }

    /// <summary>Asks for one line of text; null if cancelled.</summary>
    internal Task<string?> PromptAsync(string title, string message, string initial = "", bool secret = false, string? error = null)
    {
        var done = new TaskCompletionSource<string?>();
        var input = new TextBox { Text = initial };
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
            DialogTitle(title),
            Ui.Text(message, opacity: 0.85),
            errorText,
            input,
            ButtonRow(Ui.TextButton(Strings.Cancel, () => Close(null)), Ui.Button(Strings.OK, () =>
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
        var card = ProgressCard(status);
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
        var card = ProgressCard(status);
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
        var card = ProgressCard(status);
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
        var title = Ui.Text(status, 22, FontWeight.SemiBold);
        title.TextAlignment = TextAlignment.Center;
        var detail = Ui.Text("", opacity: 0.8);
        detail.TextAlignment = TextAlignment.Center;
        var badge = Ui.IconBadge(Platform.NfcAvailable ? Ui.NfcIcon : Ui.UsbIcon, 88);
        // A soft ring that breathes around the icon while the app waits on the key.
        var halo = new Border { Width = 128, Height = 128, CornerRadius = new CornerRadius(64), HorizontalAlignment = HorizontalAlignment.Center }
            .WithBackground("AppTonalBrush");
        var icon = new Panel { Width = 128, Height = 128, HorizontalAlignment = HorizontalAlignment.Center, Children = { halo, badge } };
        badge.VerticalAlignment = VerticalAlignment.Center;
        var cancelButton = Ui.TextButton(Strings.Cancel, cancel.Cancel);
        var card = Sheet(icon, title, detail, new ProgressBar { IsIndeterminate = true, MinHeight = 4, Margin = new Thickness(24, 4) }, cancelButton);
        var pulse = new Animation
        {
            Duration = TimeSpan.FromSeconds(1.4),
            IterationCount = IterationCount.Infinite,
            PlaybackDirection = PlaybackDirection.Alternate,
            Easing = new SineEaseInOut(),
            Children =
            {
                new KeyFrame { Cue = new Cue(0), Setters = { new Setter(OpacityProperty, 0.25) } },
                new KeyFrame { Cue = new Cue(1), Setters = { new Setter(OpacityProperty, 1.0) } },
            },
        };
        bool shown = false, finished = false;

        // Called from the worker thread; the sheet appears on the first update.
        void Update(string heading, string text, Geometry? glyph = null) => Dispatcher.UIThread.Post(() =>
        {
            if (finished)
                return;
            title.Text = heading;
            detail.Text = text;
            if (glyph is not null && badge.Child is PathIcon path)
                path.Data = glyph;
            if (!shown)
            {
                shown = true;
                PushOverlay(card, cancel.Cancel);
                _ = pulse.RunAsync(halo, cancel.Token);
            }
        });

        var key = new CtapSecurityKey(token =>
        {
            Update(MobileStrings.ConnectKeyTitle, Platform.NfcAvailable ? MobileStrings.ConnectKeyDetail : MobileStrings.ConnectKeyDetailUsb,
                Platform.NfcAvailable ? Ui.NfcIcon : Ui.UsbIcon);
            var connection = Platform.ConnectKeyAsync(token).GetAwaiter().GetResult();
            Update(status, connection.IsNfc ? MobileStrings.KeepHolding : MobileStrings.KeyWorking, connection.IsNfc ? Ui.NfcIcon : Ui.KeyIcon);
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
                waiting ? Strings.TouchKeyDetail : MobileStrings.KeyWorking, waiting ? Ui.TouchIcon : Ui.KeyIcon),
        };

        // New credentials get Android's own prompt, which asks for the PIN and the touch itself.
        var native = Platform is AndroidPlatform android ? new NativeSecurityKey(android.Activity, cancel.Token) : null;
        var phoneKey = new PhoneSecurityKey(native, key, reason =>
            Dispatcher.UIThread.Post(() => _ = AlertAsync(Strings.ErrorTitle, Ui.Format(MobileStrings.NativePromptFallback, reason))));

        try
        {
            return (true, await Task.Run(() => work(phoneKey)));
        }
        catch (OperationCanceledException)
        {
            return (false, default!);
        }
        catch (Exception e) when (cancel.IsCancellationRequested && e is VaultException or CtapException)
        {
            return (false, default!);
        }
        finally
        {
            finished = true;
            cancel.Cancel(); // also stops the pulse
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
