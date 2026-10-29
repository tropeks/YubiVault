using Avalonia;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Media;
using Avalonia.Threading;
using Microsoft.Win32;
using Yubico.YubiKey;
using YubiVault.App.Pages;
using YubiVault.App.Resources;
using YubiVault.Core;
using YubiVault.Core.Updates;

namespace YubiVault.App;

public partial class MainWindow : Window
{
    readonly DispatcherTimer _idleTimer = new() { Interval = TimeSpan.FromSeconds(15) };
    DateTime _lastActivityUtc = DateTime.UtcNow;
    Vault? _vault;
    bool _openedWithOtpKey;
    int _busyDepth;

    public MainWindow() : this(AppSettings.Load(), null) { }

    public MainWindow(AppSettings settings, string? vaultFile)
    {
        Settings = settings;
        InitializeComponent();
        ApplyFlowDirection();
        ShowStart(vaultFile);
        Updater.CleanUp();
        if (settings.CheckForUpdates && Updater.IsSupported)
            _ = CheckForUpdateAsync();

        AddHandler(KeyDownEvent, (_, _) => _lastActivityUtc = DateTime.UtcNow, RoutingStrategies.Tunnel, handledEventsToo: true);
        AddHandler(PointerMovedEvent, (_, _) => _lastActivityUtc = DateTime.UtcNow, RoutingStrategies.Tunnel, handledEventsToo: true);
        _idleTimer.Tick += (_, _) => LockIfIdle();
        _idleTimer.Start();
        if (OperatingSystem.IsWindows())
            SystemEvents.SessionSwitch += OnSessionSwitch;
        try
        {
            YubiKeyDeviceListener.Instance.Removed += OnYubiKeyRemoved;
        }
        catch (Exception)
        {
            // Device notifications are a convenience; locking still happens on idle and on session lock.
        }
    }

    public AppSettings Settings { get; }
    public TempFiles TempFiles { get; } = new();

    // ---- Updates ----

    readonly UpdateChecker _updates = new(UpdateChecker.CreateHttpClient());

    /// <summary>A newer signed release this copy can install, once the start-up check found one.</summary>
    public UpdateRelease? AvailableUpdate { get; private set; }

    async Task CheckForUpdateAsync()
    {
        try
        {
            var release = await _updates.FindNewerAsync(Updater.CurrentVersion);
            if (release is null || Updater.FileFor(release) is null)
                return;
            AvailableUpdate = release;
            if (Host.Content is StartPage start)
                start.ShowUpdate(release);
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException or UpdateException
                                      or System.Text.Json.JsonException)
        {
            // Offline, rate-limited or a release without a valid signature: simply no update offered.
            System.Diagnostics.Trace.WriteLine($"Update check: {e.Message}");
        }
    }

    /// <summary>Downloads, verifies and installs the available update, then restarts into it.</summary>
    public async void InstallUpdate()
    {
        if (AvailableUpdate is not { } release || Updater.FileFor(release) is not { } file)
            return;
        var progress = BusyProgress;
        try
        {
            await RunAsync(Strings.UpdateDownloading, () => Updater.InstallAsync(_updates, file,
                new Progress<double>(p => progress.Report($"{p:P0}"))).GetAwaiter().GetResult());
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException or UpdateException or IOException
                                      or UnauthorizedAccessException or InvalidDataException or InvalidOperationException
                                      or System.ComponentModel.Win32Exception)
        {
            await Dialogs.AlertAsync(this, Strings.UpdateFailed, e.Message);
            return;
        }
        Updater.Restart();
        Close();
    }

    // ---- Navigation ----

    public void ShowStart(string? vaultFile = null) => Host.Content = new StartPage(this, vaultFile);

    public void ShowCreate() => Host.Content = new CreatePage(this);

    public void ShowVault(Vault vault, bool openedWithOtpKey = false)
    {
        _vault = vault;
        _openedWithOtpKey = openedWithOtpKey;
        _lastActivityUtc = DateTime.UtcNow;
        Settings.RememberVault(vault.FilePath);
        Host.Content = new VaultPage(this, vault);
    }

    /// <summary>A vault file opened from the system (e.g. Finder) while the app runs.</summary>
    public void OpenFromSystem(string path)
    {
        if (_vault is null)
            ShowStart(path);
        Activate();
    }

    /// <summary>Re-reads every text after the language changed.</summary>
    public void ChangeLanguage(string code)
    {
        Settings.Language = code;
        Settings.Save();
        Localization.Apply(code);
        ApplyFlowDirection();
        ShowStart();
    }

    void ApplyFlowDirection() =>
        FlowDirection = Localization.IsRightToLeft ? FlowDirection.RightToLeft : FlowDirection.LeftToRight;

    /// <summary>Wipes the master key and temporary files and returns to the unlock screen.</summary>
    public void Lock()
    {
        if (_vault is null)
            return;
        string path = _vault.FilePath;
        _vault.Dispose();
        _vault = null;
        TempFiles.WipeAll();
        Dialogs.CloseAll();
        foreach (var window in OwnedWindows.ToList())
            window.Close();
        ShowStart(path);
    }

    void LockIfIdle()
    {
        if (_vault is null || _busyDepth > 0 || Settings.AutoLockMinutes <= 0)
            return;
        if (DateTime.UtcNow - _lastActivityUtc >= TimeSpan.FromMinutes(Settings.AutoLockMinutes))
            Lock();
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    void OnSessionSwitch(object? sender, SessionSwitchEventArgs e)
    {
        if (e.Reason is SessionSwitchReason.SessionLock or SessionSwitchReason.ConsoleDisconnect or SessionSwitchReason.RemoteDisconnect)
            Dispatcher.UIThread.Post(Lock);
    }

    void OnYubiKeyRemoved(object? sender, YubiKeyDeviceEventArgs e)
    {
        // Lock when the OTP YubiKey that opened the vault is pulled out. FIDO2 keys are only needed to unlock,
        // so for them locking relies on the idle timer and on the session being locked.
        Dispatcher.UIThread.Post(() =>
        {
            if (_vault is not null && _openedWithOtpKey && _busyDepth == 0 && !Keys.OtpYubiKeyConnected())
                Lock();
        });
    }

    protected override void OnClosing(WindowClosingEventArgs e)
    {
        _vault?.Dispose();
        TempFiles.WipeAll();
        if (OperatingSystem.IsWindows())
            SystemEvents.SessionSwitch -= OnSessionSwitch;
        base.OnClosing(e);
    }

    // ---- Busy overlay ----

    /// <summary>Runs <paramref name="work"/> off the UI thread behind the busy overlay.</summary>
    public async Task<T> RunAsync<T>(string title, Func<T> work)
    {
        BeginBusy(title);
        try
        {
            return await Task.Run(work);
        }
        finally
        {
            EndBusy();
        }
    }

    public Task RunAsync(string title, Action work) => RunAsync(title, () => { work(); return true; });

    /// <summary>Called from a background thread when the key waits for a touch (true) or stops waiting (false).</summary>
    public void ShowTouchPrompt(bool waiting = true) => Dispatcher.UIThread.Post(() =>
    {
        TouchIcon.IsVisible = waiting;
        BusyRing.IsVisible = !waiting;
        if (waiting)
        {
            BusyTitle.Text = Strings.TouchKeyTitle;
            BusyDetail.Text = Strings.TouchKeyDetail;
        }
    });

    /// <summary>Reports progress (e.g. the file being encrypted) from any thread.</summary>
    public IProgress<string> BusyProgress => new Progress<string>(text =>
    {
        TouchIcon.IsVisible = false;
        BusyRing.IsVisible = true;
        BusyDetail.Text = text;
    });

    void BeginBusy(string title)
    {
        _busyDepth++;
        TouchIcon.IsVisible = false;
        BusyRing.IsVisible = true;
        BusyTitle.Text = title;
        BusyDetail.Text = "";
        BusyOverlay.IsVisible = true;
    }

    void EndBusy()
    {
        _busyDepth--;
        _lastActivityUtc = DateTime.UtcNow;
        if (_busyDepth == 0)
            BusyOverlay.IsVisible = false;
    }
}
