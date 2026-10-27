using System.ComponentModel;
using System.Windows;
using System.Windows.Input;
using System.Windows.Threading;
using Microsoft.Win32;
using Yubico.YubiKey;
using YubiVault.App.Pages;
using YubiVault.Core;
using Wpf.Ui.Appearance;
using Wpf.Ui.Controls;

namespace YubiVault.App;

public partial class MainWindow : FluentWindow
{
    readonly DispatcherTimer _idleTimer = new() { Interval = TimeSpan.FromSeconds(15) };
    DateTime _lastActivityUtc = DateTime.UtcNow;
    Vault? _vault;
    bool _openedWithOtpKey;
    int _busyDepth;

    public MainWindow()
    {
        InitializeComponent();
        // Light or dark and the accent color follow Windows, also when they change while running.
        ApplicationThemeManager.ApplySystemTheme(updateAccent: true);
        SystemThemeWatcher.Watch(this, WindowBackdropType.Mica, updateAccents: true);
        Settings = AppSettings.Load();
        // A vault passed on the command line (e.g. a double-clicked .yvault file) is selected right away.
        string? argument = Environment.GetCommandLineArgs().Skip(1).FirstOrDefault();
        ShowStart(argument is not null && Vault.Exists(argument) ? argument : null);

        InputManager.Current.PreProcessInput += (_, _) => _lastActivityUtc = DateTime.UtcNow;
        _idleTimer.Tick += (_, _) => LockIfIdle();
        _idleTimer.Start();
        SystemEvents.SessionSwitch += OnSessionSwitch;
        try
        {
            YubiKeyDeviceListener.Instance.Removed += OnYubiKeyRemoved;
        }
        catch (Exception)
        {
            // Device notifications are a convenience; locking still happens on idle and on Windows lock.
        }
    }

    public AppSettings Settings { get; }
    public TempFiles TempFiles { get; } = new();

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

    /// <summary>Wipes the master key and temporary files and returns to the unlock screen.</summary>
    public void Lock()
    {
        if (_vault is null)
            return;
        string path = _vault.FilePath;
        _vault.Dispose();
        _vault = null;
        TempFiles.WipeAll();
        foreach (var window in OwnedWindows.Cast<Window>().ToList())
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

    void OnSessionSwitch(object? sender, SessionSwitchEventArgs e)
    {
        if (e.Reason is SessionSwitchReason.SessionLock or SessionSwitchReason.ConsoleDisconnect or SessionSwitchReason.RemoteDisconnect)
            Dispatcher.BeginInvoke(Lock);
    }

    void OnYubiKeyRemoved(object? sender, YubiKeyDeviceEventArgs e)
    {
        // Lock when the OTP YubiKey that opened the vault is pulled out. FIDO2 keys are only needed to unlock,
        // so for them locking relies on the idle timer and on Windows being locked.
        Dispatcher.BeginInvoke(() =>
        {
            if (_vault is not null && _openedWithOtpKey && _busyDepth == 0 && !Keys.OtpYubiKeyConnected())
                Lock();
        });
    }

    protected override void OnClosing(CancelEventArgs e)
    {
        _vault?.Dispose();
        TempFiles.WipeAll();
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

    /// <summary>Called from a background thread when the YubiKey waits for a touch.</summary>
    public void ShowTouchPrompt() => Dispatcher.Invoke(() =>
    {
        TouchIcon.Visibility = Visibility.Visible;
        BusyRing.Visibility = Visibility.Collapsed;
        BusyTitle.Text = "Touch your YubiKey";
        BusyDetail.Text = "The key is blinking and waiting for your touch.";
    });

    /// <summary>Reports progress (e.g. the file being encrypted) from any thread.</summary>
    public IProgress<string> BusyProgress => new Progress<string>(text =>
    {
        TouchIcon.Visibility = Visibility.Collapsed;
        BusyRing.Visibility = Visibility.Visible;
        BusyDetail.Text = text;
    });

    void BeginBusy(string title)
    {
        _busyDepth++;
        TouchIcon.Visibility = Visibility.Collapsed;
        BusyRing.Visibility = Visibility.Visible;
        BusyTitle.Text = title;
        BusyDetail.Text = "";
        BusyOverlay.Visibility = Visibility.Visible;
    }

    void EndBusy()
    {
        _busyDepth--;
        _lastActivityUtc = DateTime.UtcNow;
        if (_busyDepth == 0)
            BusyOverlay.Visibility = Visibility.Collapsed;
    }
}
