using Android.App;
using Android.Content;
using Android.Content.PM;
using Android.Hardware.Usb;
using Android.OS;
using Avalonia;
using Avalonia.Android;
using YubiVault.Android.Platform;

namespace YubiVault.Android;

[Activity(
    Label = "YubiVault",
    Theme = "@style/YubiVaultTheme",
    Icon = "@mipmap/ic_launcher",
    RoundIcon = "@mipmap/ic_launcher_round",
    MainLauncher = true,
    Exported = true,
    LaunchMode = LaunchMode.SingleTask,
    ConfigurationChanges = ConfigChanges.Orientation | ConfigChanges.ScreenSize | ConfigChanges.UiMode
        | ConfigChanges.ScreenLayout | ConfigChanges.SmallestScreenSize | ConfigChanges.Keyboard
        | ConfigChanges.KeyboardHidden | ConfigChanges.Navigation | ConfigChanges.Density)]
// Plugging in a Yubico key offers to open the app (and grants it USB access to that key).
[IntentFilter([UsbManager.ActionUsbDeviceAttached])]
[MetaData(UsbManager.ActionUsbDeviceAttached, Resource = "@xml/device_filter")]
// .yvault files opened from a file manager or another app. Most providers send no useful MIME type.
[IntentFilter([Intent.ActionView], Categories = [Intent.CategoryDefault],
    DataSchemes = ["content", "file"], DataMimeType = "application/octet-stream")]
[IntentFilter([Intent.ActionView], Categories = [Intent.CategoryDefault],
    DataSchemes = ["content", "file"], DataHost = "*", DataMimeType = "*/*",
    DataPathPatterns = [".*\\.yvault", ".*\\..*\\.yvault", ".*\\..*\\..*\\.yvault", ".*\\..*\\..*\\..*\\.yvault"])]
public class MainActivity : AvaloniaMainActivity<App>
{
    protected override void OnCreate(Bundle? savedInstanceState)
    {
        AndroidPlatform.Attach(this);
        base.OnCreate(savedInstanceState);
        AndroidPlatform.Current.HandleIntent(Intent);
    }

    protected override void OnNewIntent(Intent? intent)
    {
        base.OnNewIntent(intent);
        AndroidPlatform.Current.HandleIntent(intent);
    }

    protected override void OnResume()
    {
        base.OnResume();
        AndroidPlatform.Current.OnResumed();
    }

    protected override void OnActivityResult(int requestCode, Result resultCode, Intent? data)
    {
        base.OnActivityResult(requestCode, resultCode, data);
        AndroidPlatform.Current.OnActivityResult(requestCode, resultCode, data);
    }

    protected override AppBuilder CustomizeAppBuilder(AppBuilder builder) => base.CustomizeAppBuilder(builder);
}
