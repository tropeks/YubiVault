using Android.App;
using Android.Content;
using Android.Hardware.Usb;
using Android.OS;
using YubiVault.Fido2;

namespace YubiVault.Android.Platform;

/// <summary>Finds FIDO2 keys among the USB devices plugged into the phone and opens them.</summary>
static class UsbKeys
{
    const string ActionPermission = "io.github.tropeks.yubivault.USB_PERMISSION";
    const int FidoUsagePage = 0xF1D0;

    /// <summary>
    /// Opens the first FIDO HID device found, asking for USB permission if needed. Devices in
    /// <paramref name="skipped"/> (not FIDO, or permission refused) are not asked about again.
    /// </summary>
    public static async Task<ICtapConnection?> TryOpenAsync(Context context, HashSet<string> skipped, CancellationToken cancellationToken)
    {
        var manager = (UsbManager)context.GetSystemService(Context.UsbService)!;
        foreach (var device in manager.DeviceList?.Values ?? [])
        {
            if (skipped.Contains(device.DeviceName) || FindInterface(device) is not var (iface, input, output))
                continue;
            if (!manager.HasPermission(device) && !await RequestPermissionAsync(context, manager, device, cancellationToken))
            {
                skipped.Add(device.DeviceName);
                continue;
            }
            var connection = manager.OpenDevice(device);
            if (connection is null)
                continue;
            if (!connection.ClaimInterface(iface, true) || !IsFido(connection, iface))
            {
                connection.Close();
                skipped.Add(device.DeviceName);
                continue;
            }
            var channel = new UsbHidChannel(connection, iface, input, output);
            try
            {
                return new CtapHidConnection(channel);
            }
            catch (CtapException)
            {
                channel.Dispose();
                skipped.Add(device.DeviceName);
            }
        }
        return null;
    }

    /// <summary>A HID interface with one interrupt endpoint each way, like every FIDO key (keyboards have only an IN one).</summary>
    static (UsbInterface Interface, UsbEndpoint In, UsbEndpoint Out)? FindInterface(UsbDevice device)
    {
        for (int i = 0; i < device.InterfaceCount; i++)
        {
            var iface = device.GetInterface(i);
            if (iface.InterfaceClass != UsbClass.Hid)
                continue;
            UsbEndpoint? input = null, output = null;
            for (int e = 0; e < iface.EndpointCount; e++)
            {
                var endpoint = iface.GetEndpoint(e)!;
                if (endpoint.Type != UsbAddressing.XferInterrupt)
                    continue;
                if (endpoint.Direction == UsbAddressing.In)
                    input ??= endpoint;
                else
                    output ??= endpoint;
            }
            if (input is not null && output is not null)
                return (iface, input, output);
        }
        return null;
    }

    /// <summary>Reads the HID report descriptor and looks for the FIDO usage page (0xF1D0).</summary>
    static bool IsFido(UsbDeviceConnection connection, UsbInterface iface)
    {
        var buffer = new byte[1024];
        // bmRequestType 0x81 (device to host, standard, interface), GET_DESCRIPTOR, report descriptor.
        int length = connection.ControlTransfer((UsbAddressing)0x81, 0x06, 0x2200, iface.Id, buffer, buffer.Length, 1000);
        if (length <= 0)
            return true; // Cannot tell; the CTAPHID handshake decides.
        for (int i = 0; i + 2 < length; i++)
        {
            // Usage Page item with a 2-byte value: 0x06, low byte, high byte.
            if (buffer[i] == 0x06 && (buffer[i + 1] | (buffer[i + 2] << 8)) == FidoUsagePage)
                return true;
        }
        return false;
    }

    static async Task<bool> RequestPermissionAsync(Context context, UsbManager manager, UsbDevice device, CancellationToken cancellationToken)
    {
        var granted = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var receiver = new PermissionReceiver(device.DeviceName, granted);
        var filter = new IntentFilter(ActionPermission);
        if (OperatingSystem.IsAndroidVersionAtLeast(33))
            context.RegisterReceiver(receiver, filter, ReceiverFlags.NotExported);
        else
            context.RegisterReceiver(receiver, filter);
        try
        {
            // Mutable: the system adds the device and the answer to the intent. Explicit package, as Android 14 requires.
            var flags = OperatingSystem.IsAndroidVersionAtLeast(31) ? PendingIntentFlags.Mutable : 0;
            var intent = new Intent(ActionPermission).SetPackage(context.PackageName);
            manager.RequestPermission(device, PendingIntent.GetBroadcast(context, 0, intent, flags));
            using var registration = cancellationToken.Register(() => granted.TrySetCanceled(cancellationToken));
            return await granted.Task;
        }
        finally
        {
            context.UnregisterReceiver(receiver);
        }
    }

    sealed class PermissionReceiver(string deviceName, TaskCompletionSource<bool> granted) : BroadcastReceiver
    {
        public override void OnReceive(Context? context, Intent? intent)
        {
            var device = OperatingSystem.IsAndroidVersionAtLeast(33)
                ? intent?.GetParcelableExtra(UsbManager.ExtraDevice, Java.Lang.Class.FromType(typeof(UsbDevice))) as UsbDevice
#pragma warning disable CA1422
                : intent?.GetParcelableExtra(UsbManager.ExtraDevice) as UsbDevice;
#pragma warning restore CA1422
            if (device is not null && device.DeviceName != deviceName)
                return;
            granted.TrySetResult(intent?.GetBooleanExtra(UsbManager.ExtraPermissionGranted, false) == true);
        }
    }

    /// <summary>64-byte HID reports over the interface's interrupt endpoints.</summary>
    sealed class UsbHidChannel(UsbDeviceConnection connection, UsbInterface iface, UsbEndpoint input, UsbEndpoint output)
        : IHidReportChannel
    {
        public void Write(byte[] report)
        {
            if (connection.BulkTransfer(output, report, report.Length, 5000) < 0)
                throw new CtapException("Could not send to the security key. Is it still plugged in?");
        }

        public byte[]? Read(int timeoutMilliseconds)
        {
            var buffer = new byte[Math.Max(input.MaxPacketSize, CtapHidConnection.ReportSize)];
            int length = connection.BulkTransfer(input, buffer, buffer.Length, timeoutMilliseconds);
            return length > 0 ? buffer[..length] : null;
        }

        public void Dispose()
        {
            connection.ReleaseInterface(iface);
            connection.Close();
        }
    }
}
