using Avalonia.Controls;
using YubiVault.App.Resources;
using YubiVault.Core;
using YubiVault.Core.Keys;
using YubiVault.YubiKey;

namespace YubiVault.App;

/// <summary>Picks the right kind of key for a vault, with messages a person can act on.</summary>
static class Keys
{
    /// <summary>
    /// A FIDO2 security key: through Windows' own PIN and touch dialog on Windows, and through the
    /// Yubico SDK with our own PIN prompt on Linux and macOS.
    /// </summary>
    public static IFido2Authenticator SecurityKey(Window owner, MainWindow main)
    {
        if (!OperatingSystem.IsWindows())
        {
            return new YubicoSecurityKey
            {
                AskPin = retries => Dialogs.AskPinFromWorker(owner, retries),
                TouchNotifier = waiting => main.ShowTouchPrompt(waiting),
            };
        }
        if (!WindowsSecurityKey.IsSupported(out string reason))
            throw new VaultException(reason);
        return new WindowsSecurityKey(owner.TryGetPlatformHandle()?.Handle ?? IntPtr.Zero);
    }

    /// <summary>True when the key's PIN is asked by the system (Windows) rather than by YubiVault.</summary>
    public static bool SystemAsksForPin => OperatingSystem.IsWindows();

    /// <summary>The one YubiKey with OTP challenge-response that is plugged in.</summary>
    /// <exception cref="VaultException">No key, or more than one.</exception>
    public static YubiKeyResponder OtpYubiKey(Action onTouch)
    {
        var keys = YubiKeyResponder.FindAll();
        if (keys.Count == 0)
            throw new VaultException(Strings.NoOtpKey);
        if (keys.Count > 1)
            throw new VaultException(Strings.MoreThanOneKey);
        keys[0].TouchNotifier = onTouch;
        return keys[0];
    }

    public static bool OtpYubiKeyConnected()
    {
        try
        {
            return YubiKeyResponder.FindAll().Count > 0;
        }
        catch (Exception)
        {
            return false;
        }
    }

    /// <summary>
    /// True when the vault should be opened with a FIDO2 key: it has a FIDO2 slot, and no OTP YubiKey
    /// that could open it instead is plugged in.
    /// </summary>
    public static bool PreferFido2(IReadOnlyList<KeySlot> slots)
    {
        bool hasFido2 = slots.Any(s => s.Type == KeySlotType.Fido2);
        bool hasOtp = slots.Any(s => s.Type == KeySlotType.YubiKey);
        return hasFido2 && !(hasOtp && OtpYubiKeyConnected());
    }
}
