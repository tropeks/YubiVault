using System.Windows;
using System.Windows.Interop;
using YubiVault.Core;
using YubiVault.Core.Keys;
using YubiVault.YubiKey;

namespace YubiVault.App;

/// <summary>Picks the right kind of key for a vault, with messages a person can act on.</summary>
static class Keys
{
    /// <summary>A FIDO2 security key reached through Windows' own PIN and touch dialog.</summary>
    public static IFido2Authenticator SecurityKey(Window owner)
    {
        if (!WindowsSecurityKey.IsSupported(out string reason))
            throw new VaultException(reason);
        return new WindowsSecurityKey(new WindowInteropHelper(owner).Handle);
    }

    /// <summary>The one YubiKey with OTP challenge-response that is plugged in.</summary>
    /// <exception cref="VaultException">No key, or more than one.</exception>
    public static YubiKeyResponder OtpYubiKey(Action onTouch)
    {
        var keys = YubiKeyResponder.FindAll();
        if (keys.Count == 0)
            throw new VaultException("No YubiKey with OTP found. Security Key models have no OTP; use a FIDO2 security key instead.");
        if (keys.Count > 1)
            throw new VaultException("More than one YubiKey is connected. Leave only one plugged in.");
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
