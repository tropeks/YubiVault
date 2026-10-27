namespace YubiVault.Core.Keys;

/// <summary>A hardware token that answers an HMAC-SHA1 challenge with a secret it never reveals.</summary>
public interface IChallengeResponder
{
    /// <summary>Device serial number, when the device exposes it.</summary>
    int? SerialNumber { get; }

    /// <summary>Human-readable name, e.g. "YubiKey 5 NFC (12345678)".</summary>
    string Description { get; }

    /// <summary>Returns the HMAC-SHA1 response to <paramref name="challenge"/> (may wait for a touch).</summary>
    byte[] Respond(byte[] challenge);
}
