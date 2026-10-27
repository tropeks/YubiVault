namespace YubiVault.Fido2;

/// <summary>An open channel to one security key that carries CTAP2 messages (USB HID or NFC).</summary>
public interface ICtapConnection : IDisposable
{
    /// <summary>
    /// Sends a CTAP2 command (command byte followed by its CBOR parameters) and returns the response
    /// (status byte followed by CBOR). Blocks while the key waits for a touch.
    /// </summary>
    byte[] SendCbor(byte[] request, CancellationToken cancellationToken);

    /// <summary>True over NFC, where holding the key to the phone counts as the touch.</summary>
    bool IsNfc { get; }

    /// <summary>Called with true when the key starts waiting for a touch, and with false when it stops.</summary>
    Action<bool>? TouchNotifier { get; set; }
}
