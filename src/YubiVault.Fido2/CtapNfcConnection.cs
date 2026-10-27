namespace YubiVault.Fido2;

/// <summary>An ISO 7816 smart card link (ISO-DEP over NFC): sends a command APDU, returns the response with its status word.</summary>
public interface IApduChannel : IDisposable
{
    byte[] Transceive(byte[] apdu);
}

/// <summary>CTAP2 over NFC: the FIDO applet is selected, then each message goes in chained short APDUs.</summary>
public sealed class CtapNfcConnection : ICtapConnection
{
    static readonly byte[] SelectFido = [0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01, 0x00];
    const byte InsCtapMsg = 0x10, InsGetResponse = 0x11;

    readonly IApduChannel _card;

    public CtapNfcConnection(IApduChannel card)
    {
        _card = card;
        var (_, sw) = Exchange(SelectFido);
        if (sw != 0x9000)
            throw new CtapException("This NFC tag is not a FIDO security key.");
    }

    public bool IsNfc => true;

    public Action<bool>? TouchNotifier { get; set; }

    public byte[] SendCbor(byte[] request, CancellationToken cancellationToken)
    {
        // Command chaining: every block but the last has CLA bit 0x10 set.
        int offset = 0;
        while (request.Length - offset > 255)
        {
            var (_, chainSw) = Exchange([0x90, InsCtapMsg, 0x00, 0x00, 0xFF, .. request.AsSpan(offset, 255)]);
            if (chainSw != 0x9000)
                throw new CtapException($"The security key refused the NFC message (0x{chainSw:X4}).");
            offset += 255;
        }
        int rest = request.Length - offset;
        var (data, sw) = Exchange([0x80, InsCtapMsg, 0x00, 0x00, (byte)rest, .. request.AsSpan(offset, rest), 0x00]);
        // 0x9100: the key is still working (for example waiting for user presence); poll it.
        while (sw == 0x9100)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Thread.Sleep(100);
            (data, sw) = Exchange([0x80, InsGetResponse, 0x00, 0x00, 0x00]);
        }
        if (sw != 0x9000)
            throw new CtapException($"The security key refused the NFC message (0x{sw:X4}).");
        return data;
    }

    /// <summary>Sends one APDU and follows 61xx (more data) with GET RESPONSE.</summary>
    (byte[] Data, int Sw) Exchange(byte[] apdu)
    {
        var buffer = new List<byte>();
        byte[] response = _card.Transceive(apdu);
        while (true)
        {
            if (response.Length < 2)
                throw new CtapException("The security key sent a truncated NFC response.");
            int sw = (response[^2] << 8) | response[^1];
            buffer.AddRange(response.AsSpan(0, response.Length - 2));
            if ((sw >> 8) != 0x61)
                return (buffer.ToArray(), sw);
            response = _card.Transceive([0x00, 0xC0, 0x00, 0x00, (byte)(sw & 0xFF)]);
        }
    }

    public void Dispose() => _card.Dispose();
}
