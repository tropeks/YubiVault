using System.Buffers.Binary;
using System.Security.Cryptography;

namespace YubiVault.Fido2;

/// <summary>The raw 64-byte reports of a FIDO HID device, as the platform's USB API sees them.</summary>
public interface IHidReportChannel : IDisposable
{
    void Write(byte[] report);

    /// <summary>Reads one report; null on timeout.</summary>
    byte[]? Read(int timeoutMilliseconds);
}

/// <summary>CTAP2 over USB HID (CTAPHID): messages split into 64-byte packets on a channel of our own.</summary>
public sealed class CtapHidConnection : ICtapConnection
{
    public const int ReportSize = 64;
    const byte CmdCbor = 0x10, CmdInit = 0x06, CmdCancel = 0x11, CmdKeepalive = 0x3B, CmdError = 0x3F;
    const byte KeepaliveUpNeeded = 2;
    const uint BroadcastChannel = 0xFFFFFFFF;

    readonly IHidReportChannel _device;
    readonly uint _channel;

    public CtapHidConnection(IHidReportChannel device)
    {
        _device = device;
        byte[] nonce = RandomNumberGenerator.GetBytes(8);
        byte[] response = Transact(BroadcastChannel, CmdInit, nonce, CancellationToken.None, expectedCommand: CmdInit,
            accept: r => r.AsSpan(0, 8).SequenceEqual(nonce));
        if (response.Length < 17)
            throw new CtapException("The security key did not answer the USB handshake.");
        _channel = BinaryPrimitives.ReadUInt32BigEndian(response.AsSpan(8));
        bool hasCbor = (response[16] & 0x04) != 0;
        if (!hasCbor)
            throw new CtapException("This security key does not support FIDO2 (CTAP2).");
    }

    public bool IsNfc => false;

    public Action<bool>? TouchNotifier { get; set; }

    public byte[] SendCbor(byte[] request, CancellationToken cancellationToken)
    {
        bool waiting = false;
        try
        {
            return Transact(_channel, CmdCbor, request, cancellationToken, CmdCbor, onKeepalive: status =>
            {
                bool upNeeded = status == KeepaliveUpNeeded;
                if (upNeeded != waiting)
                {
                    waiting = upNeeded;
                    TouchNotifier?.Invoke(upNeeded);
                }
            });
        }
        finally
        {
            if (waiting)
                TouchNotifier?.Invoke(false);
        }
    }

    byte[] Transact(uint channel, byte command, byte[] payload, CancellationToken cancellationToken, byte expectedCommand,
        Action<byte>? onKeepalive = null, Func<byte[], bool>? accept = null)
    {
        foreach (var packet in Packets(channel, command, payload))
            _device.Write(packet);
        bool cancelSent = false;
        while (true)
        {
            if (cancellationToken.IsCancellationRequested && !cancelSent)
            {
                // The key answers a cancel with CTAP2_ERR_KEEPALIVE_CANCEL on the pending request.
                _device.Write(Packets(channel, CmdCancel, []).First());
                cancelSent = true;
            }
            var (cmd, data) = ReadMessage(channel, cancellationToken);
            if (cmd == CmdKeepalive)
            {
                onKeepalive?.Invoke(data.Length > 0 ? data[0] : (byte)0);
                continue;
            }
            if (cmd == CmdError)
                throw new CtapException($"The security key reported USB error 0x{(data.Length > 0 ? data[0] : 0):X2}.");
            if (cmd != expectedCommand || (accept is not null && !accept(data)))
                continue;
            if (cancelSent)
                throw new OperationCanceledException(cancellationToken);
            return data;
        }
    }

    (byte Command, byte[] Data) ReadMessage(uint channel, CancellationToken cancellationToken)
    {
        while (true)
        {
            var first = ReadReport(cancellationToken);
            if (BinaryPrimitives.ReadUInt32BigEndian(first) != channel || (first[4] & 0x80) == 0)
                continue;
            byte command = (byte)(first[4] & 0x7F);
            int length = (first[5] << 8) | first[6];
            var data = new byte[length];
            int copied = Math.Min(length, ReportSize - 7);
            Array.Copy(first, 7, data, 0, copied);
            for (byte sequence = 0; copied < length; sequence++)
            {
                var next = ReadReport(cancellationToken);
                if (BinaryPrimitives.ReadUInt32BigEndian(next) != channel)
                    continue;
                if (next[4] != sequence)
                    throw new CtapException("The security key sent USB packets out of order.");
                int count = Math.Min(length - copied, ReportSize - 5);
                Array.Copy(next, 5, data, copied, count);
                copied += count;
            }
            return (command, data);
        }
    }

    byte[] ReadReport(CancellationToken cancellationToken)
    {
        // Keepalives arrive every 100 ms or so while the key works; a long silence means it is gone.
        for (int i = 0; i < 30; i++)
        {
            var report = _device.Read(1000);
            if (report is not null)
                return report.Length >= ReportSize ? report : [.. report, .. new byte[ReportSize - report.Length]];
        }
        throw new CtapException("The security key stopped responding.");
    }

    internal static IEnumerable<byte[]> Packets(uint channel, byte command, byte[] payload)
    {
        var first = new byte[ReportSize];
        BinaryPrimitives.WriteUInt32BigEndian(first, channel);
        first[4] = (byte)(command | 0x80);
        first[5] = (byte)(payload.Length >> 8);
        first[6] = (byte)payload.Length;
        int sent = Math.Min(payload.Length, ReportSize - 7);
        payload.AsSpan(0, sent).CopyTo(first.AsSpan(7));
        yield return first;
        for (byte sequence = 0; sent < payload.Length; sequence++)
        {
            var next = new byte[ReportSize];
            BinaryPrimitives.WriteUInt32BigEndian(next, channel);
            next[4] = sequence;
            int count = Math.Min(payload.Length - sent, ReportSize - 5);
            payload.AsSpan(sent, count).CopyTo(next.AsSpan(5));
            sent += count;
            yield return next;
        }
    }

    public void Dispose() => _device.Dispose();
}
