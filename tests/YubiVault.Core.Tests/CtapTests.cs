using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using YubiVault.Core.Keys;
using YubiVault.Fido2;

namespace YubiVault.Core.Tests;

public class CtapSecurityKeyTests : IDisposable
{
    readonly TempFolder _temp = new();
    string VaultFilePath => _temp["vault" + Vault.FileExtension];

    static CtapSecurityKey KeyFor(ICtapConnection connection, params string?[] pins)
    {
        var queue = new Queue<string?>(pins);
        return new CtapSecurityKey(_ => connection) { AskPin = _ => queue.Count > 0 ? queue.Dequeue() : null };
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    public void CreatesAndOpensAVault(int protocol)
    {
        var authenticator = new SoftwareAuthenticator("123456", protocol);
        var (vault, _) = Vault.Create(VaultFilePath, KeyFor(authenticator, "123456"), Fast.Options);
        vault.Dispose();
        Assert.Equal(2, authenticator.Touches);

        using var reopened = Vault.OpenWithFido2(VaultFilePath, KeyFor(authenticator, "123456"), Fast.Options);
        Assert.Equal(3, authenticator.Touches);
    }

    [Fact]
    public void ReturnsTheSecretWindowsWouldRead()
    {
        // Windows passes SHA-256("WebAuthn PRF" || 0x00 || salt) to hmac-secret, with the PIN verified.
        var authenticator = new SoftwareAuthenticator("1234");
        var key = KeyFor(authenticator, "1234");
        byte[] credentialId = key.MakeCredential("yubivault", [1, 2, 3], "vault");
        byte[] salt = RandomNumberGenerator.GetBytes(32);

        var (usedId, secret) = key.GetSecret("yubivault", [(credentialId, salt)]);

        byte[] prfSalt = SHA256.HashData([.. "WebAuthn PRF\0"u8.ToArray(), .. salt]);
        Assert.Equal(credentialId, usedId);
        Assert.Equal(authenticator.ExpectedSecret(credentialId, prfSalt, uv: true), secret);
    }

    [Fact]
    public void AsksForThePinOncePerOperation()
    {
        var authenticator = new SoftwareAuthenticator("1234");
        int asked = 0;
        var key = new CtapSecurityKey(_ => authenticator) { AskPin = _ => { asked++; return "1234"; } };
        Vault.Create(VaultFilePath, key, Fast.Options).Vault.Dispose();
        Assert.Equal(1, asked);
    }

    [Fact]
    public void AsksAgainAfterAWrongPinWithTheRetriesLeft()
    {
        var authenticator = new SoftwareAuthenticator("1234");
        Vault.Create(VaultFilePath, KeyFor(authenticator, "1234"), Fast.Options).Vault.Dispose();

        var retries = new List<int?>();
        var answers = new Queue<string>(["0000", "1234"]);
        var key = new CtapSecurityKey(_ => authenticator) { AskPin = r => { retries.Add(r); return answers.Dequeue(); } };
        using (Vault.OpenWithFido2(VaultFilePath, key, Fast.Options)) { }

        Assert.Equal([null, 7], retries);
        Assert.Equal(8, authenticator.PinRetries);
    }

    [Fact]
    public void CancellingThePinCancels()
    {
        var authenticator = new SoftwareAuthenticator("1234");
        Vault.Create(VaultFilePath, KeyFor(authenticator, "1234"), Fast.Options).Vault.Dispose();
        var e = Assert.Throws<VaultException>(() => Vault.OpenWithFido2(VaultFilePath, KeyFor(authenticator), Fast.Options));
        Assert.Equal("Cancelled.", e.Message);
    }

    [Fact]
    public void AnotherKeyIsRejected()
    {
        Vault.Create(VaultFilePath, KeyFor(new SoftwareAuthenticator("1234"), "1234"), Fast.Options).Vault.Dispose();
        Assert.Throws<WrongKeyException>(() =>
            Vault.OpenWithFido2(VaultFilePath, KeyFor(new SoftwareAuthenticator("1234"), "1234"), Fast.Options));
    }

    [Fact]
    public void ABackupKeyOpensTheVault()
    {
        var first = new SoftwareAuthenticator("1111");
        var backup = new SoftwareAuthenticator("2222", 1);
        var (vault, _) = Vault.Create(VaultFilePath, KeyFor(first, "1111"), Fast.Options);
        vault.AddSecurityKey(KeyFor(backup, "2222"));
        vault.Dispose();

        using (Vault.OpenWithFido2(VaultFilePath, KeyFor(backup, "2222"), Fast.Options)) { }
        using (Vault.OpenWithFido2(VaultFilePath, KeyFor(first, "1111"), Fast.Options)) { }
    }

    [Fact]
    public void ClosesEachConnection()
    {
        var authenticator = new SoftwareAuthenticator("1234");
        Vault.Create(VaultFilePath, KeyFor(authenticator, "1234"), Fast.Options).Vault.Dispose();
        Assert.True(authenticator.Disposed);
    }

    [Fact]
    public void RegistersAndReadsTheSecretOverOneConnection()
    {
        // Over NFC every connection is a tap, so creating a vault must not reconnect.
        var authenticator = new SoftwareAuthenticator("1234");
        int connections = 0;
        var key = new CtapSecurityKey(_ => { connections++; return authenticator; }) { AskPin = _ => "1234" };
        Vault.Create(VaultFilePath, key, Fast.Options).Vault.Dispose();
        Assert.Equal(1, connections);

        using (Vault.OpenWithFido2(VaultFilePath, KeyFor(authenticator, "1234"), Fast.Options)) { }
    }

    [Fact]
    public void AShortPinIsAskedAgainWithoutCostingARetry()
    {
        var authenticator = new SoftwareAuthenticator("1234");
        var answers = new Queue<string>(["12", "1234"]);
        int invalid = 0;
        var key = new CtapSecurityKey(_ => authenticator) { AskPin = _ => answers.Dequeue(), InvalidPin = () => invalid++ };
        Vault.Create(VaultFilePath, key, Fast.Options).Vault.Dispose();
        Assert.Equal(1, invalid);
        Assert.Equal(8, authenticator.PinRetries);
    }

    [Fact]
    public void KeepsOnlyTheHashOfThePinAndWipesIt()
    {
        var hash = PinHash.From("1234")!;
        Assert.Equal(SHA256.HashData("1234"u8.ToArray())[..16], hash.Copy());
        hash.Dispose();
        Assert.Throws<ObjectDisposedException>(() => hash.Copy());
        Assert.Null(PinHash.From("123"));
        Assert.Null(PinHash.From(new string('1', 64)));
    }

    public void Dispose() => _temp.Dispose();
}

public class CtapTransportTests
{
    [Fact]
    public void CanonicalCborSortsKeys()
    {
        var map = new CborMap().Add("type", "public-key").Add(-2, new byte[] { 1 }).Add(3, -25).Add(1, 2).Add("id", new byte[] { 9 });
        byte[] encoded = Cbor.Encode(map);
        var reader = new System.Formats.Cbor.CborReader(encoded, System.Formats.Cbor.CborConformanceMode.Ctap2Canonical);
        reader.SkipValue();
        Assert.Equal(0, reader.BytesRemaining);
    }

    [Fact]
    public void WorksOverUsbHidWithKeepalives()
    {
        var authenticator = new SoftwareAuthenticator("1234");
        var touches = new List<bool>();
        using var connection = new CtapHidConnection(new FakeHidDevice(authenticator));
        var key = new CtapSecurityKey(_ => connection) { AskPin = _ => "1234", TouchNotifier = touches.Add };
        byte[] credentialId = key.MakeCredential("yubivault", [1], "vault");
        var (_, secret) = key.GetSecret("yubivault", [(credentialId, new byte[32])]);
        Assert.Equal(32, secret.Length);
        Assert.Contains(true, touches);
        Assert.False(touches[^1]);
    }

    [Fact]
    public void WorksOverNfcWithChainingAndPolling()
    {
        var authenticator = new SoftwareAuthenticator("1234");
        var card = new FakeNfcCard(authenticator);
        var key = new CtapSecurityKey(_ => new CtapNfcConnection(card)) { AskPin = _ => "1234" };
        // A long credential list does not change much; a long user name makes the request span several APDUs.
        byte[] credentialId = key.MakeCredential("yubivault", [1], new string('x', 600));
        var (_, secret) = key.GetSecret("yubivault", [(credentialId, new byte[32])]);
        Assert.Equal(32, secret.Length);
        Assert.True(card.ChainedBlocks > 0);
        Assert.True(card.Polls > 0);
    }

    [Fact]
    public void ParsesAuthenticatorDataWithCredentialAndExtensions()
    {
        byte[] id = [5, 6, 7];
        byte[] coseKey = Cbor.Encode(new CborMap().Add(1, 2).Add(3, -7));
        byte[] extensions = Cbor.Encode(new CborMap().Add("hmac-secret", true));
        byte[] authData = [.. new byte[32], 0xC5, 0, 0, 0, 1, .. new byte[16], 0, 3, .. id, .. coseKey, .. extensions];
        var (credentialId, ext) = Ctap2Session.ParseAuthenticatorData(authData);
        Assert.Equal(id, credentialId);
        Assert.Equal(true, ext!.Get("hmac-secret"));
    }

    [Theory]
    [InlineData(40)] // credential flag set, data ends inside the AAGUID
    [InlineData(54)] // data ends inside the credential id length
    public void TruncatedAuthenticatorDataIsACtapError(int length)
    {
        byte[] authData = new byte[length];
        authData[32] = 0x41;
        Assert.Throws<CtapException>(() => Ctap2Session.ParseAuthenticatorData(authData));
    }

    [Fact]
    public void CredentialIdLongerThanTheDataIsACtapError()
    {
        byte[] authData = [.. new byte[32], 0x41, 0, 0, 0, 1, .. new byte[16], 0xFF, 0xFF, 1, 2, 3];
        Assert.Throws<CtapException>(() => Ctap2Session.ParseAuthenticatorData(authData));
    }

    [Fact]
    public void MalformedCborIsACtapError()
    {
        Assert.Throws<CtapException>(() => Cbor.DecodeMap(new byte[] { 0xA2, 0x01 })); // map of 2, cut short
        Assert.Throws<CtapException>(() => Cbor.DecodeMap(new byte[] { 0xFF }));
        byte[] deep = [.. Enumerable.Repeat((byte)0x81, 5000), 0x00]; // arrays nested 5000 deep
        Assert.Throws<CtapException>(() => Cbor.DecodeFirst(deep));
    }

    [Fact]
    public void ANfcKeyThatStaysBusyTimesOut()
    {
        var connection = new CtapNfcConnection(new ScriptedCard(_ => [0x91, 0x00])) { PollInterval = TimeSpan.FromMilliseconds(1) };
        Assert.Throws<CtapException>(() => connection.SendCbor([0x04], CancellationToken.None));
    }

    [Fact]
    public void ANfcKeyThatNeverStopsSendingIsCut()
    {
        var connection = new CtapNfcConnection(new ScriptedCard(_ => [.. new byte[250], 0x61, 0xFF]));
        Assert.Throws<CtapException>(() => connection.SendCbor([0x04], CancellationToken.None));
    }

    /// <summary>Selects the FIDO applet, then answers every other APDU with <paramref name="reply"/>.</summary>
    sealed class ScriptedCard(Func<byte[], byte[]> reply) : IApduChannel
    {
        public byte[] Transceive(byte[] apdu) => apdu[1] == 0xA4 ? [.. "FIDO_2_0"u8.ToArray(), 0x90, 0x00] : reply(apdu);

        public void Dispose() { }
    }

    /// <summary>A USB FIDO device: reassembles CTAPHID packets, answers INIT, and sends keepalives before each CBOR reply.</summary>
    sealed class FakeHidDevice(SoftwareAuthenticator authenticator) : IHidReportChannel
    {
        readonly Queue<byte[]> _out = new();
        readonly List<byte> _message = [];
        int _expected;
        byte _command;
        uint _channel;

        public void Write(byte[] report)
        {
            Assert.Equal(CtapHidConnection.ReportSize, report.Length);
            uint channel = BinaryPrimitives.ReadUInt32BigEndian(report);
            if ((report[4] & 0x80) != 0)
            {
                _channel = channel;
                _command = (byte)(report[4] & 0x7F);
                _expected = (report[5] << 8) | report[6];
                _message.Clear();
                _message.AddRange(report.AsSpan(7, Math.Min(_expected, 57)).ToArray());
            }
            else
            {
                _message.AddRange(report.AsSpan(5, Math.Min(_expected - _message.Count, 59)).ToArray());
            }
            if (_message.Count < _expected)
                return;
            switch (_command)
            {
                case 0x06:
                    Reply(_channel, 0x06, [.. _message, 0x12, 0x34, 0x56, 0x78, 2, 5, 4, 3, 0x05]);
                    break;
                case 0x10:
                    Reply(_channel, 0x3B, [1]);
                    Reply(_channel, 0x3B, [2]);
                    Reply(_channel, 0x10, authenticator.SendCbor([.. _message], CancellationToken.None));
                    break;
            }
        }

        void Reply(uint channel, byte command, byte[] data)
        {
            foreach (var packet in CtapHidConnection.Packets(channel, command, data))
                _out.Enqueue(packet);
        }

        public byte[]? Read(int timeoutMilliseconds) => _out.TryDequeue(out var report) ? report : null;

        public void Dispose() { }
    }

    /// <summary>An NFC FIDO card: needs chaining for long commands, answers 9100 once before each reply, and splits replies with 61xx.</summary>
    sealed class FakeNfcCard(SoftwareAuthenticator authenticator) : IApduChannel
    {
        readonly List<byte> _chained = [];
        byte[] _pending = [];
        bool _ready;
        public int ChainedBlocks { get; private set; }
        public int Polls { get; private set; }

        public byte[] Transceive(byte[] apdu)
        {
            byte cla = apdu[0], ins = apdu[1];
            if (ins == 0xA4)
                return [.. "FIDO_2_0"u8.ToArray(), 0x90, 0x00];
            if (ins == 0x10)
            {
                int length = apdu[4];
                Assert.True(length <= 255);
                _chained.AddRange(apdu.AsSpan(5, length).ToArray());
                if ((cla & 0x10) != 0)
                {
                    ChainedBlocks++;
                    return [0x90, 0x00];
                }
                _pending = authenticator.SendCbor([.. _chained], CancellationToken.None);
                _chained.Clear();
                _ready = false;
                return [0x91, 0x00];
            }
            if (ins == 0x11)
            {
                Polls++;
                _ready = true;
                return Next();
            }
            if (ins == 0xC0)
                return Next();
            throw new InvalidOperationException();
        }

        byte[] Next()
        {
            Assert.True(_ready);
            int count = Math.Min(_pending.Length, 100);
            byte[] chunk = _pending[..count];
            _pending = _pending[count..];
            return _pending.Length > 0
                ? [.. chunk, 0x61, (byte)Math.Min(_pending.Length, 255)]
                : [.. chunk, 0x90, 0x00];
        }

        public void Dispose() { }
    }
}

/// <summary>Checks the test authenticator's PIN protocols against the Yubico SDK's, so both sides follow the specification.</summary>
public class PinProtocolCrossCheckTests
{
    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    public void SoftwareAuthenticatorAgreesWithTheYubicoSdk(int protocol)
    {
        var authenticator = new SoftwareAuthenticator("1234", protocol);
        using Yubico.YubiKey.Fido2.PinProtocols.PinUvAuthProtocolBase yubico = protocol == 1
            ? new Yubico.YubiKey.Fido2.PinProtocols.PinUvAuthProtocolOne()
            : new Yubico.YubiKey.Fido2.PinProtocols.PinUvAuthProtocolTwo();
        yubico.Encapsulate(new Yubico.YubiKey.Fido2.Cose.CoseEcPublicKey(authenticator.PublicKey));
        var platform = (Yubico.YubiKey.Fido2.Cose.CoseEcPublicKey)yubico.PlatformPublicKey!;

        byte[] shared = authenticator.SharedSecret(protocol, new()
        {
            [-2L] = platform.XCoordinate.ToArray(),
            [-3L] = platform.YCoordinate.ToArray(),
        });

        byte[] message = RandomNumberGenerator.GetBytes(32);
        PinProtocol ours = protocol == 1 ? new PinProtocolOne() : new PinProtocolTwo();
        Assert.Equal(yubico.Authenticate(message), ours.Authenticate(shared, message));
        byte[] encrypted = yubico.Encrypt(message, 0, message.Length);
        Assert.Equal(message, ours.Decrypt(shared, encrypted));
        Assert.Equal(message, SoftwareAuthenticator.Decrypt(protocol, shared, encrypted));
        byte[] ourCiphertext = ours.Encrypt(shared, message);
        Assert.Equal(message, yubico.Decrypt(ourCiphertext, 0, ourCiphertext.Length));
    }
}
