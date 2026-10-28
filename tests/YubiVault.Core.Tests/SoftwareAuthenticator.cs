using System.Security.Cryptography;
using System.Text;
using YubiVault.Fido2;

namespace YubiVault.Core.Tests;

/// <summary>
/// A CTAP2.1 authenticator in software, written from the specification and independent of the client:
/// PIN protocols 1 and 2, makeCredential and getAssertion with hmac-secret. It speaks raw CBOR, as a key would.
/// </summary>
sealed class SoftwareAuthenticator : ICtapConnection
{
    readonly ECDiffieHellman _keyAgreement = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
    readonly byte[] _pinToken = RandomNumberGenerator.GetBytes(32);
    // CTAP 2.1: makeCredential withdraws the token's permissions until a new one is issued.
    bool _tokenSpent;
    readonly Dictionary<string, (string RpId, byte[] CredRandomWithUv, byte[] CredRandomWithoutUv)> _credentials = [];
    readonly int[] _protocols;
    string _pin;

    public SoftwareAuthenticator(string pin, params int[] protocols)
    {
        _pin = pin;
        _protocols = protocols.Length == 0 ? [2, 1] : protocols;
    }

    public int PinRetries { get; private set; } = 8;
    public int Touches { get; private set; }
    public bool IsNfc => false;
    public Action<bool>? TouchNotifier { get; set; }
    public bool Disposed { get; private set; }

    /// <summary>The hmac-secret output this key computes for a credential, salt (already PRF-hashed) and UV state.</summary>
    public byte[] ExpectedSecret(byte[] credentialId, byte[] salt, bool uv = true)
    {
        var credential = _credentials[Convert.ToHexString(credentialId)];
        return HMACSHA256.HashData(uv ? credential.CredRandomWithUv : credential.CredRandomWithoutUv, salt);
    }

    public byte[] SendCbor(byte[] request, CancellationToken cancellationToken)
    {
        var parameters = request.Length > 1 ? Decode(request[1..]) : [];
        try
        {
            return request[0] switch
            {
                0x04 => Ok(GetInfo()),
                0x06 => Ok(ClientPin(parameters)),
                0x01 => Ok(MakeCredential(parameters)),
                0x02 => Ok(GetAssertion(parameters)),
                _ => [0x01],
            };
        }
        catch (StatusException e)
        {
            return [e.Status];
        }
    }

    sealed class StatusException(byte status) : Exception
    {
        public byte Status { get; } = status;
    }

    static byte[] Ok(object response) => [0x00, .. Encode(response)];

    Dictionary<object, object> GetInfo() => new()
    {
        [1L] = new List<object> { "FIDO_2_0", "FIDO_2_1" },
        [2L] = new List<object> { "hmac-secret" },
        [3L] = new byte[16],
        [4L] = new Dictionary<object, object> { ["rk"] = true, ["clientPin"] = true, ["up"] = true, ["pinUvAuthToken"] = true },
        [6L] = _protocols.Select(p => (object)(long)p).ToList(),
    };

    Dictionary<object, object> ClientPin(Dictionary<object, object> p)
    {
        int protocol = (int)(long)p[1L];
        switch ((long)p[2L])
        {
            case 0x01:
                return new() { [3L] = (long)PinRetries };
            case 0x02:
                var q = _keyAgreement.ExportParameters(false).Q;
                return new() { [1L] = Cose(q.X!, q.Y!) };
            case 0x05:
            case 0x09:
                byte[] shared = SharedSecret(protocol, (Dictionary<object, object>)p[3L]);
                byte[] pinHash = Decrypt(protocol, shared, (byte[])p[6L]);
                if (!pinHash.AsSpan().SequenceEqual(SHA256.HashData(Encoding.UTF8.GetBytes(_pin)).AsSpan(0, 16)))
                {
                    PinRetries--;
                    throw new StatusException(PinRetries == 0 ? CtapStatus.PinBlocked : CtapStatus.PinInvalid);
                }
                PinRetries = 8;
                _tokenSpent = false;
                return new() { [2L] = Encrypt(protocol, shared, _pinToken) };
            default:
                throw new StatusException(0x02);
        }
    }

    Dictionary<object, object> MakeCredential(Dictionary<object, object> p)
    {
        byte[] clientDataHash = (byte[])p[1L];
        int protocol = (int)(long)p[9L];
        CheckPinAuth(protocol, clientDataHash, (byte[])p[8L]);
        string rpId = (string)((Dictionary<object, object>)p[2L])["id"];
        bool hmacSecret = p.TryGetValue(6L, out var ext) && ((Dictionary<object, object>)ext).ContainsKey("hmac-secret");
        Touch();
        _tokenSpent = true;
        byte[] id = RandomNumberGenerator.GetBytes(48);
        _credentials[Convert.ToHexString(id)] = (rpId, RandomNumberGenerator.GetBytes(32), RandomNumberGenerator.GetBytes(32));

        using var credentialKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var q = credentialKey.ExportParameters(false).Q;
        var publicKey = Encode(new Dictionary<object, object> { [1L] = 2L, [3L] = -7L, [-1L] = 1L, [-2L] = q.X!, [-3L] = q.Y! });
        byte flags = (byte)(0x01 | 0x04 | 0x40 | (hmacSecret ? 0x80 : 0));
        byte[] authData =
        [
            .. SHA256.HashData(Encoding.UTF8.GetBytes(rpId)), flags, 0, 0, 0, 1,
            .. new byte[16], (byte)(id.Length >> 8), (byte)id.Length, .. id, .. publicKey,
            .. hmacSecret ? Encode(new Dictionary<object, object> { ["hmac-secret"] = true }) : [],
        ];
        return new() { [1L] = "none", [2L] = authData, [3L] = new Dictionary<object, object>() };
    }

    Dictionary<object, object> GetAssertion(Dictionary<object, object> p)
    {
        string rpId = (string)p[1L];
        byte[] clientDataHash = (byte[])p[2L];
        var allowed = ((List<object>)p[3L]).Cast<Dictionary<object, object>>().Select(c => (byte[])c["id"]);
        byte[]? id = allowed.FirstOrDefault(c => _credentials.TryGetValue(Convert.ToHexString(c), out var cred) && cred.RpId == rpId)
            ?? throw new StatusException(CtapStatus.NoCredentials);
        bool uv = p.ContainsKey(6L);
        if (uv)
            CheckPinAuth((int)(long)p[7L], clientDataHash, (byte[])p[6L]);
        Touch();

        byte[] extensions = [];
        if (p.TryGetValue(4L, out var ext) && ((Dictionary<object, object>)ext).TryGetValue("hmac-secret", out var input))
        {
            var h = (Dictionary<object, object>)input;
            int protocol = h.TryGetValue(4L, out var proto) ? (int)(long)proto : 1;
            byte[] shared = SharedSecret(protocol, (Dictionary<object, object>)h[1L]);
            byte[] saltEnc = (byte[])h[2L];
            if (!Authenticate(protocol, shared, saltEnc).AsSpan().SequenceEqual((byte[])h[3L]))
                throw new StatusException(CtapStatus.PinAuthInvalid);
            byte[] salt = Decrypt(protocol, shared, saltEnc);
            byte[] output = ExpectedSecret(id, salt, uv);
            extensions = Encode(new Dictionary<object, object> { ["hmac-secret"] = Encrypt(protocol, shared, output) });
        }
        byte flags = (byte)(0x01 | (uv ? 0x04 : 0) | (extensions.Length > 0 ? 0x80 : 0));
        byte[] authData = [.. SHA256.HashData(Encoding.UTF8.GetBytes(rpId)), flags, 0, 0, 0, 2, .. extensions];
        return new()
        {
            [1L] = new Dictionary<object, object> { ["id"] = id, ["type"] = "public-key" },
            [2L] = authData,
            [3L] = new byte[64],
        };
    }

    void Touch()
    {
        Touches++;
        TouchNotifier?.Invoke(true);
        TouchNotifier?.Invoke(false);
    }

    void CheckPinAuth(int protocol, byte[] clientDataHash, byte[] pinUvAuthParam)
    {
        if (_tokenSpent)
            throw new StatusException(CtapStatus.PinAuthInvalid);
        if (!Authenticate(protocol, _pinToken, clientDataHash).AsSpan().SequenceEqual(pinUvAuthParam))
            throw new StatusException(CtapStatus.PinAuthInvalid);
    }

    static Dictionary<object, object> Cose(byte[] x, byte[] y) =>
        new() { [1L] = 2L, [3L] = -25L, [-1L] = 1L, [-2L] = x, [-3L] = y };

    /// <summary>The shared secret as the specification defines it, from our private key and the platform's COSE key.</summary>
    public byte[] SharedSecret(int protocol, Dictionary<object, object> platformKey)
    {
        using var peer = ECDiffieHellman.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint { X = (byte[])platformKey[-2L], Y = (byte[])platformKey[-3L] },
        });
        byte[] z = _keyAgreement.DeriveRawSecretAgreement(peer.PublicKey);
        if (protocol == 1)
            return SHA256.HashData(z);
        byte[] salt = new byte[32];
        return
        [
            .. HKDF.DeriveKey(HashAlgorithmName.SHA256, z, 32, salt, Encoding.ASCII.GetBytes("CTAP2 HMAC key")),
            .. HKDF.DeriveKey(HashAlgorithmName.SHA256, z, 32, salt, Encoding.ASCII.GetBytes("CTAP2 AES key")),
        ];
    }

    public ECParameters PublicKey => _keyAgreement.ExportParameters(false);

    static byte[] Encrypt(int protocol, byte[] shared, byte[] data)
    {
        using var aes = Aes.Create();
        if (protocol == 1)
        {
            aes.Key = shared;
            return aes.EncryptCbc(data, new byte[16], PaddingMode.None);
        }
        aes.Key = shared[32..];
        byte[] iv = RandomNumberGenerator.GetBytes(16);
        return [.. iv, .. aes.EncryptCbc(data, iv, PaddingMode.None)];
    }

    public static byte[] Decrypt(int protocol, byte[] shared, byte[] data)
    {
        using var aes = Aes.Create();
        if (protocol == 1)
        {
            aes.Key = shared;
            return aes.DecryptCbc(data, new byte[16], PaddingMode.None);
        }
        aes.Key = shared[32..];
        return aes.DecryptCbc(data[16..], data[..16], PaddingMode.None);
    }

    static byte[] Authenticate(int protocol, byte[] key, byte[] message) => protocol == 1
        ? HMACSHA256.HashData(key, message)[..16]
        : HMACSHA256.HashData(key.Length == 64 ? key[..32] : key, message);

    static Dictionary<object, object> Decode(byte[] data)
    {
        var reader = new System.Formats.Cbor.CborReader(data, System.Formats.Cbor.CborConformanceMode.Ctap2Canonical);
        return (Dictionary<object, object>)Read(reader);
    }

    static object Read(System.Formats.Cbor.CborReader reader)
    {
        switch (reader.PeekState())
        {
            case System.Formats.Cbor.CborReaderState.UnsignedInteger:
            case System.Formats.Cbor.CborReaderState.NegativeInteger:
                return reader.ReadInt64();
            case System.Formats.Cbor.CborReaderState.ByteString:
                return reader.ReadByteString();
            case System.Formats.Cbor.CborReaderState.TextString:
                return reader.ReadTextString();
            case System.Formats.Cbor.CborReaderState.Boolean:
                return reader.ReadBoolean();
            case System.Formats.Cbor.CborReaderState.StartArray:
                reader.ReadStartArray();
                var list = new List<object>();
                while (reader.PeekState() != System.Formats.Cbor.CborReaderState.EndArray)
                    list.Add(Read(reader));
                reader.ReadEndArray();
                return list;
            case System.Formats.Cbor.CborReaderState.StartMap:
                reader.ReadStartMap();
                var map = new Dictionary<object, object>();
                while (reader.PeekState() != System.Formats.Cbor.CborReaderState.EndMap)
                {
                    var key = Read(reader);
                    map[key] = Read(reader);
                }
                reader.ReadEndMap();
                return map;
            default:
                throw new InvalidOperationException($"Unexpected CBOR {reader.PeekState()}");
        }
    }

    static byte[] Encode(object value)
    {
        var writer = new System.Formats.Cbor.CborWriter(System.Formats.Cbor.CborConformanceMode.Ctap2Canonical);
        Write(writer, value);
        return writer.Encode();
    }

    static void Write(System.Formats.Cbor.CborWriter writer, object value)
    {
        switch (value)
        {
            case long l: writer.WriteInt64(l); break;
            case bool b: writer.WriteBoolean(b); break;
            case string s: writer.WriteTextString(s); break;
            case byte[] bytes: writer.WriteByteString(bytes); break;
            case Dictionary<object, object> map:
                writer.WriteStartMap(map.Count);
                foreach (var (k, v) in map) { Write(writer, k); Write(writer, v); }
                writer.WriteEndMap();
                break;
            case List<object> list:
                writer.WriteStartArray(list.Count);
                foreach (var item in list) Write(writer, item);
                writer.WriteEndArray();
                break;
            default: throw new ArgumentException(value.GetType().Name);
        }
    }

    public void ChangePin(string pin) => _pin = pin;

    public void Dispose() => Disposed = true;
}
