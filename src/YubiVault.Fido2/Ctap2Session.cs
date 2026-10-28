using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace YubiVault.Fido2;

/// <summary>The CTAP2 commands YubiVault needs: getInfo, clientPIN, makeCredential and getAssertion with hmac-secret.</summary>
public sealed class Ctap2Session
{
    const byte CmdMakeCredential = 0x01, CmdGetAssertion = 0x02, CmdGetInfo = 0x04, CmdClientPin = 0x06;
    const byte PinGetRetries = 0x01, PinGetKeyAgreement = 0x02, PinGetPinToken = 0x05, PinGetTokenWithPermissions = 0x09;
    const int PermissionMakeCredential = 0x01, PermissionGetAssertion = 0x02;
    const string HmacSecret = "hmac-secret";

    readonly ICtapConnection _connection;
    readonly CancellationToken _cancellationToken;

    public Ctap2Session(ICtapConnection connection, CancellationToken cancellationToken = default)
    {
        _connection = connection;
        _cancellationToken = cancellationToken;
        var info = Send(CmdGetInfo, null);
        Extensions = (info.Get(2) as List<object>)?.OfType<string>().ToList() ?? [];
        Options = (info.Get(4) as CborMap)?.Where(o => o.Key is string && o.Value is bool)
            .ToDictionary(o => (string)o.Key, o => (bool)o.Value) ?? [];
        var protocols = (info.Get(6) as List<object>)?.OfType<long>().ToList() ?? [1];
        PinProtocol = protocols.Contains(2) ? new PinProtocolTwo() : new PinProtocolOne();
    }

    public IReadOnlyList<string> Extensions { get; }

    public IReadOnlyDictionary<string, bool> Options { get; }

    public PinProtocol PinProtocol { get; }

    public bool SupportsHmacSecret => Extensions.Contains(HmacSecret);

    /// <summary>True if a PIN is set; false if the key supports one but has none; null if it has no PIN at all.</summary>
    public bool? PinIsSet => Options.TryGetValue("clientPin", out bool set) ? set : null;

    public int GetPinRetries()
    {
        var response = Send(CmdClientPin, new CborMap().Add(1, PinProtocol.Version).Add(2, PinGetRetries));
        return response.Get(3) is long retries ? (int)retries : 0;
    }

    /// <summary>Runs ECDH with the key; the shared secret serves the PIN exchange and hmac-secret.</summary>
    internal (CborMap PlatformKey, byte[] SharedSecret) KeyAgreement()
    {
        var response = Send(CmdClientPin, new CborMap().Add(1, PinProtocol.Version).Add(2, PinGetKeyAgreement));
        var peer = response.Get(1) as CborMap ?? throw new CtapException("The security key sent no key agreement key.");
        return PinProtocol.Encapsulate(peer);
    }

    /// <summary>Exchanges the PIN for a token allowed to make credentials and get assertions for <paramref name="rpId"/>.</summary>
    public byte[] GetPinToken(string pin, string rpId)
    {
        var (platformKey, sharedSecret) = KeyAgreement();
        byte[] pinBytes = Encoding.UTF8.GetBytes(pin.Normalize(NormalizationForm.FormC));
        byte[] pinHash = SHA256.HashData(pinBytes)[..16];
        try
        {
            var request = new CborMap()
                .Add(1, PinProtocol.Version)
                .Add(3, platformKey)
                .Add(6, PinProtocol.Encrypt(sharedSecret, pinHash));
            if (Options.GetValueOrDefault("pinUvAuthToken"))
                request.Add(2, PinGetTokenWithPermissions).Add(9, PermissionMakeCredential | PermissionGetAssertion).Add(10, rpId);
            else
                request.Add(2, PinGetPinToken);
            var response = Send(CmdClientPin, request);
            var encrypted = response.Get(2) as byte[] ?? throw new CtapException("The security key sent no PIN token.");
            return PinProtocol.Decrypt(sharedSecret, encrypted);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pinBytes);
            CryptographicOperations.ZeroMemory(pinHash);
            CryptographicOperations.ZeroMemory(sharedSecret);
        }
    }

    /// <summary>Creates a non-discoverable ES256 credential with hmac-secret, verified with the PIN token; returns its id.</summary>
    public byte[] MakeCredential(string rpId, string rpName, byte[] userId, string userName, byte[] pinToken)
    {
        byte[] clientDataHash = RandomNumberGenerator.GetBytes(32);
        var request = new CborMap()
            .Add(1, clientDataHash)
            .Add(2, new CborMap().Add("id", rpId).Add("name", rpName))
            .Add(3, new CborMap().Add("id", userId).Add("name", userName).Add("displayName", userName))
            .Add(4, new[] { new CborMap().Add("alg", -7).Add("type", "public-key") })
            .Add(6, new CborMap().Add(HmacSecret, true))
            .Add(7, new CborMap().Add("rk", false))
            .Add(8, PinProtocol.Authenticate(pinToken, clientDataHash))
            .Add(9, PinProtocol.Version);
        var response = Send(CmdMakeCredential, request);
        var authData = response.Get(2) as byte[] ?? throw new CtapException("The security key sent no authenticator data.");
        var (credentialId, extensions) = ParseAuthenticatorData(authData);
        if (credentialId is null)
            throw new CtapException("The security key returned no credential.");
        if (extensions?.Get(HmacSecret) is not true)
            throw new CtapException("The security key did not enable hmac-secret for the credential.");
        return credentialId;
    }

    /// <summary>
    /// Gets an assertion for one credential and returns the decrypted hmac-secret output for
    /// <paramref name="salt"/> (32 bytes). Throws CtapException with NoCredentials if the credential is not on this key.
    /// </summary>
    public byte[] GetHmacSecret(string rpId, byte[] credentialId, byte[] salt, byte[] pinToken)
    {
        if (salt.Length != 32)
            throw new ArgumentException("The hmac-secret salt must be 32 bytes.", nameof(salt));
        var (platformKey, sharedSecret) = KeyAgreement();
        try
        {
            byte[] saltEnc = PinProtocol.Encrypt(sharedSecret, salt);
            var hmacInput = new CborMap()
                .Add(1, platformKey)
                .Add(2, saltEnc)
                .Add(3, PinProtocol.Authenticate(sharedSecret, saltEnc));
            if (PinProtocol.Version != 1)
                hmacInput.Add(4, PinProtocol.Version);
            byte[] clientDataHash = RandomNumberGenerator.GetBytes(32);
            var request = new CborMap()
                .Add(1, rpId)
                .Add(2, clientDataHash)
                .Add(3, new[] { new CborMap().Add("id", credentialId).Add("type", "public-key") })
                .Add(4, new CborMap().Add(HmacSecret, hmacInput))
                .Add(6, PinProtocol.Authenticate(pinToken, clientDataHash))
                .Add(7, PinProtocol.Version);
            var response = Send(CmdGetAssertion, request);
            var authData = response.Get(2) as byte[] ?? throw new CtapException("The security key sent no authenticator data.");
            var (_, extensions) = ParseAuthenticatorData(authData);
            if ((authData[32] & 0x04) == 0)
                throw new CtapException("The security key did not verify the PIN.");
            var output = extensions?.Get(HmacSecret) as byte[]
                ?? throw new CtapException("The security key did not return an hmac-secret.");
            byte[] secret = PinProtocol.Decrypt(sharedSecret, output);
            if (secret.Length < 32)
                throw new CtapException("The security key returned a short hmac-secret.");
            return secret[..32];
        }
        finally
        {
            CryptographicOperations.ZeroMemory(sharedSecret);
        }
    }

    /// <summary>Splits authenticator data into the attested credential id (if any) and the extension outputs (if any).</summary>
    internal static (byte[]? CredentialId, CborMap? Extensions) ParseAuthenticatorData(byte[] authData)
    {
        if (authData.Length < 37)
            throw new CtapException("The security key sent truncated authenticator data.");
        byte flags = authData[32];
        int offset = 37;
        byte[]? credentialId = null;
        if ((flags & 0x40) != 0)
        {
            offset += 16; // AAGUID
            int length = BinaryPrimitives.ReadUInt16BigEndian(authData.AsSpan(offset));
            offset += 2;
            credentialId = authData[offset..(offset + length)];
            offset += length;
            var (_, keyLength) = Cbor.DecodeFirst(authData.AsMemory(offset));
            offset += keyLength;
        }
        CborMap? extensions = null;
        if ((flags & 0x80) != 0)
            extensions = Cbor.DecodeFirst(authData.AsMemory(offset)).Value as CborMap;
        return (credentialId, extensions);
    }

    CborMap Send(byte command, CborMap? parameters)
    {
        byte[] request = parameters is null ? [command] : [command, .. Cbor.Encode(parameters)];
        byte[] response = _connection.SendCbor(request, _cancellationToken);
        if (response.Length == 0)
            throw new CtapException("The security key sent an empty response.");
        if (response[0] != CtapStatus.Ok)
            throw new CtapException(response[0]);
        return response.Length == 1 ? new CborMap() : Cbor.DecodeMap(response.AsMemory(1));
    }
}
