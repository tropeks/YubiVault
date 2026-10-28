using System.Security.Cryptography;

namespace YubiVault.Fido2;

/// <summary>
/// A CTAP2 PIN/UV auth protocol (1 or 2): the ECDH key agreement with the key and the shared-secret
/// operations used for the PIN and for hmac-secret.
/// </summary>
public abstract class PinProtocol
{
    public abstract int Version { get; }

    /// <summary>
    /// Agrees on a shared secret with the key's public key (a COSE map from getKeyAgreement).
    /// Returns our public key as a COSE map, to send along, and the shared secret.
    /// </summary>
    internal (CborMap PlatformKey, byte[] SharedSecret) Encapsulate(CborMap peerCoseKey)
    {
        var peerX = peerCoseKey.Get(-2) as byte[];
        var peerY = peerCoseKey.Get(-3) as byte[];
        if (peerX is not { Length: 32 } || peerY is not { Length: 32 })
            throw new CtapException("The security key sent an invalid key agreement key.");
        using var ours = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        using var peer = ECDiffieHellman.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint { X = peerX, Y = peerY },
        });
        byte[] z = ours.DeriveRawSecretAgreement(peer.PublicKey);
        try
        {
            var q = ours.ExportParameters(false).Q;
            var platformKey = new CborMap().Add(1, 2).Add(3, -25).Add(-1, 1).Add(-2, q.X!).Add(-3, q.Y!);
            return (platformKey, Kdf(z));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(z);
        }
    }

    /// <summary>Turns the ECDH x-coordinate into the shared secret.</summary>
    protected abstract byte[] Kdf(byte[] z);

    public abstract byte[] Encrypt(byte[] sharedSecret, byte[] plaintext);

    public abstract byte[] Decrypt(byte[] sharedSecret, byte[] ciphertext);

    public abstract byte[] Authenticate(byte[] key, byte[] message);

    protected static byte[] AesCbc(byte[] key, byte[] iv, byte[] data, bool encrypt)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        return encrypt
            ? aes.EncryptCbc(data, iv, PaddingMode.None)
            : aes.DecryptCbc(data, iv, PaddingMode.None);
    }
}

/// <summary>PIN/UV auth protocol 1 (CTAP 2.0): SHA-256 of the ECDH secret, AES-CBC with a zero IV, 16-byte HMACs.</summary>
public sealed class PinProtocolOne : PinProtocol
{
    public override int Version => 1;

    protected override byte[] Kdf(byte[] z) => SHA256.HashData(z);

    public override byte[] Encrypt(byte[] sharedSecret, byte[] plaintext) => AesCbc(sharedSecret, new byte[16], plaintext, true);

    public override byte[] Decrypt(byte[] sharedSecret, byte[] ciphertext) => AesCbc(sharedSecret, new byte[16], ciphertext, false);

    public override byte[] Authenticate(byte[] key, byte[] message) => HMACSHA256.HashData(key, message)[..16];
}

/// <summary>
/// PIN/UV auth protocol 2 (CTAP 2.1): HKDF splits the ECDH secret into an HMAC key and an AES key,
/// ciphertexts carry a random IV, HMACs are 32 bytes.
/// </summary>
public sealed class PinProtocolTwo : PinProtocol
{
    public override int Version => 2;

    protected override byte[] Kdf(byte[] z)
    {
        byte[] salt = new byte[32];
        return
        [
            .. HKDF.DeriveKey(HashAlgorithmName.SHA256, z, 32, salt, "CTAP2 HMAC key"u8.ToArray()),
            .. HKDF.DeriveKey(HashAlgorithmName.SHA256, z, 32, salt, "CTAP2 AES key"u8.ToArray()),
        ];
    }

    public override byte[] Encrypt(byte[] sharedSecret, byte[] plaintext)
    {
        byte[] iv = RandomNumberGenerator.GetBytes(16);
        return [.. iv, .. AesCbc(sharedSecret[32..], iv, plaintext, true)];
    }

    public override byte[] Decrypt(byte[] sharedSecret, byte[] ciphertext)
    {
        if (ciphertext.Length < 16)
            throw new CtapException("The security key sent a truncated ciphertext.");
        return AesCbc(sharedSecret[32..], ciphertext[..16], ciphertext[16..], false);
    }

    /// <summary>The key is either a shared secret (its HMAC half is used) or a 32-byte PIN token.</summary>
    public override byte[] Authenticate(byte[] key, byte[] message) =>
        HMACSHA256.HashData(key.Length == 64 ? key[..32] : key, message);
}
