using System.Security.Cryptography;
using System.Text;
using NSec.Cryptography;
using YubiVault.Core;

namespace YubiVault.Core.Crypto;

/// <summary>Derives key-encryption keys and wraps the vault master key with AES-256-GCM.</summary>
static class KeyWrap
{
    public const int MasterKeySize = 32;
    const int TagSize = 16;
    static readonly byte[] YubiKeyKekInfo = "YubiVault v1 yubikey kek"u8.ToArray();
    static readonly byte[] RecoveryKekInfo = "YubiVault v1 recovery kek"u8.ToArray();

    public static byte[] YubiKeyKek(ReadOnlySpan<byte> response, ReadOnlySpan<byte> challenge, string? password, Argon2Settings? argon2)
    {
        if ((password is null) != (argon2 is null))
            throw new ArgumentException("Password and Argon2 settings must be given together.");
        byte[] passwordHash = password is null ? [] : Argon2(Encoding.UTF8.GetBytes(password), argon2!);
        var ikm = new byte[response.Length + passwordHash.Length];
        try
        {
            response.CopyTo(ikm);
            passwordHash.CopyTo(ikm.AsSpan(response.Length));
            return HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, 32, challenge.ToArray(), YubiKeyKekInfo);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ikm);
            CryptographicOperations.ZeroMemory(passwordHash);
        }
    }

    public static byte[] RecoveryKek(ReadOnlySpan<byte> recoveryCode, Argon2Settings argon2)
    {
        byte[] stretched = Argon2(recoveryCode, argon2);
        try
        {
            return HKDF.DeriveKey(HashAlgorithmName.SHA256, stretched, 32, argon2.Salt, RecoveryKekInfo);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(stretched);
        }
    }

    public static Argon2Settings NewArgon2Settings(VaultOptions options) => new()
    {
        Salt = RandomNumberGenerator.GetBytes(16),
        MemoryKiB = options.Argon2MemoryKiB,
        Passes = options.Argon2Passes,
    };

    static byte[] Argon2(ReadOnlySpan<byte> secret, Argon2Settings settings)
    {
        var parameters = new Argon2Parameters
        {
            DegreeOfParallelism = 1,
            MemorySize = settings.MemoryKiB,
            NumberOfPasses = settings.Passes,
        };
        return PasswordBasedKeyDerivationAlgorithm.Argon2id(parameters).DeriveBytes(secret, settings.Salt, 32);
    }

    public static void Wrap(KeySlot slot, ReadOnlySpan<byte> kek, ReadOnlySpan<byte> masterKey, ReadOnlySpan<byte> vaultId)
    {
        slot.Nonce = RandomNumberGenerator.GetBytes(12);
        slot.WrappedKey = new byte[MasterKeySize + TagSize];
        using var aes = new AesGcm(kek, TagSize);
        aes.Encrypt(slot.Nonce, masterKey, slot.WrappedKey.AsSpan(0, MasterKeySize),
            slot.WrappedKey.AsSpan(MasterKeySize), AssociatedData(slot, vaultId));
    }

    /// <returns>The master key, or null when the key-encryption key is wrong.</returns>
    public static byte[]? Unwrap(KeySlot slot, ReadOnlySpan<byte> kek, ReadOnlySpan<byte> vaultId)
    {
        if (slot.WrappedKey.Length != MasterKeySize + TagSize || slot.Nonce.Length != 12)
            return null;
        var masterKey = new byte[MasterKeySize];
        using var aes = new AesGcm(kek, TagSize);
        try
        {
            aes.Decrypt(slot.Nonce, slot.WrappedKey.AsSpan(0, MasterKeySize), slot.WrappedKey.AsSpan(MasterKeySize),
                masterKey, AssociatedData(slot, vaultId));
            return masterKey;
        }
        catch (AuthenticationTagMismatchException)
        {
            return null;
        }
    }

    // Binds the wrapped key to its vault and slot, so slots cannot be moved between vaults or retyped.
    static byte[] AssociatedData(KeySlot slot, ReadOnlySpan<byte> vaultId) =>
        Encoding.UTF8.GetBytes($"YubiVault v1 slot|{Convert.ToBase64String(vaultId)}|{slot.Id}|{slot.Type}|{slot.RequiresPassword}");
}
