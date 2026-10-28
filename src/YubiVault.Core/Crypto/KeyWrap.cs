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
    static readonly byte[] Fido2KekInfo = "YubiVault v1 fido2 kek"u8.ToArray();
    static readonly byte[] RecoveryKekInfo = "YubiVault v1 recovery kek"u8.ToArray();

    // Accepted Argon2id cost. The header is not authenticated, so a vault outside this range is refused
    // before any derivation runs. The app writes 64 MiB and 3 passes.
    public const long MinArgon2MemoryKiB = 8 * 1024;
    public const long MaxArgon2MemoryKiB = 1024 * 1024;
    public const long MinArgon2Passes = 1;
    public const long MaxArgon2Passes = 20;
    public const int MinArgon2SaltSize = 16;

    public static bool IsAcceptable(Argon2Settings settings) =>
        settings.MemoryKiB is >= MinArgon2MemoryKiB and <= MaxArgon2MemoryKiB
        && settings.Passes is >= MinArgon2Passes and <= MaxArgon2Passes
        && settings.Salt is { Length: >= MinArgon2SaltSize };

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

    public static byte[] Fido2Kek(ReadOnlySpan<byte> secret, ReadOnlySpan<byte> salt) =>
        HKDF.DeriveKey(HashAlgorithmName.SHA256, secret.ToArray(), 32, salt.ToArray(), Fido2KekInfo);

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

    /// <summary>
    /// Key that opens hidden vault slots: Argon2id of the hidden password or recovery code, with the
    /// vault's key-area salt and the options' cost, then HKDF with an info string per kind of secret.
    /// </summary>
    public static byte[] HiddenSlotKey(ReadOnlySpan<byte> secret, byte[] salt, VaultOptions options, ReadOnlySpan<byte> info)
    {
        byte[] stretched = Argon2(secret, new Argon2Settings { Salt = salt, MemoryKiB = options.Argon2MemoryKiB, Passes = options.Argon2Passes });
        try
        {
            return HKDF.DeriveKey(HashAlgorithmName.SHA256, stretched, 32, salt, info.ToArray());
        }
        finally
        {
            CryptographicOperations.ZeroMemory(stretched);
        }
    }

    /// <summary>KEK of a hidden vault opened by password and security key: both secrets are needed.</summary>
    public static byte[] HiddenFido2Kek(ReadOnlySpan<byte> secret, ReadOnlySpan<byte> slotKey, ReadOnlySpan<byte> salt)
    {
        byte[] ikm = [.. secret, .. slotKey];
        try
        {
            return HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, 32, salt.ToArray(), HiddenFido2KekInfo);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ikm);
        }
    }

    static readonly byte[] HiddenFido2KekInfo = "YubiVault v2 hidden fido2 kek"u8.ToArray();

    public static Argon2Settings NewArgon2Settings(VaultOptions options) => new()
    {
        Salt = RandomNumberGenerator.GetBytes(16),
        MemoryKiB = options.Argon2MemoryKiB,
        Passes = options.Argon2Passes,
    };

    static byte[] Argon2(ReadOnlySpan<byte> secret, Argon2Settings settings)
    {
        if (!IsAcceptable(settings))
            throw new VaultException("The Argon2id settings are outside the supported range.");
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
