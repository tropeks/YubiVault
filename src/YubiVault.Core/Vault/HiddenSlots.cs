using System.Security.Cryptography;
using System.Text;
using YubiVault.Core.Crypto;

namespace YubiVault.Core;

/// <summary>
/// The key slots of a hidden vault, stored in the random key area of the vault file. A slot is
/// nonce | AES-256-GCM(slot key, payload) | tag; unused slots are left random, so the area looks
/// the same whether a hidden vault exists or not.
/// </summary>
/// <remarks>
/// Key area: Argon2id salt (16 bytes), then <see cref="SlotCount"/> slots of <see cref="SlotSize"/> bytes.
/// Payloads: <c>1 | credential id length | credential id (256) | hmac-secret salt (32) | nonce (12) | wrapped master key (48)</c>
/// for password and security key, <c>2 | master key (32)</c> for the recovery code.
/// </remarks>
static class HiddenSlots
{
    public const int SaltSize = 16;
    public const int SlotCount = 6;
    const int SlotSize = 500;
    const int NonceSize = 12;
    const int TagSize = 16;
    const int PayloadSize = SlotSize - NonceSize - TagSize;
    const int MaxCredentialIdSize = 256;
    const long FirstSlot = VaultFile.KeyAreaStart + SaltSize;

    public const byte PasswordAndKey = 1;
    public const byte Recovery = 2;

    public static readonly byte[] PasswordInfo = "YubiVault v2 hidden password"u8.ToArray();
    public static readonly byte[] RecoveryInfo = "YubiVault v2 hidden recovery"u8.ToArray();

    public static byte[] ReadSalt(VaultFile file)
    {
        var salt = new byte[SaltSize];
        file.ReadAt(VaultFile.KeyAreaStart, salt);
        return salt;
    }

    /// <returns>The decrypted payload of the first slot <paramref name="slotKey"/> opens, or null.</returns>
    public static byte[]? Find(VaultFile file, byte[] slotKey, byte[] vaultId)
    {
        var slot = new byte[SlotSize];
        using var aes = new AesGcm(slotKey, TagSize);
        for (int i = 0; i < SlotCount; i++)
        {
            file.ReadAt(FirstSlot + i * SlotSize, slot);
            var payload = new byte[PayloadSize];
            try
            {
                aes.Decrypt(slot.AsSpan(0, NonceSize), slot.AsSpan(NonceSize, PayloadSize), slot.AsSpan(SlotSize - TagSize),
                    payload, AssociatedData(vaultId));
                return payload;
            }
            catch (AuthenticationTagMismatchException)
            {
            }
        }
        return null;
    }

    public static void Write(VaultFile file, int index, byte[] slotKey, byte[] payload, byte[] vaultId)
    {
        if (payload.Length > PayloadSize)
            throw new ArgumentException("Hidden slot payload too large.", nameof(payload));
        var plain = new byte[PayloadSize];
        payload.CopyTo(plain, 0);
        var slot = new byte[SlotSize];
        RandomNumberGenerator.Fill(slot.AsSpan(0, NonceSize));
        using (var aes = new AesGcm(slotKey, TagSize))
            aes.Encrypt(slot.AsSpan(0, NonceSize), plain, slot.AsSpan(NonceSize, PayloadSize), slot.AsSpan(SlotSize - TagSize),
                AssociatedData(vaultId));
        CryptographicOperations.ZeroMemory(plain);
        file.WriteAt(FirstSlot + index * SlotSize, slot);
    }

    public static byte[] PasswordPayload(byte[] credentialId, byte[] fido2Salt, byte[] kek, ReadOnlySpan<byte> masterKey, byte[] vaultId)
    {
        if (credentialId.Length > MaxCredentialIdSize)
            throw new VaultException("This security key's credential is too long for a hidden vault.");
        var payload = new byte[2 + MaxCredentialIdSize + 32 + NonceSize + KeyWrap.MasterKeySize + TagSize];
        payload[0] = PasswordAndKey;
        payload[1] = (byte)(credentialId.Length - 1); // 1..256
        credentialId.CopyTo(payload, 2);
        int at = 2 + MaxCredentialIdSize;
        fido2Salt.CopyTo(payload, at);
        var nonce = payload.AsSpan(at + 32, NonceSize);
        RandomNumberGenerator.Fill(nonce);
        using var aes = new AesGcm(kek, TagSize);
        aes.Encrypt(nonce, masterKey, payload.AsSpan(at + 32 + NonceSize, KeyWrap.MasterKeySize),
            payload.AsSpan(at + 32 + NonceSize + KeyWrap.MasterKeySize, TagSize), WrapData(vaultId));
        return payload;
    }

    public static (byte[] CredentialId, byte[] Fido2Salt) ReadPasswordPayload(byte[] payload)
    {
        int at = 2 + MaxCredentialIdSize;
        return (payload.AsSpan(2, payload[1] + 1).ToArray(), payload.AsSpan(at, 32).ToArray());
    }

    /// <returns>The master key, or null if <paramref name="kek"/> is wrong.</returns>
    public static byte[]? UnwrapPasswordPayload(byte[] payload, byte[] kek, byte[] vaultId)
    {
        int at = 2 + MaxCredentialIdSize + 32;
        var masterKey = new byte[KeyWrap.MasterKeySize];
        using var aes = new AesGcm(kek, TagSize);
        try
        {
            aes.Decrypt(payload.AsSpan(at, NonceSize), payload.AsSpan(at + NonceSize, KeyWrap.MasterKeySize),
                payload.AsSpan(at + NonceSize + KeyWrap.MasterKeySize, TagSize), masterKey, WrapData(vaultId));
            return masterKey;
        }
        catch (AuthenticationTagMismatchException)
        {
            return null;
        }
    }

    public static byte[] RecoveryPayload(ReadOnlySpan<byte> masterKey) => [Recovery, .. masterKey];

    public static byte[] ReadRecoveryPayload(byte[] payload) => payload.AsSpan(1, KeyWrap.MasterKeySize).ToArray();

    /// <summary>Two distinct random slot positions.</summary>
    public static (int, int) PickTwo()
    {
        int a = RandomNumberGenerator.GetInt32(SlotCount);
        int b = RandomNumberGenerator.GetInt32(SlotCount - 1);
        return (a, b >= a ? b + 1 : b);
    }

    static byte[] AssociatedData(byte[] vaultId) => Encoding.UTF8.GetBytes($"YubiVault v2 hidden slot|{Convert.ToBase64String(vaultId)}");

    static byte[] WrapData(byte[] vaultId) => Encoding.UTF8.GetBytes($"YubiVault v2 hidden key|{Convert.ToBase64String(vaultId)}");
}
