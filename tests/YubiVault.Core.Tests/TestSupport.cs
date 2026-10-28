using System.Security.Cryptography;
using System.Text;
using YubiVault.Core.Keys;
using YubiVault.Core;

namespace YubiVault.Core.Tests;

/// <summary>Software stand-in for a YubiKey in HMAC-SHA1 challenge-response mode.</summary>
sealed class FakeYubiKey(string secret, int? serial = null) : IChallengeResponder
{
    public int Touches { get; private set; }
    public int? SerialNumber => serial;
    public string Description => $"Fake YubiKey {serial}";

    public byte[] Respond(byte[] challenge)
    {
        Touches++;
        return HMACSHA1.HashData(Encoding.UTF8.GetBytes(secret), challenge);
    }
}

sealed class TempFolder : IDisposable
{
    public string Path { get; } = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "yubivault-tests", Guid.NewGuid().ToString("n"));

    public TempFolder() => Directory.CreateDirectory(Path);

    public string this[string relative] => System.IO.Path.Combine(Path, relative);

    public string WriteFile(string relative, byte[] content)
    {
        string full = this[relative];
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(full)!);
        File.WriteAllBytes(full, content);
        return full;
    }

    public void Dispose()
    {
        try { Directory.Delete(Path, recursive: true); } catch (IOException) { }
    }
}

static class Fast
{
    // The cheapest accepted Argon2id and small chunks keep the tests fast; real vaults use the defaults.
    public static readonly VaultOptions Options = new() { Argon2MemoryKiB = 8 * 1024, Argon2Passes = 1, ChunkSizeLog2 = 10 };
}

/// <summary>Software stand-in for a FIDO2 key with hmac-secret: per-credential secrets derived from a device secret.</summary>
sealed class FakeSecurityKey(string deviceSecret) : YubiVault.Core.Keys.IFido2Authenticator
{
    public int Requests { get; private set; }
    public string Description => "Fake security key";

    byte[] Mac(byte[] data) => HMACSHA256.HashData(Encoding.UTF8.GetBytes(deviceSecret), data);

    public byte[] MakeCredential(string relyingPartyId, byte[] userId, string userName)
    {
        Requests++;
        // Like a real non-discoverable credential, the id is sealed by the device: random part + device MAC.
        var random = RandomNumberGenerator.GetBytes(16);
        return [.. random, .. Mac(random)];
    }

    public (byte[] CredentialId, byte[] Secret) GetSecret(string relyingPartyId, IReadOnlyList<(byte[] CredentialId, byte[] Salt)> credentials)
    {
        Requests++;
        foreach (var (id, salt) in credentials)
        {
            if (id.Length != 48 || !Mac(id[..16]).AsSpan().SequenceEqual(id[16..]))
                continue; // not one of this device's credentials
            var credRandom = HMACSHA256.HashData(Encoding.UTF8.GetBytes(deviceSecret), id);
            return (id, HMACSHA256.HashData(credRandom, salt));
        }
        throw new YubiVault.Core.VaultException("This security key is not registered in this vault.");
    }
}
