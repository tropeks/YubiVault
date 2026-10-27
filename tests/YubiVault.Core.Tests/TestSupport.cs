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
    // Cheap Argon2id and small chunks keep the tests fast; real vaults use the defaults.
    public static readonly VaultOptions Options = new() { Argon2MemoryKiB = 64, Argon2Passes = 1, ChunkSizeLog2 = 10 };
}
