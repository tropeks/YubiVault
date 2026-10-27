namespace YubiVault.Core;

public sealed class VaultOptions
{
    /// <summary>Argon2id memory cost for passwords and recovery codes, in KiB (default 64 MiB).</summary>
    public long Argon2MemoryKiB { get; init; } = 64 * 1024;

    /// <summary>Argon2id iterations.</summary>
    public long Argon2Passes { get; init; } = 3;

    /// <summary>log2 of the encryption chunk size (default 1 MiB).</summary>
    public int ChunkSizeLog2 { get; init; } = Crypto.CascadeCipher.DefaultChunkSizeLog2;

    public static VaultOptions Default { get; } = new();
}
