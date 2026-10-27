using System.Security.Cryptography;
using YubiVault.Core.Crypto;

namespace YubiVault.Core.Tests;

public class CascadeCipherTests
{
    const int ChunkLog2 = 10;
    const int Chunk = 1 << ChunkLog2;
    static readonly byte[] Key = RandomNumberGenerator.GetBytes(32);
    static readonly byte[] Context = "blob:test"u8.ToArray();

    static byte[] Encrypt(byte[] plain, byte[]? key = null, byte[]? context = null)
    {
        using var input = new MemoryStream(plain);
        using var output = new MemoryStream();
        CascadeCipher.Encrypt(input, output, key ?? Key, context ?? Context, ChunkLog2);
        return output.ToArray();
    }

    static byte[] Decrypt(byte[] sealedData, byte[]? key = null, byte[]? context = null)
    {
        using var input = new MemoryStream(sealedData);
        using var output = new MemoryStream();
        CascadeCipher.Decrypt(input, output, key ?? Key, context ?? Context);
        return output.ToArray();
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(Chunk - 1)]
    [InlineData(Chunk)]
    [InlineData(Chunk + 1)]
    [InlineData(5 * Chunk)]
    [InlineData(5 * Chunk + 123)]
    public void RoundTrips(int length)
    {
        var plain = RandomNumberGenerator.GetBytes(length);
        var sealedData = Encrypt(plain);
        Assert.Equal(CascadeCipher.CiphertextLength(length, ChunkLog2), sealedData.Length);
        Assert.Equal(plain, Decrypt(sealedData));
    }

    [Fact]
    public void SameInputEncryptsDifferentlyEachTime()
    {
        var plain = RandomNumberGenerator.GetBytes(100);
        Assert.NotEqual(Encrypt(plain), Encrypt(plain));
    }

    [Fact]
    public void WrongKeyIsRejected() =>
        Assert.ThrowsAny<CryptographicException>(() => Decrypt(Encrypt([1, 2, 3]), key: RandomNumberGenerator.GetBytes(32)));

    [Fact]
    public void WrongContextIsRejected() =>
        Assert.ThrowsAny<CryptographicException>(() => Decrypt(Encrypt([1, 2, 3]), context: "blob:other"u8.ToArray()));

    [Theory]
    [InlineData(0)]      // magic
    [InlineData(5)]      // chunk size
    [InlineData(10)]     // salt
    [InlineData(40)]     // first chunk
    [InlineData(-1)]     // last tag byte
    public void AnyFlippedBitIsDetected(int position)
    {
        var sealedData = Encrypt(RandomNumberGenerator.GetBytes(3 * Chunk));
        int index = position >= 0 ? position : sealedData.Length + position;
        sealedData[index] ^= 0x01;
        Assert.ThrowsAny<Exception>(() => Decrypt(sealedData));
    }

    [Fact]
    public void DroppingTheLastChunkIsDetected()
    {
        var sealedData = Encrypt(RandomNumberGenerator.GetBytes(3 * Chunk + 10));
        int lastChunk = 10 + 32;
        Assert.ThrowsAny<CryptographicException>(() => Decrypt(sealedData[..^lastChunk]));
    }

    [Fact]
    public void TruncatingAtAChunkBoundaryIsDetected()
    {
        var sealedData = Encrypt(RandomNumberGenerator.GetBytes(3 * Chunk));
        int headerSize = 38, sealedChunk = Chunk + 32;
        Assert.ThrowsAny<CryptographicException>(() => Decrypt(sealedData[..(headerSize + 2 * sealedChunk)]));
    }

    [Fact]
    public void SwappingChunksIsDetected()
    {
        var sealedData = Encrypt(RandomNumberGenerator.GetBytes(3 * Chunk));
        int headerSize = 38, sealedChunk = Chunk + 32;
        var first = sealedData.AsSpan(headerSize, sealedChunk).ToArray();
        sealedData.AsSpan(headerSize + sealedChunk, sealedChunk).CopyTo(sealedData.AsSpan(headerSize));
        first.CopyTo(sealedData.AsSpan(headerSize + sealedChunk));
        Assert.ThrowsAny<CryptographicException>(() => Decrypt(sealedData));
    }

    [Fact]
    public void BothLayersAreApplied()
    {
        // The output must not equal a plain AES-GCM or plain XChaCha20 encryption: each chunk carries two tags.
        var sealedData = Encrypt(new byte[10]);
        Assert.Equal(38 + 10 + 32, sealedData.Length);
    }

    [Fact]
    public void GarbageIsRejectedAsInvalidData() =>
        Assert.Throws<InvalidDataException>(() => Decrypt("not a vault file"u8.ToArray()));
}
