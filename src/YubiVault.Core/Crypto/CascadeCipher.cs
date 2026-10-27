using System.Buffers.Binary;
using System.Security.Cryptography;
using NSec.Cryptography;

namespace YubiVault.Core.Crypto;

/// <summary>
/// Streams data through two independent AEAD layers: AES-256-GCM first, then
/// XChaCha20-Poly1305 over the result. Each stream gets its own random salt, from
/// which per-stream keys for both layers are derived with HKDF-SHA256.
/// </summary>
/// <remarks>
/// Stream layout: header (magic, version, chunk size, salt) followed by chunks.
/// Every chunk is authenticated with the header and a caller-supplied context as
/// associated data, and its nonce carries the chunk counter and a final-chunk flag,
/// so reordering, duplicating, truncating or moving chunks between files is detected.
/// </remarks>
public static class CascadeCipher
{
    public const int DefaultChunkSizeLog2 = 20; // 1 MiB
    public const int MinChunkSizeLog2 = 10;
    public const int MaxChunkSizeLog2 = 24;

    const int SaltSize = 32;
    const int TagSize = 16;
    const int Overhead = 2 * TagSize;
    const byte FormatVersion = 1;
    static readonly byte[] Magic = "YVF1"u8.ToArray();
    static readonly int HeaderSize = Magic.Length + 2 + SaltSize;

    static readonly byte[] AesInfo = "YubiVault v1 chunk aes-256-gcm"u8.ToArray();
    static readonly byte[] XChaChaInfo = "YubiVault v1 chunk xchacha20-poly1305"u8.ToArray();

    static readonly XChaCha20Poly1305 XChaCha = AeadAlgorithm.XChaCha20Poly1305;

    /// <summary>Size of the ciphertext produced for <paramref name="plaintextLength"/> bytes.</summary>
    public static long CiphertextLength(long plaintextLength, int chunkSizeLog2 = DefaultChunkSizeLog2)
    {
        long chunkSize = 1L << chunkSizeLog2;
        long chunks = Math.Max(1, (plaintextLength + chunkSize - 1) / chunkSize);
        if (plaintextLength > 0 && plaintextLength % chunkSize == 0)
            chunks++; // a full last chunk is followed by an empty final chunk
        return HeaderSize + plaintextLength + chunks * Overhead;
    }

    public static void Encrypt(Stream input, Stream output, ReadOnlySpan<byte> masterKey, ReadOnlySpan<byte> context,
        int chunkSizeLog2 = DefaultChunkSizeLog2)
    {
        if (chunkSizeLog2 is < MinChunkSizeLog2 or > MaxChunkSizeLog2)
            throw new ArgumentOutOfRangeException(nameof(chunkSizeLog2));

        var header = new byte[HeaderSize];
        Magic.CopyTo(header, 0);
        header[Magic.Length] = FormatVersion;
        header[Magic.Length + 1] = (byte)chunkSizeLog2;
        RandomNumberGenerator.Fill(header.AsSpan(Magic.Length + 2));
        output.Write(header);

        int chunkSize = 1 << chunkSizeLog2;
        using var keys = new ChunkKeys(masterKey, header.AsSpan(Magic.Length + 2), header, context, chunkSize);
        var current = new byte[chunkSize];
        var next = new byte[chunkSize];
        var sealedChunk = new byte[chunkSize + Overhead];

        int currentLength = input.ReadAtLeast(current, chunkSize, throwOnEndOfStream: false);
        ulong counter = 0;
        while (true)
        {
            int nextLength = currentLength == chunkSize
                ? input.ReadAtLeast(next, chunkSize, throwOnEndOfStream: false)
                : 0;
            bool final = currentLength < chunkSize;
            int sealedLength = keys.Seal(counter, final, current.AsSpan(0, currentLength), sealedChunk);
            output.Write(sealedChunk, 0, sealedLength);
            if (final)
                break;
            (current, next) = (next, current);
            currentLength = nextLength;
            counter++;
        }

        CryptographicOperations.ZeroMemory(current);
        CryptographicOperations.ZeroMemory(next);
    }

    /// <exception cref="InvalidDataException">The data is not a YubiVault stream.</exception>
    /// <exception cref="AuthenticationTagMismatchException">Wrong key, wrong context, or tampered data.</exception>
    public static void Decrypt(Stream input, Stream output, ReadOnlySpan<byte> masterKey, ReadOnlySpan<byte> context)
    {
        var header = new byte[HeaderSize];
        if (input.ReadAtLeast(header, HeaderSize, throwOnEndOfStream: false) != HeaderSize
            || !header.AsSpan(0, Magic.Length).SequenceEqual(Magic))
            throw new InvalidDataException("Not a YubiVault encrypted stream.");
        if (header[Magic.Length] != FormatVersion)
            throw new InvalidDataException($"Unsupported format version {header[Magic.Length]}.");
        int chunkSizeLog2 = header[Magic.Length + 1];
        if (chunkSizeLog2 is < MinChunkSizeLog2 or > MaxChunkSizeLog2)
            throw new InvalidDataException("Invalid chunk size.");

        using var keys = new ChunkKeys(masterKey, header.AsSpan(Magic.Length + 2), header, context, 1 << chunkSizeLog2);
        int sealedSize = (1 << chunkSizeLog2) + Overhead;
        var current = new byte[sealedSize];
        var next = new byte[sealedSize];
        var plain = new byte[sealedSize];

        int currentLength = input.ReadAtLeast(current, sealedSize, throwOnEndOfStream: false);
        ulong counter = 0;
        try
        {
            while (true)
            {
                if (currentLength < Overhead)
                    throw new AuthenticationTagMismatchException("Encrypted stream is truncated.");
                int nextLength = currentLength == sealedSize
                    ? input.ReadAtLeast(next, sealedSize, throwOnEndOfStream: false)
                    : 0;
                bool final = nextLength == 0;
                int plainLength = keys.Open(counter, final, current.AsSpan(0, currentLength), plain);
                output.Write(plain, 0, plainLength);
                if (final)
                    break;
                (current, next) = (next, current);
                currentLength = nextLength;
                counter++;
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plain);
        }
    }

    sealed class ChunkKeys : IDisposable
    {
        readonly AesGcm _aes;
        readonly Key _xchacha;
        readonly byte[] _associatedData;
        readonly byte[] _middle;

        public ChunkKeys(ReadOnlySpan<byte> masterKey, ReadOnlySpan<byte> salt, ReadOnlySpan<byte> header, ReadOnlySpan<byte> context, int chunkSize)
        {
            Span<byte> aesKey = stackalloc byte[32];
            Span<byte> xKey = stackalloc byte[32];
            HKDF.DeriveKey(HashAlgorithmName.SHA256, masterKey, aesKey, salt, AesInfo);
            HKDF.DeriveKey(HashAlgorithmName.SHA256, masterKey, xKey, salt, XChaChaInfo);
            _aes = new AesGcm(aesKey, TagSize);
            _xchacha = Key.Import(XChaCha, xKey, KeyBlobFormat.RawSymmetricKey);
            CryptographicOperations.ZeroMemory(aesKey);
            CryptographicOperations.ZeroMemory(xKey);

            _associatedData = new byte[header.Length + context.Length];
            header.CopyTo(_associatedData);
            context.CopyTo(_associatedData.AsSpan(header.Length));
            _middle = new byte[chunkSize + TagSize];
        }

        public int Seal(ulong counter, bool final, ReadOnlySpan<byte> plaintext, Span<byte> destination)
        {
            Span<byte> aesNonce = stackalloc byte[12];
            Span<byte> xNonce = stackalloc byte[24];
            FillNonce(aesNonce, counter, final);
            FillNonce(xNonce, counter, final);

            var middle = _middle.AsSpan(0, plaintext.Length + TagSize);
            _aes.Encrypt(aesNonce, plaintext, middle[..plaintext.Length], middle[plaintext.Length..], _associatedData);
            int length = middle.Length + TagSize;
            XChaCha.Encrypt(_xchacha, xNonce, _associatedData, middle, destination[..length]);
            CryptographicOperations.ZeroMemory(middle);
            return length;
        }

        public int Open(ulong counter, bool final, ReadOnlySpan<byte> sealedChunk, Span<byte> destination)
        {
            Span<byte> aesNonce = stackalloc byte[12];
            Span<byte> xNonce = stackalloc byte[24];
            FillNonce(aesNonce, counter, final);
            FillNonce(xNonce, counter, final);

            var middle = _middle.AsSpan(0, sealedChunk.Length - TagSize);
            if (!XChaCha.Decrypt(_xchacha, xNonce, _associatedData, sealedChunk, middle))
                throw new AuthenticationTagMismatchException("Chunk failed XChaCha20-Poly1305 authentication.");
            int length = middle.Length - TagSize;
            _aes.Decrypt(aesNonce, middle[..length], middle[length..], destination[..length], _associatedData);
            CryptographicOperations.ZeroMemory(middle);
            return length;
        }

        static void FillNonce(Span<byte> nonce, ulong counter, bool final)
        {
            nonce.Clear();
            BinaryPrimitives.WriteUInt64BigEndian(nonce, counter);
            nonce[^1] = final ? (byte)1 : (byte)0;
        }

        public void Dispose()
        {
            _aes.Dispose();
            _xchacha.Dispose();
            CryptographicOperations.ZeroMemory(_middle);
        }
    }
}
