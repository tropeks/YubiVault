using System.Buffers.Binary;
using System.Security.Cryptography;

namespace YubiVault.Core;

/// <summary>
/// A hidden vault's records, kept inside the random padding of a vault file. Every byte written is
/// masked with an AES-256-CTR keystream and the superblocks are AES-256-GCM encrypted with random
/// nonces, so without the hidden master key the area cannot be told apart from random padding.
/// </summary>
/// <remarks>
/// Layout, relative to the start of the padding: superblock slots A and B (256 bytes each), then records.
/// Superblock plaintext: generation | index offset | index length | end of data, 64-bit little-endian.
/// The area has a fixed size: the vault file around it never writes into it.
/// </remarks>
sealed class HiddenStore : IRecordStore, IDisposable
{
    const int SuperblockSlotSize = 256;
    const int SuperblockPlainSize = 32;
    const int NonceSize = 12;
    const int TagSize = 16;
    public const int RecordsStart = 2 * SuperblockSlotSize;
    const int PieceSize = 1 << 16;

    static readonly byte[] SuperblockInfo = "YubiVault v2 hidden superblock"u8.ToArray();
    static readonly byte[] MaskInfo = "YubiVault v2 hidden mask"u8.ToArray();
    static readonly byte[] SuperblockContext = "YubiVault hidden superblock"u8.ToArray();

    readonly VaultFile _file;
    readonly long _base;
    readonly long _size;
    readonly byte[] _superblockKey;
    readonly Aes _mask;
    Superblock _current;
    long _append;

    HiddenStore(VaultFile file, long baseOffset, long size, ReadOnlySpan<byte> masterKey)
    {
        _file = file;
        _base = baseOffset;
        _size = size;
        _superblockKey = HKDF.DeriveKey(HashAlgorithmName.SHA256, masterKey.ToArray(), 32, [], SuperblockInfo);
        byte[] maskKey = HKDF.DeriveKey(HashAlgorithmName.SHA256, masterKey.ToArray(), 32, [], MaskInfo);
        _mask = Aes.Create();
        _mask.Key = maskKey;
        CryptographicOperations.ZeroMemory(maskKey);
        _current = new Superblock(0, 0, 0, RecordsStart);
        _append = RecordsStart;
    }

    /// <summary>Smallest padding that can hold a hidden vault.</summary>
    public const long MinimumSize = 1 << 20;

    /// <summary>Bytes available for records.</summary>
    public long Capacity => _size - RecordsStart;

    public long End => _current.End;
    public long IndexLength => _current.IndexLength;

    /// <summary>Starts an empty hidden vault in the area; call <see cref="Commit"/> to make it exist.</summary>
    public static HiddenStore Create(VaultFile file, long baseOffset, long size, ReadOnlySpan<byte> masterKey)
    {
        if (size < MinimumSize)
            throw new VaultException("The space for a hidden vault must be at least 1 MiB.");
        return new HiddenStore(file, baseOffset, size, masterKey);
    }

    /// <returns>The hidden vault, or null if <paramref name="masterKey"/> finds none in the area.</returns>
    public static HiddenStore? Open(VaultFile file, long baseOffset, long size, ReadOnlySpan<byte> masterKey)
    {
        if (size < MinimumSize)
            return null;
        var store = new HiddenStore(file, baseOffset, size, masterKey);
        Superblock? a = store.ReadSuperblock(0), b = store.ReadSuperblock(1);
        var current = a is null ? b : b is null ? a : a.Value.Generation >= b.Value.Generation ? a : b;
        if (current is null)
        {
            store.Dispose();
            return null;
        }
        store._current = current.Value;
        store._append = current.Value.End;
        return store;
    }

    public Stream OpenIndex() => OpenRecord(_current.IndexOffset, _current.IndexLength);

    public Stream OpenRecord(long offset, long length)
    {
        if (offset < RecordsStart || length < 0 || offset + length > _current.End)
            throw new VaultException("A record points outside the hidden vault.");
        return new MaskedReadStream(this, offset, length);
    }

    public (long Offset, long Length) Append(Action<Stream> write)
    {
        var output = new MaskedAppendStream(this, _append);
        write(output);
        long offset = _append;
        _append = output.Position;
        return (offset, _append - offset);
    }

    public void Commit(Action<Stream> writeIndex)
    {
        var (indexOffset, indexLength) = Append(writeIndex);
        _file.Flush();
        var next = new Superblock(_current.Generation + 1, indexOffset, indexLength, _append);
        WriteSuperblock(next);
        _file.Flush();
        _current = next;
    }

    /// <summary>
    /// Moves the records of <paramref name="entries"/> down over the space of deleted ones, in place.
    /// Not crash-safe: an interruption can damage the hidden vault.
    /// </summary>
    /// <returns>The entries with their new offsets, to be committed.</returns>
    public List<VaultEntry> Slide(IReadOnlyList<VaultEntry> entries)
    {
        var moved = new List<VaultEntry>(entries.Count);
        long position = RecordsStart;
        var buffer = new byte[PieceSize];
        foreach (var entry in entries.OrderBy(e => e.Offset))
        {
            if (entry.Offset < position)
                throw new VaultException("The hidden vault index is damaged.");
            if (entry.Offset != position)
            {
                // Copying forward is safe: the destination always lies before the source.
                for (long done = 0; done < entry.Length;)
                {
                    int count = (int)Math.Min(buffer.Length, entry.Length - done);
                    ReadMasked(entry.Offset + done, buffer.AsSpan(0, count));
                    WriteMasked(position + done, buffer.AsSpan(0, count));
                    done += count;
                }
            }
            moved.Add(new VaultEntry
            {
                Path = entry.Path, BlobId = entry.BlobId, Offset = position, Length = entry.Length,
                Size = entry.Size, ModifiedUtc = entry.ModifiedUtc,
            });
            position += entry.Length;
        }
        _append = position;
        return moved;
    }

    Superblock? ReadSuperblock(int slot)
    {
        Span<byte> block = stackalloc byte[NonceSize + SuperblockPlainSize + TagSize];
        _file.ReadAt(_base + slot * SuperblockSlotSize, block);
        Span<byte> plain = stackalloc byte[SuperblockPlainSize];
        using var aes = new AesGcm(_superblockKey, TagSize);
        try
        {
            aes.Decrypt(block[..NonceSize], block[NonceSize..^TagSize], block[^TagSize..], plain, SuperblockContext);
        }
        catch (AuthenticationTagMismatchException)
        {
            return null;
        }
        var sb = new Superblock(
            BinaryPrimitives.ReadInt64LittleEndian(plain),
            BinaryPrimitives.ReadInt64LittleEndian(plain[8..]),
            BinaryPrimitives.ReadInt64LittleEndian(plain[16..]),
            BinaryPrimitives.ReadInt64LittleEndian(plain[24..]));
        bool sane = sb.Generation > 0 && sb.End >= RecordsStart && sb.End <= _size
            && sb.IndexOffset >= RecordsStart && sb.IndexLength > 0 && sb.IndexOffset + sb.IndexLength <= sb.End;
        return sane ? sb : null;
    }

    void WriteSuperblock(Superblock sb)
    {
        Span<byte> plain = stackalloc byte[SuperblockPlainSize];
        BinaryPrimitives.WriteInt64LittleEndian(plain, sb.Generation);
        BinaryPrimitives.WriteInt64LittleEndian(plain[8..], sb.IndexOffset);
        BinaryPrimitives.WriteInt64LittleEndian(plain[16..], sb.IndexLength);
        BinaryPrimitives.WriteInt64LittleEndian(plain[24..], sb.End);
        Span<byte> block = stackalloc byte[NonceSize + SuperblockPlainSize + TagSize];
        RandomNumberGenerator.Fill(block[..NonceSize]);
        using (var aes = new AesGcm(_superblockKey, TagSize))
            aes.Encrypt(block[..NonceSize], plain, block[NonceSize..^TagSize], block[^TagSize..], SuperblockContext);
        _file.WriteAt(_base + (sb.Generation % 2) * SuperblockSlotSize, block);
    }

    void ReadMasked(long position, Span<byte> buffer)
    {
        _file.ReadAt(_base + position, buffer);
        Mask(position, buffer);
    }

    void WriteMasked(long position, ReadOnlySpan<byte> data)
    {
        if (position + data.Length > _size)
            throw new HiddenVaultFullException();
        var buffer = new byte[Math.Min(data.Length, PieceSize)];
        for (int done = 0; done < data.Length;)
        {
            int count = Math.Min(buffer.Length, data.Length - done);
            data.Slice(done, count).CopyTo(buffer);
            Mask(position + done, buffer.AsSpan(0, count));
            _file.WriteAt(_base + position + done, buffer.AsSpan(0, count));
            done += count;
        }
        CryptographicOperations.ZeroMemory(buffer);
    }

    /// <summary>XORs <paramref name="data"/> with the AES-CTR keystream at <paramref name="position"/> (counter = position / 16).</summary>
    void Mask(long position, Span<byte> data)
    {
        while (data.Length > 0)
        {
            int count = Math.Min(data.Length, PieceSize);
            long firstBlock = position / 16;
            int skip = (int)(position % 16);
            int blocks = (skip + count + 15) / 16;
            var counters = new byte[blocks * 16];
            for (int i = 0; i < blocks; i++)
                BinaryPrimitives.WriteInt64BigEndian(counters.AsSpan(i * 16 + 8), firstBlock + i);
            byte[] keystream = _mask.EncryptEcb(counters, PaddingMode.None);
            for (int i = 0; i < count; i++)
                data[i] ^= keystream[skip + i];
            CryptographicOperations.ZeroMemory(keystream);
            data = data[count..];
            position += count;
        }
    }

    public void Dispose()
    {
        CryptographicOperations.ZeroMemory(_superblockKey);
        _mask.Dispose();
    }

    readonly record struct Superblock(long Generation, long IndexOffset, long IndexLength, long End);

    sealed class MaskedReadStream(HiddenStore store, long offset, long length) : Stream
    {
        long _position;

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => length;
        public override long Position { get => _position; set => throw new NotSupportedException(); }

        public override int Read(byte[] buffer, int offset1, int count) => Read(buffer.AsSpan(offset1, count));

        public override int Read(Span<byte> buffer)
        {
            long left = length - _position;
            if (left <= 0)
                return 0;
            if (buffer.Length > left)
                buffer = buffer[..(int)left];
            if (buffer.Length > PieceSize)
                buffer = buffer[..PieceSize];
            store.ReadMasked(offset + _position, buffer);
            _position += buffer.Length;
            return buffer.Length;
        }

        public override void Flush() { }
        public override long Seek(long offset1, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset1, int count) => throw new NotSupportedException();
    }

    sealed class MaskedAppendStream(HiddenStore store, long start) : Stream
    {
        long _position = start;

        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => _position; set => throw new NotSupportedException(); }

        public override void Write(byte[] buffer, int offset, int count) => Write(buffer.AsSpan(offset, count));

        public override void Write(ReadOnlySpan<byte> buffer)
        {
            store.WriteMasked(_position, buffer);
            _position += buffer.Length;
        }

        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
    }
}

/// <summary>A hidden vault has no room left for what is being added.</summary>
public sealed class HiddenVaultFullException() : VaultException("The hidden vault is full.");
