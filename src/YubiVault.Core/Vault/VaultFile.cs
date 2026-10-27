using System.Buffers.Binary;
using System.Security.Cryptography;

namespace YubiVault.Core;

/// <summary>
/// The single-file container behind a vault. Records (the header, encrypted file blobs and the
/// encrypted index) are only ever appended; a commit then points one of two superblocks at the
/// newest header and index, so an interrupted write leaves the previous state intact.
/// </summary>
/// <remarks>
/// Layout: superblock A at 0, superblock B at 512, records from <see cref="DataStart"/> on.
/// Superblock: magic (8) | generation (8) | header offset (8) | header length (8) | index offset (8)
/// | index length (8) | end of data (8) | SHA-256 of the previous bytes (32), little-endian.
/// The valid superblock with the highest generation wins.
/// </remarks>
sealed class VaultFile : IDisposable
{
    public const int DataStart = 4096;
    const int SuperblockSlotSize = 512;
    const int SuperblockSize = 56 + 32;
    static readonly byte[] Magic = "YVAULT\0\x01"u8.ToArray();

    readonly FileStream _stream;
    Superblock _current;
    long _append;

    VaultFile(FileStream stream, Superblock current)
    {
        _stream = stream;
        _current = current;
        _append = Math.Max(current.End, DataStart);
    }

    public long Length => _stream.Length;
    public long End => _current.End;
    public long HeaderLength => _current.HeaderLength;
    public long IndexLength => _current.IndexLength;

    /// <summary>True if <paramref name="path"/> is a file that starts like a vault.</summary>
    public static bool LooksLikeVault(string path)
    {
        if (!File.Exists(path))
            return false;
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            Span<byte> magic = stackalloc byte[Magic.Length];
            return stream.ReadAtLeast(magic, magic.Length, throwOnEndOfStream: false) == magic.Length
                && (magic.SequenceEqual(Magic) || ReadSuperblock(stream, SuperblockSlotSize) is not null);
        }
        catch (IOException)
        {
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            return false;
        }
    }

    /// <summary>Creates an empty container; nothing is valid in it until the first <see cref="Commit"/>.</summary>
    public static VaultFile Create(string path)
    {
        var stream = new FileStream(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.Read);
        stream.SetLength(DataStart);
        return new VaultFile(stream, new Superblock(0, 0, 0, 0, 0, DataStart));
    }

    /// <exception cref="VaultException">Not a vault, damaged, or open for writing elsewhere.</exception>
    public static VaultFile Open(string path, bool writable)
    {
        if (!File.Exists(path))
            throw new VaultException($"No vault found at {Path.GetFullPath(path)}.");
        FileStream stream;
        try
        {
            stream = writable
                ? new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.Read)
                : new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        }
        catch (IOException e)
        {
            throw new VaultException("The vault is open in another window or program.", e);
        }
        try
        {
            var a = ReadSuperblock(stream, 0);
            var b = ReadSuperblock(stream, SuperblockSlotSize);
            var current = a is null ? b : b is null ? a : a.Value.Generation >= b.Value.Generation ? a : b;
            if (current is null)
                throw new VaultException("Not a YubiVault vault, or its header is damaged.");
            if (current.Value.End > stream.Length)
                throw new VaultException("The vault file is truncated.");
            var file = new VaultFile(stream, current.Value);
            if (writable && stream.Length > current.Value.End)
                stream.SetLength(current.Value.End); // drop the tail of an interrupted write
            return file;
        }
        catch
        {
            stream.Dispose();
            throw;
        }
    }

    public byte[] ReadHeader()
    {
        if (_current.HeaderLength is <= 0 or > 16 << 20)
            throw new VaultException("The vault header is damaged.");
        var bytes = new byte[_current.HeaderLength];
        _stream.Position = _current.HeaderOffset;
        _stream.ReadExactly(bytes);
        return bytes;
    }

    public Stream OpenIndex() => OpenRecord(_current.IndexOffset, _current.IndexLength);

    /// <summary>A read-only view of one record.</summary>
    public Stream OpenRecord(long offset, long length)
    {
        if (offset < DataStart || length < 0 || offset + length > _current.End)
            throw new VaultException("A record points outside the vault file.");
        return new RecordStream(_stream, offset, length);
    }

    /// <summary>Appends a record after everything else. It stays invisible until the next <see cref="Commit"/>.</summary>
    public (long Offset, long Length) Append(Action<Stream> write)
    {
        long offset = _append;
        _stream.Position = offset;
        try
        {
            write(new AppendStream(_stream));
        }
        catch
        {
            _stream.SetLength(offset); // drop the partial record
            throw;
        }
        long length = _stream.Position - offset;
        _append = _stream.Position;
        return (offset, length);
    }

    /// <summary>Makes everything appended so far durable and current.</summary>
    /// <param name="header">New header bytes, or null to keep the current header.</param>
    /// <param name="writeIndex">Writes the encrypted index.</param>
    public void Commit(byte[]? header, Action<Stream> writeIndex)
    {
        var (headerOffset, headerLength) = header is null
            ? (_current.HeaderOffset, _current.HeaderLength)
            : Append(s => s.Write(header));
        var (indexOffset, indexLength) = Append(writeIndex);
        _stream.Flush(flushToDisk: true);

        var next = new Superblock(_current.Generation + 1, headerOffset, headerLength, indexOffset, indexLength, _append);
        Span<byte> block = stackalloc byte[SuperblockSize];
        next.WriteTo(block);
        _stream.Position = (next.Generation % 2) * SuperblockSlotSize;
        _stream.Write(block);
        _stream.Flush(flushToDisk: true);
        _current = next;
    }

    static Superblock? ReadSuperblock(FileStream stream, long position)
    {
        Span<byte> block = stackalloc byte[SuperblockSize];
        stream.Position = position;
        if (stream.ReadAtLeast(block, SuperblockSize, throwOnEndOfStream: false) < SuperblockSize)
            return null;
        if (!block[..Magic.Length].SequenceEqual(Magic))
            return null;
        Span<byte> hash = stackalloc byte[32];
        SHA256.HashData(block[..56], hash);
        if (!CryptographicOperations.FixedTimeEquals(hash, block[56..]))
            return null;
        var sb = new Superblock(
            BinaryPrimitives.ReadInt64LittleEndian(block[8..]),
            BinaryPrimitives.ReadInt64LittleEndian(block[16..]),
            BinaryPrimitives.ReadInt64LittleEndian(block[24..]),
            BinaryPrimitives.ReadInt64LittleEndian(block[32..]),
            BinaryPrimitives.ReadInt64LittleEndian(block[40..]),
            BinaryPrimitives.ReadInt64LittleEndian(block[48..]));
        bool sane = sb.Generation > 0 && sb.End >= DataStart
            && sb.HeaderOffset >= DataStart && sb.HeaderLength > 0 && sb.HeaderOffset + sb.HeaderLength <= sb.End
            && sb.IndexOffset >= DataStart && sb.IndexLength > 0 && sb.IndexOffset + sb.IndexLength <= sb.End;
        return sane ? sb : null;
    }

    readonly record struct Superblock(long Generation, long HeaderOffset, long HeaderLength, long IndexOffset, long IndexLength, long End)
    {
        public void WriteTo(Span<byte> block)
        {
            Magic.CopyTo(block);
            BinaryPrimitives.WriteInt64LittleEndian(block[8..], Generation);
            BinaryPrimitives.WriteInt64LittleEndian(block[16..], HeaderOffset);
            BinaryPrimitives.WriteInt64LittleEndian(block[24..], HeaderLength);
            BinaryPrimitives.WriteInt64LittleEndian(block[32..], IndexOffset);
            BinaryPrimitives.WriteInt64LittleEndian(block[40..], IndexLength);
            BinaryPrimitives.WriteInt64LittleEndian(block[48..], End);
            SHA256.HashData(block[..56], block[56..]);
        }
    }

    public void Dispose() => _stream.Dispose();

    /// <summary>Reads a slice of the shared file stream; it is the only reader while it is in use.</summary>
    sealed class RecordStream(FileStream file, long offset, long length) : Stream
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
            file.Position = offset + _position;
            int read = file.Read(buffer);
            if (read == 0)
                throw new EndOfStreamException("The vault file is truncated.");
            _position += read;
            return read;
        }

        public override void Flush() { }
        public override long Seek(long offset1, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset1, int count) => throw new NotSupportedException();
    }

    /// <summary>Lets an encoder write into the file without closing it.</summary>
    sealed class AppendStream(FileStream file) : Stream
    {
        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Write(byte[] buffer, int offset, int count) => file.Write(buffer, offset, count);
        public override void Write(ReadOnlySpan<byte> buffer) => file.Write(buffer);
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
    }
}
