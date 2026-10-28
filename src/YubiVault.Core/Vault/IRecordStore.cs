namespace YubiVault.Core;

/// <summary>Append-only storage for encrypted records: the vault file itself, or a hidden vault inside its padding.</summary>
interface IRecordStore
{
    /// <summary>End of the committed data.</summary>
    long End { get; }

    long IndexLength { get; }

    Stream OpenIndex();

    /// <summary>A read-only view of one record.</summary>
    Stream OpenRecord(long offset, long length);

    /// <summary>Appends a record after everything else. It stays invisible until the next <see cref="Commit"/>.</summary>
    (long Offset, long Length) Append(Action<Stream> write);

    /// <summary>Writes the index and makes everything appended so far durable and current.</summary>
    void Commit(Action<Stream> writeIndex);
}
