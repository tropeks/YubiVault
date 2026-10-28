using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace YubiVault.Fido2;

/// <summary>
/// The only form in which this library keeps a PIN: LEFT(SHA-256(PIN), 16), which is all CTAP2 needs.
/// It lives in a pinned buffer (the garbage collector never leaves copies of it behind) and is wiped on
/// <see cref="Dispose"/>. The PIN's own bytes are wiped as soon as the hash is taken.
/// </summary>
/// <remarks>
/// The PIN arrives as a .NET string from the text box, which cannot be wiped; callers drop their
/// reference at once so it lives only until the next garbage collection.
/// </remarks>
public sealed class PinHash : IDisposable
{
    /// <summary>CTAP2 limits: at least 4 Unicode code points, at most 63 bytes of UTF-8.</summary>
    public const int MinLength = 4, MaxBytes = 63;

    readonly byte[] _hash = GC.AllocateArray<byte>(16, pinned: true);
    bool _disposed;

    PinHash()
    {
    }

    /// <returns>The hash, or null if the PIN breaks the CTAP2 length rules (the key would reject it).</returns>
    public static PinHash? From(string pin)
    {
        string normalized = pin.Normalize(NormalizationForm.FormC);
        int codePoints = 0;
        foreach (var _ in normalized.EnumerateRunes())
            codePoints++;
        int length = Encoding.UTF8.GetByteCount(normalized);
        if (codePoints < MinLength || length > MaxBytes)
            return null;

        byte[] bytes = GC.AllocateArray<byte>(length, pinned: true);
        byte[] digest = GC.AllocateArray<byte>(32, pinned: true);
        try
        {
            Encoding.UTF8.GetBytes(normalized, bytes);
            SHA256.HashData(bytes, digest);
            var hash = new PinHash();
            digest.AsSpan(0, 16).CopyTo(hash._hash);
            return hash;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
            CryptographicOperations.ZeroMemory(digest);
        }
    }

    /// <summary>Copies the hash into a pinned buffer the caller must wipe.</summary>
    internal byte[] Copy()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        byte[] copy = GC.AllocateArray<byte>(16, pinned: true);
        _hash.CopyTo(copy, 0);
        return copy;
    }

    public void Dispose()
    {
        _disposed = true;
        CryptographicOperations.ZeroMemory(_hash);
    }
}
