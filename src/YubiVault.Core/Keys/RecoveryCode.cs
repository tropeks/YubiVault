using System.Security.Cryptography;
using System.Text;

namespace YubiVault.Core.Keys;

/// <summary>160-bit recovery code shown to the user as eight groups of four Base32 characters.</summary>
public static class RecoveryCode
{
    public const int ByteLength = 20;
    const int CharLength = ByteLength * 8 / 5;
    const string Alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // no 0/O or 1/I to avoid misreading

    public static byte[] Generate() => RandomNumberGenerator.GetBytes(ByteLength);

    public static string Format(ReadOnlySpan<byte> code)
    {
        if (code.Length != ByteLength)
            throw new ArgumentException("Invalid recovery code length.", nameof(code));
        var chars = new StringBuilder(CharLength + CharLength / 4);
        int buffer = 0, bits = 0, written = 0;
        foreach (byte b in code)
        {
            buffer = (buffer << 8) | b;
            bits += 8;
            while (bits >= 5)
            {
                if (written > 0 && written % 4 == 0)
                    chars.Append('-');
                chars.Append(Alphabet[(buffer >> (bits - 5)) & 31]);
                bits -= 5;
                written++;
            }
        }
        return chars.ToString();
    }

    /// <exception cref="FormatException">The text is not a valid recovery code.</exception>
    public static byte[] Parse(string text)
    {
        var result = new byte[ByteLength];
        int buffer = 0, bits = 0, index = 0, count = 0;
        foreach (char raw in text)
        {
            if (raw is '-' or ' ')
                continue;
            int value = Alphabet.IndexOf(char.ToUpperInvariant(raw));
            if (value < 0 || count == CharLength)
                throw new FormatException("Invalid recovery code.");
            buffer = (buffer << 5) | value;
            bits += 5;
            count++;
            if (bits >= 8)
            {
                result[index++] = (byte)(buffer >> (bits - 8));
                bits -= 8;
            }
        }
        if (count != CharLength)
            throw new FormatException("Invalid recovery code.");
        return result;
    }
}
