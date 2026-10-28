using System.Formats.Cbor;

namespace YubiVault.Fido2;

/// <summary>
/// Just enough CBOR for CTAP2: maps with integer or text keys, byte and text strings, integers,
/// booleans and arrays. Requests are written in CTAP2 canonical form; responses are read leniently
/// into plain .NET values (long, byte[], string, bool, List, Dictionary).
/// </summary>
static class Cbor
{
    public static byte[] Encode(object value)
    {
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        Write(writer, value);
        return writer.Encode();
    }

    static void Write(CborWriter writer, object value)
    {
        switch (value)
        {
            case byte b:
                writer.WriteInt64(b);
                break;
            case int i:
                writer.WriteInt64(i);
                break;
            case long l:
                writer.WriteInt64(l);
                break;
            case bool flag:
                writer.WriteBoolean(flag);
                break;
            case string s:
                writer.WriteTextString(s);
                break;
            case byte[] bytes:
                writer.WriteByteString(bytes);
                break;
            case CborMap map:
                // Ctap2Canonical sorts the keys itself; the order they were added in does not matter.
                writer.WriteStartMap(map.Count);
                foreach (var (key, item) in map)
                {
                    Write(writer, key);
                    Write(writer, item);
                }
                writer.WriteEndMap();
                break;
            case System.Collections.IEnumerable list:
                var items = list.Cast<object>().ToList();
                writer.WriteStartArray(items.Count);
                foreach (var item in items)
                    Write(writer, item);
                writer.WriteEndArray();
                break;
            default:
                throw new ArgumentException($"Cannot encode {value.GetType().Name} as CBOR.");
        }
    }

    public static CborMap DecodeMap(ReadOnlyMemory<byte> data)
    {
        var reader = new CborReader(data, CborConformanceMode.Lax, allowMultipleRootLevelValues: true);
        return Read(reader) as CborMap ?? throw new CtapException("The security key sent an unexpected response.");
    }

    /// <summary>Reads one value and tells how many bytes it took (for the extensions at the end of authenticator data).</summary>
    public static (object Value, int Length) DecodeFirst(ReadOnlyMemory<byte> data)
    {
        var reader = new CborReader(data, CborConformanceMode.Lax, allowMultipleRootLevelValues: true);
        var value = Read(reader);
        return (value, data.Length - reader.BytesRemaining);
    }

    static object Read(CborReader reader)
    {
        switch (reader.PeekState())
        {
            case CborReaderState.UnsignedInteger:
            case CborReaderState.NegativeInteger:
                return reader.ReadInt64();
            case CborReaderState.ByteString:
                return reader.ReadByteString();
            case CborReaderState.TextString:
                return reader.ReadTextString();
            case CborReaderState.Boolean:
                return reader.ReadBoolean();
            case CborReaderState.Null:
                reader.ReadNull();
                return null!;
            case CborReaderState.StartArray:
                int? count = reader.ReadStartArray();
                var list = new List<object>();
                while (reader.PeekState() != CborReaderState.EndArray)
                    list.Add(Read(reader));
                reader.ReadEndArray();
                return list;
            case CborReaderState.StartMap:
                reader.ReadStartMap();
                var map = new CborMap();
                while (reader.PeekState() != CborReaderState.EndMap)
                {
                    var key = Read(reader);
                    map[key] = Read(reader);
                }
                reader.ReadEndMap();
                return map;
            default:
                reader.SkipValue();
                return null!;
        }
    }
}

/// <summary>A CBOR map. Integer keys are stored as long, so <c>map[1L]</c> and <c>map.Get(1)</c> find them.</summary>
sealed class CborMap : Dictionary<object, object>
{
    public CborMap Add(int key, object value)
    {
        this[(long)key] = value;
        return this;
    }

    public CborMap Add(string key, object value)
    {
        this[key] = value;
        return this;
    }

    public object? Get(int key) => TryGetValue((long)key, out var value) ? value : null;

    public object? Get(string key) => TryGetValue(key, out var value) ? value : null;
}
