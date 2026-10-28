using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text.Json.Nodes;
using YubiVault.Core;

namespace YubiVault.Core.Tests;

/// <summary>Rewrites the unauthenticated parts of a vault file (superblocks and header) the way a forged file could.</summary>
static class VaultFileEditor
{
    const int SuperblockSlotSize = 512;
    static readonly byte[] Magic = "YVAULT\0\x01"u8.ToArray();

    public readonly record struct Superblock(long Generation, long HeaderOffset, long HeaderLength, long IndexOffset, long IndexLength, long End);

    public static Superblock ReadCurrent(string path)
    {
        using var file = File.OpenRead(path);
        Superblock? best = null;
        for (int slot = 0; slot < 2; slot++)
        {
            var block = new byte[88];
            file.Position = slot * SuperblockSlotSize;
            file.ReadExactly(block);
            if (!block.AsSpan(0, 8).SequenceEqual(Magic) || !SHA256.HashData(block.AsSpan(0, 56)).AsSpan().SequenceEqual(block.AsSpan(56)))
                continue;
            long Field(int i) => BinaryPrimitives.ReadInt64LittleEndian(block.AsSpan(8 + 8 * i));
            var sb = new Superblock(Field(0), Field(1), Field(2), Field(3), Field(4), Field(5));
            if (best is null || sb.Generation > best.Value.Generation)
                best = sb;
        }
        return best ?? throw new InvalidOperationException("No valid superblock.");
    }

    /// <summary>Writes a superblock with a correct SHA-256, as anyone can.</summary>
    public static void Write(string path, int slot, Superblock sb)
    {
        var block = new byte[88];
        Magic.CopyTo(block, 0);
        long[] fields = [sb.Generation, sb.HeaderOffset, sb.HeaderLength, sb.IndexOffset, sb.IndexLength, sb.End];
        for (int i = 0; i < fields.Length; i++)
            BinaryPrimitives.WriteInt64LittleEndian(block.AsSpan(8 + 8 * i), fields[i]);
        SHA256.HashData(block.AsSpan(0, 56), block.AsSpan(56));
        using var file = new FileStream(path, FileMode.Open);
        file.Position = slot * SuperblockSlotSize;
        file.Write(block);
    }

    /// <summary>Writes the same superblock to both slots, so there is no older one to fall back to.</summary>
    public static void WriteBoth(string path, Superblock sb)
    {
        Write(path, 0, sb);
        Write(path, 1, sb);
    }

    /// <summary>Appends an edited copy of the header and commits it with a new superblock.</summary>
    public static void EditHeader(string path, Action<JsonNode> edit)
    {
        var current = ReadCurrent(path);
        var bytes = File.ReadAllBytes(path);
        var header = JsonNode.Parse(bytes.AsSpan((int)current.HeaderOffset, (int)current.HeaderLength))!;
        edit(header);
        byte[] json = System.Text.Encoding.UTF8.GetBytes(header.ToJsonString());
        long offset = current.End;
        using (var file = new FileStream(path, FileMode.Open))
        {
            file.SetLength(offset);
            file.Position = offset;
            file.Write(json);
        }
        var next = current with { Generation = current.Generation + 1, HeaderOffset = offset, HeaderLength = json.Length, End = offset + json.Length };
        Write(path, (int)(next.Generation % 2), next);
    }

    public static JsonNode Argon2Of(JsonNode header, string type) =>
        header["slots"]!.AsArray().First(s => (string?)s!["type"] == type)!["argon2id"]!;
}

public class Argon2SettingsValidationTests : IDisposable
{
    readonly TempFolder _temp = new();
    readonly FakeYubiKey _key = new("primary", serial: 1001);

    public void Dispose() => _temp.Dispose();

    string VaultFilePath => _temp["test.yvault"];

    string CreateVault(string? password = null, VaultOptions? options = null)
    {
        var (vault, recovery) = Vault.Create(VaultFilePath, _key, password, options ?? Fast.Options);
        vault.Dispose();
        return recovery;
    }

    static void AssertRefused(Action open)
    {
        var e = Assert.Throws<VaultException>(open);
        Assert.Contains("Argon2id", e.Message);
    }

    [Fact]
    public void HugeMemoryCostIsRefusedBeforeDerivation()
    {
        string recovery = CreateVault(password: "pw");
        VaultFileEditor.EditHeader(VaultFilePath, header =>
        {
            VaultFileEditor.Argon2Of(header, KeySlotType.Recovery)["memoryKiB"] = 1L << 40; // 1 PiB
            VaultFileEditor.Argon2Of(header, KeySlotType.YubiKey)["memoryKiB"] = long.MaxValue;
        });

        int touches = _key.Touches;
        long allocated = GC.GetAllocatedBytesForCurrentThread();
        AssertRefused(() => Vault.OpenWithRecoveryCode(VaultFilePath, recovery, Fast.Options));
        AssertRefused(() => Vault.OpenWithYubiKey(VaultFilePath, _key, () => "pw", Fast.Options));
        Assert.True(GC.GetAllocatedBytesForCurrentThread() - allocated < 16 << 20);
        Assert.Equal(touches, _key.Touches); // refused while reading the header, before asking the key
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1000)]
    public void PassesOutOfRangeAreRefused(long passes)
    {
        string recovery = CreateVault();
        VaultFileEditor.EditHeader(VaultFilePath, header => VaultFileEditor.Argon2Of(header, KeySlotType.Recovery)["passes"] = passes);
        AssertRefused(() => Vault.OpenWithRecoveryCode(VaultFilePath, recovery, Fast.Options));
    }

    [Fact]
    public void TinyMemoryCostIsRefused()
    {
        string recovery = CreateVault();
        VaultFileEditor.EditHeader(VaultFilePath, header => VaultFileEditor.Argon2Of(header, KeySlotType.Recovery)["memoryKiB"] = 64);
        AssertRefused(() => Vault.OpenWithRecoveryCode(VaultFilePath, recovery, Fast.Options));
    }

    [Fact]
    public void ShortSaltIsRefused()
    {
        string recovery = CreateVault();
        VaultFileEditor.EditHeader(VaultFilePath, header =>
            VaultFileEditor.Argon2Of(header, KeySlotType.Recovery)["salt"] = Convert.ToBase64String(new byte[8]));
        AssertRefused(() => Vault.OpenWithRecoveryCode(VaultFilePath, recovery, Fast.Options));
    }

    [Fact]
    public void AnySlotOutOfRangeRefusesTheVault()
    {
        // The key opening the vault does not use the bad slot, but the whole header is refused.
        CreateVault();
        VaultFileEditor.EditHeader(VaultFilePath, header => VaultFileEditor.Argon2Of(header, KeySlotType.Recovery)["passes"] = 0);
        AssertRefused(() => Vault.OpenWithYubiKey(VaultFilePath, _key, () => throw new Exception("No password expected"), Fast.Options));
    }

    [Fact]
    public void VaultWithTheAppsDefaultsOpens()
    {
        string recovery = CreateVault(password: "pw", options: VaultOptions.Default);
        var header = File.ReadAllText(VaultFilePath, System.Text.Encoding.Latin1);
        Assert.Contains($"\"memoryKiB\": {64 * 1024}", header);
        Assert.Contains("\"passes\": 3", header);

        Vault.OpenWithRecoveryCode(VaultFilePath, recovery).Dispose();
        Vault.OpenWithYubiKey(VaultFilePath, _key, () => "pw").Dispose();
    }

    [Fact]
    public void OptionsOutOfRangeCannotCreateAVault()
    {
        // The app never writes a vault it would refuse to open.
        AssertRefused(() => Vault.Create(VaultFilePath, _key, null, new VaultOptions { Argon2MemoryKiB = 64, Argon2Passes = 1 }));
    }
}

public class BoundsArithmeticTests : IDisposable
{
    readonly TempFolder _temp = new();
    readonly FakeYubiKey _key = new("primary", serial: 1001);

    public void Dispose() => _temp.Dispose();

    string VaultFilePath => _temp["test.yvault"];

    void CreateVault() => Vault.Create(VaultFilePath, _key, null, Fast.Options).Vault.Dispose();

    void Open() => Vault.OpenWithYubiKey(VaultFilePath, _key, () => throw new Exception("No password expected"), Fast.Options).Dispose();

    /// <summary>Fails on any exception that is not a <see cref="VaultException"/>, such as <see cref="EndOfStreamException"/>.</summary>
    static void AssertVaultException(Action action)
    {
        var e = Record.Exception(action);
        Assert.NotNull(e);
        Assert.IsAssignableFrom<VaultException>(e);
    }

    [Fact]
    public void HeaderOffsetNearTheLimitIsRefused()
    {
        CreateVault();
        var sb = VaultFileEditor.ReadCurrent(VaultFilePath);
        VaultFileEditor.WriteBoth(VaultFilePath, sb with { Generation = sb.Generation + 1, HeaderOffset = long.MaxValue - 1, HeaderLength = 16 });
        AssertVaultException(Open);
    }

    [Fact]
    public void IndexOffsetNearTheLimitIsRefused()
    {
        CreateVault();
        var sb = VaultFileEditor.ReadCurrent(VaultFilePath);
        VaultFileEditor.WriteBoth(VaultFilePath, sb with { Generation = sb.Generation + 1, IndexOffset = long.MaxValue - 1, IndexLength = 16 });
        AssertVaultException(Open);
    }

    [Fact]
    public void ForgedSuperblockFallsBackToTheValidOne()
    {
        CreateVault();
        var sb = VaultFileEditor.ReadCurrent(VaultFilePath);
        var forged = sb with { Generation = sb.Generation + 1, HeaderOffset = long.MaxValue - 1, HeaderLength = 16 };
        VaultFileEditor.Write(VaultFilePath, (int)(forged.Generation % 2), forged);
        Open();
    }

    [Fact]
    public void ReservedAreaReadNearTheLimitIsRefused()
    {
        CreateVault();
        using var file = VaultFile.Open(VaultFilePath, writable: true);
        AssertVaultException(() => file.ReadAt(long.MaxValue - 1, new byte[16]));
        AssertVaultException(() => file.WriteAt(long.MaxValue - 1, new byte[16]));
    }

    [Fact]
    public void RecordNearTheLimitIsRefused()
    {
        CreateVault();
        using var file = VaultFile.Open(VaultFilePath, writable: false);
        AssertVaultException(() =>
        {
            using var record = file.OpenRecord(long.MaxValue - 1, 16);
            record.ReadExactly(new byte[16]);
        });
        AssertVaultException(() => file.OpenRecord(VaultFile.DataStart, long.MaxValue));
    }

    [Fact]
    public void PaddingNearTheLimitIsRefused()
    {
        CreateVault();
        VaultFileEditor.EditHeader(VaultFilePath, header => header["padding"] = long.MaxValue - 1);
        AssertVaultException(Open);
    }
}
