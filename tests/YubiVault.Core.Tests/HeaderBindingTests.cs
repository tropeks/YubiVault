using System.Reflection;
using System.Text.Json.Nodes;
using YubiVault.Core;
using YubiVault.Core.Crypto;

namespace YubiVault.Core.Tests;

public class HeaderBindingTests : IDisposable
{
    readonly TempFolder _temp = new();
    readonly FakeYubiKey _key = new("primary", serial: 1001);

    public void Dispose() => _temp.Dispose();

    string VaultFilePath => _temp["test.yvault"];

    Vault Open() => Vault.OpenWithYubiKey(VaultFilePath, _key, () => throw new Exception("No password expected"), Fast.Options);

    void CreatePaddedVaultWithAFile()
    {
        string source = _temp.WriteFile("in/a.txt", [1, 2, 3]);
        var (vault, _) = Vault.Create(VaultFilePath, _key, null, Fast.Options);
        using (vault)
        {
            vault.SetPadding(2 << 20);
            vault.Add(source);
        }
    }

    [Fact]
    public void ChangedPaddingIsRefused()
    {
        CreatePaddedVaultWithAFile();
        VaultFileEditor.EditHeader(VaultFilePath, header => header["padding"] = 1 << 20);
        Assert.Throws<VaultException>(Open);
    }

    [Fact]
    public void ChangedVersionIsRefused()
    {
        CreatePaddedVaultWithAFile();
        VaultFileEditor.EditHeader(VaultFilePath, header =>
        {
            header["version"] = 1;
            header["padding"] = 0;
        });
        Assert.Throws<VaultException>(Open);
    }

    [Fact]
    public void ChangedVaultIdIsRefused()
    {
        CreatePaddedVaultWithAFile();
        VaultFileEditor.EditHeader(VaultFilePath, header => header["vaultId"] = Convert.ToBase64String(new byte[16]));
        Assert.ThrowsAny<VaultException>(Open);
    }

    [Fact]
    public void UntouchedHeaderStillOpensAfterEdits()
    {
        CreatePaddedVaultWithAFile();
        using (var vault = Open())
            vault.Add(_temp.WriteFile("in/b.txt", [4]));
        using var reopened = Open();
        Assert.Equal(2, reopened.Entries.Count);
        Assert.Equal(2 << 20, reopened.Padding);
    }

    [Fact]
    public void IndexWrittenBeforeTheBindingOpensAndIsUpgraded()
    {
        CreatePaddedVaultWithAFile();
        byte[] masterKey;
        List<VaultEntry> entries;
        using (var vault = Open())
        {
            masterKey = ((byte[])typeof(Vault).GetField("_masterKey", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(vault)!).ToArray();
            entries = vault.Entries.ToList();
        }
        // Commit an index the way earlier versions wrote it.
        using (var file = VaultFile.Open(VaultFilePath, writable: true))
        {
            byte[] json = System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(entries);
            file.Commit(null, output => CascadeCipher.Encrypt(new MemoryStream(json), output, masterKey, "index"u8, Fast.Options.ChunkSizeLog2));
        }

        using (var vault = Open())
            Assert.Single(vault.Entries);

        // Opening rewrote the index bound to the header, so the header can no longer be changed.
        VaultFileEditor.EditHeader(VaultFilePath, header => header["padding"] = 1 << 20);
        Assert.Throws<VaultException>(Open);
    }

    [Fact]
    public void HiddenVaultStillWorks()
    {
        var securityKey = new FakeSecurityKey("device");
        var (vault, _) = Vault.Create(VaultFilePath, securityKey, Fast.Options);
        string recovery;
        using (vault)
            recovery = vault.CreateHiddenVault("hidden pw", securityKey, 2 << 20);
        string source = _temp.WriteFile("in/secret.txt", [9]);
        using (var hidden = Vault.OpenHidden(VaultFilePath, "hidden pw", securityKey, Fast.Options))
            hidden.Add(source);
        using (var outer = Vault.OpenWithFido2(VaultFilePath, securityKey, Fast.Options))
            outer.Add(_temp.WriteFile("in/outer.txt", [1]));
        using var reopened = Vault.OpenHiddenWithRecoveryCode(VaultFilePath, recovery, Fast.Options);
        Assert.Equal("secret.txt", Assert.Single(reopened.Entries).Path);
    }
}

public class SlotLimitTests : IDisposable
{
    readonly TempFolder _temp = new();
    readonly FakeYubiKey _key = new("primary", serial: 1001);

    public void Dispose() => _temp.Dispose();

    string VaultFilePath => _temp["test.yvault"];

    string CreateVault()
    {
        var (vault, recovery) = Vault.Create(VaultFilePath, _key, null, Fast.Options);
        vault.Dispose();
        return recovery;
    }

    static void CopySlot(JsonNode header, string type, int copies, Func<int, string> id)
    {
        var slots = header["slots"]!.AsArray();
        var original = slots.First(s => (string?)s!["type"] == type)!;
        for (int i = 0; i < copies; i++)
        {
            var copy = original.DeepClone();
            copy["id"] = id(i);
            slots.Add(copy);
        }
    }

    [Fact]
    public void TooManySlotsAreRefused()
    {
        string recovery = CreateVault();
        VaultFileEditor.EditHeader(VaultFilePath, header => CopySlot(header, KeySlotType.YubiKey, Vault.MaxSlots - 1, i => "x" + i));
        int touches = _key.Touches;
        var e = Assert.Throws<VaultException>(() => Vault.OpenWithRecoveryCode(VaultFilePath, recovery, Fast.Options));
        Assert.Contains("key slots", e.Message);
        Assert.Throws<VaultException>(() => Vault.OpenWithYubiKey(VaultFilePath, _key, () => "", Fast.Options));
        Assert.Equal(touches, _key.Touches);
    }

    [Fact]
    public void MoreThanOneRecoverySlotIsRefused()
    {
        string recovery = CreateVault();
        VaultFileEditor.EditHeader(VaultFilePath, header => CopySlot(header, KeySlotType.Recovery, 1, i => "r9"));
        var e = Assert.Throws<VaultException>(() => Vault.OpenWithRecoveryCode(VaultFilePath, recovery, Fast.Options));
        Assert.Contains("key slots", e.Message);
    }

    [Fact]
    public void AFullVaultTakesNoMoreKeys()
    {
        var (vault, _) = Vault.Create(VaultFilePath, _key, null, Fast.Options);
        using (vault)
        {
            for (int serial = 2; vault.Slots.Count < Vault.MaxSlots; serial++)
                vault.AddYubiKey(new FakeYubiKey("k" + serial, serial), null);
            Assert.Throws<VaultException>(() => vault.AddYubiKey(new FakeYubiKey("one too many", 999), null));
            vault.RegenerateRecoveryCode(); // replacing the recovery code still works when full
        }
        Vault.OpenWithYubiKey(VaultFilePath, _key, () => "", Fast.Options).Dispose();
    }
}
