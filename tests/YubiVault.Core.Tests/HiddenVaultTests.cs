using System.Security.Cryptography;
using System.Text;
using YubiVault.Core;

namespace YubiVault.Core.Tests;

public class HiddenVaultTests : IDisposable
{
    const long OneMiB = 1 << 20;
    const string Password = "correct horse battery staple";

    readonly TempFolder _temp = new();
    readonly FakeSecurityKey _key = new("security-key-1");

    public void Dispose() => _temp.Dispose();

    string VaultFilePath => _temp["test.yvault"];

    Vault CreateOuter() => Vault.Create(VaultFilePath, _key, Fast.Options).Vault;

    /// <summary>An outer vault holding decoy.txt, with a hidden vault of <paramref name="size"/> bytes; returns the hidden recovery code.</summary>
    string CreateWithHidden(long size = 2 * OneMiB)
    {
        string decoy = _temp.WriteFile("in/decoy.txt", "nothing to see"u8.ToArray());
        using var outer = CreateOuter();
        outer.Add(decoy);
        return outer.CreateHiddenVault(Password, _key, size);
    }

    Vault OpenHidden(string password = Password, FakeSecurityKey? key = null) =>
        Vault.OpenHidden(VaultFilePath, password, key ?? _key, Fast.Options);

    [Fact]
    public void HiddenAndOuterVaultsKeepTheirOwnFiles()
    {
        CreateWithHidden();
        var secret = RandomNumberGenerator.GetBytes(50_000);
        using (var hidden = OpenHidden())
        {
            Assert.True(hidden.IsHidden);
            Assert.Empty(hidden.Entries);
            hidden.Add(_temp.WriteFile("in/secret.bin", secret));
        }

        using (var outer = Vault.OpenWithFido2(VaultFilePath, _key, Fast.Options))
        {
            Assert.False(outer.IsHidden);
            Assert.Equal(["decoy.txt"], outer.Entries.Select(e => e.Path));
            Assert.Equal(2 * OneMiB, outer.Padding);
        }

        using (var hidden = OpenHidden())
        {
            Assert.Equal(["secret.bin"], hidden.Entries.Select(e => e.Path));
            hidden.Extract("secret.bin", _temp["out"]);
        }
        Assert.Equal(secret, File.ReadAllBytes(_temp["out/secret.bin"]));
    }

    [Fact]
    public void OuterWritesAndCompactionLeaveTheHiddenVaultIntact()
    {
        CreateWithHidden();
        var secret = RandomNumberGenerator.GetBytes(20_000);
        using (var hidden = OpenHidden())
            hidden.Add(_temp.WriteFile("in/secret.bin", secret));

        using (var outer = Vault.OpenWithFido2(VaultFilePath, _key, Fast.Options))
        {
            outer.Add(_temp.WriteFile("in/big.bin", RandomNumberGenerator.GetBytes(3 * (int)OneMiB)));
            outer.Remove("big.bin"); // wastes most of the file: compacts by itself
            outer.Add(_temp.WriteFile("in/more.txt", [1, 2, 3]));
            outer.Compact();
            Assert.Equal(0, outer.WastedBytes);
        }

        using var reopened = OpenHidden();
        reopened.Extract("secret.bin", _temp["out"]);
        Assert.Equal(secret, File.ReadAllBytes(_temp["out/secret.bin"]));
    }

    [Fact]
    public void WrongPasswordFindsNothing()
    {
        CreateWithHidden();
        var e = Assert.Throws<WrongKeyException>(() => OpenHidden("wrong password"));
        Assert.Equal("No hidden vault opens with this password.", e.Message);
    }

    [Fact]
    public void AVaultWithoutHiddenVaultAnswersTheSame()
    {
        using (var outer = CreateOuter())
            outer.SetPadding(2 * OneMiB);
        var e = Assert.Throws<WrongKeyException>(() => OpenHidden());
        Assert.Equal("No hidden vault opens with this password.", e.Message);

        using (CreateOuterAt(_temp["plain.yvault"])) { }
        Assert.Throws<WrongKeyException>(() => Vault.OpenHidden(_temp["plain.yvault"], Password, _key, Fast.Options));
    }

    Vault CreateOuterAt(string path) => Vault.Create(path, _key, Fast.Options).Vault;

    [Fact]
    public void TheRightPasswordWithAnotherKeyDoesNotOpen()
    {
        CreateWithHidden();
        Assert.ThrowsAny<VaultException>(() => OpenHidden(key: new FakeSecurityKey("someone else")));
    }

    [Fact]
    public void TheHiddenRecoveryCodeOpensItWithoutTheKey()
    {
        string recovery = CreateWithHidden();
        using (var hidden = OpenHidden())
            hidden.Add(_temp.WriteFile("in/a.txt", [9]));

        using var opened = Vault.OpenHiddenWithRecoveryCode(VaultFilePath, recovery, Fast.Options);
        Assert.True(opened.IsHidden);
        Assert.Equal(["a.txt"], opened.Entries.Select(e => e.Path));

        // The hidden recovery code is not the outer one, and opens nothing outside.
        opened.Dispose();
        Assert.Throws<WrongKeyException>(() => Vault.OpenWithRecoveryCode(VaultFilePath, recovery, Fast.Options));
    }

    [Fact]
    public void TheOuterRecoveryCodeDoesNotOpenTheHiddenVault()
    {
        var (outer, outerRecovery) = Vault.Create(VaultFilePath, _key, Fast.Options);
        using (outer)
            outer.CreateHiddenVault(Password, _key, OneMiB);
        Assert.Throws<WrongKeyException>(() => Vault.OpenHiddenWithRecoveryCode(VaultFilePath, outerRecovery, Fast.Options));
    }

    [Fact]
    public void AFullHiddenVaultReusesTheSpaceOfDeletedFiles()
    {
        CreateWithHidden(OneMiB);
        var first = RandomNumberGenerator.GetBytes(600_000);
        var second = RandomNumberGenerator.GetBytes(600_000);
        var small = RandomNumberGenerator.GetBytes(10_000);
        using (var hidden = OpenHidden())
        {
            hidden.Add(_temp.WriteFile("in/small.bin", small));
            hidden.Add(_temp.WriteFile("in/first.bin", first));
            Assert.Throws<HiddenVaultFullException>(() => hidden.Add(_temp.WriteFile("in/second.bin", second)));
            Assert.Equal(["small.bin", "first.bin"], hidden.Entries.Select(e => e.Path));

            hidden.Remove("first.bin");
            hidden.Add(_temp["in/second.bin"]); // fits only after the hidden vault compacts itself
            Assert.True(hidden.HiddenFreeBytes < OneMiB - 600_000);
        }

        using var reopened = OpenHidden();
        reopened.Extract("/", _temp["out"]);
        Assert.Equal(small, File.ReadAllBytes(_temp["out/small.bin"]));
        Assert.Equal(second, File.ReadAllBytes(_temp["out/second.bin"]));
    }

    [Fact]
    public void PaddingWithAndWithoutAHiddenVaultLooksRandom()
    {
        CreateWithHidden(OneMiB);
        using (var hidden = OpenHidden())
            hidden.Add(_temp.WriteFile("in/secret.txt", Encoding.UTF8.GetBytes(new string('A', 100_000))));
        using (var other = CreateOuterAt(_temp["padded.yvault"]))
            other.SetPadding(OneMiB);

        foreach (var path in new[] { VaultFilePath, _temp["padded.yvault"] })
        {
            var bytes = File.ReadAllBytes(path).AsSpan(VaultFile.KeyAreaStart, VaultFile.DataStart + (int)OneMiB - VaultFile.KeyAreaStart);
            Assert.Equal(-1, bytes.IndexOf("YVF1"u8));
            Assert.Equal(-1, bytes.IndexOf("secret"u8));
            Assert.Equal(-1, bytes.IndexOf(new byte[16]));
            // Every byte value close to equally common, as in random data.
            var counts = new int[256];
            foreach (byte b in bytes)
                counts[b]++;
            double expected = bytes.Length / 256.0;
            double chiSquare = counts.Sum(c => (c - expected) * (c - expected) / expected);
            Assert.InRange(chiSquare, 150, 380);
        }
    }

    [Fact]
    public void NewVaultsHaveARandomKeyArea()
    {
        using (CreateOuter()) { }
        var area = File.ReadAllBytes(VaultFilePath).AsSpan(VaultFile.KeyAreaStart, VaultFile.DataStart - VaultFile.KeyAreaStart);
        Assert.Equal(-1, area.IndexOf(new byte[16]));
    }

    [Fact]
    public void CreatingAHiddenVaultAgainReplacesTheOldOne()
    {
        CreateWithHidden();
        using (var hidden = OpenHidden())
            hidden.Add(_temp.WriteFile("in/old.txt", [1]));
        using (var outer = Vault.OpenWithFido2(VaultFilePath, _key, Fast.Options))
            outer.CreateHiddenVault("new password", _key, OneMiB);

        Assert.Throws<WrongKeyException>(() => OpenHidden());
        using var fresh = OpenHidden("new password");
        Assert.Empty(fresh.Entries);
    }

    [Fact]
    public void AHiddenVaultShowsNoKeysAndCannotChangeThem()
    {
        CreateWithHidden();
        using var hidden = OpenHidden();
        Assert.Empty(hidden.Slots);
        Assert.Throws<VaultException>(() => hidden.AddSecurityKey(new FakeSecurityKey("security-key-2")));
        Assert.Throws<VaultException>(() => hidden.RegenerateRecoveryCode());
        Assert.Throws<VaultException>(() => hidden.CreateHiddenVault("x", _key, OneMiB));
        Assert.Throws<VaultException>(() => hidden.SetPadding(0));
    }

    [Fact]
    public void ADamagedHiddenSuperblockFallsBackToThePreviousCommit()
    {
        CreateWithHidden();
        using (var hidden = OpenHidden())
        {
            hidden.Add(_temp.WriteFile("in/a.txt", [1, 2])); // generation 2, slot A
            hidden.Add(_temp.WriteFile("in/b.txt", [3]));    // generation 3, slot B
        }
        using (var stream = File.OpenWrite(VaultFilePath))
        {
            stream.Position = VaultFile.DataStart + 256 + 20;
            stream.Write(new byte[8]);
        }
        using var reopened = OpenHidden();
        Assert.Equal(["a.txt"], reopened.Entries.Select(e => e.Path));
    }

    [Fact]
    public void OpeningAsksTheKeyOnce()
    {
        CreateWithHidden();
        var key = new FakeSecurityKey("security-key-1");
        using (OpenHidden(key: key)) { }
        Assert.Equal(1, key.Requests);
    }

    [Fact]
    public void PaddingCanBeRemovedAgain()
    {
        using var outer = CreateOuter();
        outer.SetPadding(OneMiB);
        Assert.True(outer.FileSize > OneMiB);
        outer.SetPadding(0);
        Assert.True(outer.FileSize < OneMiB);
        Assert.Equal(0, outer.WastedBytes);
    }
}
