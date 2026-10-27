using System.Security.Cryptography;
using YubiVault.Core;

namespace YubiVault.Core.Tests;

public class VaultTests : IDisposable
{
    readonly TempFolder _temp = new();
    readonly FakeYubiKey _key = new("primary", serial: 1001);

    public void Dispose() => _temp.Dispose();

    string VaultFolder => _temp["vault"];

    (Vault Vault, string Recovery) CreateVault(string? password = null) =>
        Vault.Create(VaultFolder, _key, password, Fast.Options);

    Vault Open(FakeYubiKey? key = null, string? password = null) =>
        Vault.OpenWithYubiKey(VaultFolder, key ?? _key, () => password ?? throw new Exception("No password expected"), Fast.Options);

    [Fact]
    public void FilesSurviveCloseAndReopen()
    {
        var content = RandomNumberGenerator.GetBytes(5000);
        string source = _temp.WriteFile("in/report.pdf", content);
        var (vault, _) = CreateVault();
        using (vault)
            vault.Add(source);

        using var reopened = Open();
        var entry = Assert.Single(reopened.Entries);
        Assert.Equal("report.pdf", entry.Path);
        Assert.Equal(5000, entry.Size);

        reopened.Extract("report.pdf", _temp["out"]);
        Assert.Equal(content, File.ReadAllBytes(_temp["out/report.pdf"]));
    }

    [Fact]
    public void NothingReadableIsStoredOnDisk()
    {
        string source = _temp.WriteFile("in/secret-plans.txt", "TOP SECRET CONTENT"u8.ToArray());
        var (vault, _) = CreateVault();
        using (vault)
            vault.Add(source);

        foreach (var file in Directory.EnumerateFiles(VaultFolder, "*", SearchOption.AllDirectories))
        {
            Assert.DoesNotContain("secret-plans", file);
            string bytes = System.Text.Encoding.Latin1.GetString(File.ReadAllBytes(file));
            Assert.DoesNotContain("TOP SECRET", bytes);
            Assert.DoesNotContain("secret-plans", bytes);
        }
    }

    [Fact]
    public void FoldersKeepTheirStructure()
    {
        _temp.WriteFile("in/Photos/2025/a.jpg", [1]);
        _temp.WriteFile("in/Photos/2025/b.jpg", [2]);
        _temp.WriteFile("in/Photos/c.jpg", [3]);
        var (vault, _) = CreateVault();
        using (vault)
        {
            Assert.Equal(3, vault.Add(_temp["in/Photos"], "Backup"));
            Assert.Equal(["Backup/Photos/2025/a.jpg", "Backup/Photos/2025/b.jpg", "Backup/Photos/c.jpg"],
                vault.Entries.Select(e => e.Path).Order());

            Assert.Equal(2, vault.Extract("Backup/Photos/2025", _temp["out"]));
            Assert.Equal([2], File.ReadAllBytes(_temp["out/2025/b.jpg"]));

            Assert.Equal(3, vault.Extract("/", _temp["all"]));
            Assert.Equal([3], File.ReadAllBytes(_temp["all/Backup/Photos/c.jpg"]));
        }
    }

    [Fact]
    public void AddingTheSamePathReplacesTheFile()
    {
        string source = _temp.WriteFile("in/notes.txt", "v1"u8.ToArray());
        var (vault, _) = CreateVault();
        using (vault)
        {
            vault.Add(source);
            File.WriteAllBytes(source, "version 2"u8.ToArray());
            vault.Add(source);
            Assert.Single(vault.Entries);
            vault.Extract("notes.txt", _temp["out"]);
        }
        Assert.Equal("version 2", File.ReadAllText(_temp["out/notes.txt"]));
        Assert.Single(Directory.EnumerateFiles(Path.Combine(VaultFolder, "data"), "*.yvb", SearchOption.AllDirectories));
    }

    [Fact]
    public void RemoveDeletesEntriesAndBlobs()
    {
        _temp.WriteFile("in/docs/a.txt", [1]);
        _temp.WriteFile("in/docs/b.txt", [2]);
        var (vault, _) = CreateVault();
        using (vault)
        {
            vault.Add(_temp["in/docs"]);
            Assert.Equal(2, vault.Remove("docs"));
            Assert.Empty(vault.Entries);
        }
        Assert.Empty(Directory.EnumerateFiles(Path.Combine(VaultFolder, "data"), "*", SearchOption.AllDirectories));
    }

    [Fact]
    public void ExtractDoesNotOverwriteUnlessAsked()
    {
        string source = _temp.WriteFile("in/a.txt", [1]);
        _temp.WriteFile("out/a.txt", [9]);
        var (vault, _) = CreateVault();
        using (vault)
        {
            vault.Add(source);
            Assert.Throws<VaultException>(() => vault.Extract("a.txt", _temp["out"]));
            Assert.Equal([9], File.ReadAllBytes(_temp["out/a.txt"]));
            vault.Extract("a.txt", _temp["out"], overwrite: true);
        }
        Assert.Equal([1], File.ReadAllBytes(_temp["out/a.txt"]));
    }

    [Fact]
    public void AnotherYubiKeyCannotOpen()
    {
        CreateVault().Vault.Dispose();
        Assert.Throws<WrongKeyException>(() => Open(new FakeYubiKey("someone else", serial: 2002)));
        Assert.Throws<WrongKeyException>(() => Open(new FakeYubiKey("someone else", serial: 1001)));
    }

    [Fact]
    public void PasswordIsRequiredWhenSet()
    {
        CreateVault(password: "correct horse").Vault.Dispose();
        Assert.Throws<WrongKeyException>(() => Open(password: "wrong"));
        using var vault = Open(password: "correct horse");
        Assert.Empty(vault.Entries);
    }

    [Fact]
    public void NoPasswordPromptWithoutPassword()
    {
        CreateVault().Vault.Dispose();
        using var vault = Open(); // Open() throws if asked for a password
        Assert.Empty(vault.Entries);
    }

    [Fact]
    public void SerialNumberAvoidsExtraTouches()
    {
        var (vault, _) = CreateVault();
        using (vault)
            vault.AddYubiKey(new FakeYubiKey("backup", serial: 3003), null);

        var backup = new FakeYubiKey("backup", serial: 3003);
        using (Open(backup)) { }
        Assert.Equal(1, backup.Touches);
    }

    [Fact]
    public void RecoveryCodeOpensTheVault()
    {
        string source = _temp.WriteFile("in/a.txt", [42]);
        var (vault, recovery) = CreateVault(password: "pw");
        using (vault)
            vault.Add(source);

        using var recovered = Vault.OpenWithRecoveryCode(VaultFolder, recovery.ToLowerInvariant(), Fast.Options);
        recovered.Extract("a.txt", _temp["out"]);
        Assert.Equal([42], File.ReadAllBytes(_temp["out/a.txt"]));
    }

    [Fact]
    public void WrongRecoveryCodeIsRejected()
    {
        CreateVault().Vault.Dispose();
        string other = Keys.RecoveryCode.Format(Keys.RecoveryCode.Generate());
        Assert.Throws<WrongKeyException>(() => Vault.OpenWithRecoveryCode(VaultFolder, other, Fast.Options));
    }

    [Fact]
    public void NewRecoveryCodeReplacesTheOldOne()
    {
        var (vault, oldCode) = CreateVault();
        string newCode;
        using (vault)
            newCode = vault.RegenerateRecoveryCode();

        Assert.Throws<WrongKeyException>(() => Vault.OpenWithRecoveryCode(VaultFolder, oldCode, Fast.Options));
        using var reopened = Vault.OpenWithRecoveryCode(VaultFolder, newCode, Fast.Options);
    }

    [Fact]
    public void SecondYubiKeyOpensWithoutReencrypting()
    {
        string source = _temp.WriteFile("in/a.txt", [7]);
        var (vault, _) = CreateVault();
        using (vault)
        {
            vault.Add(source);
            vault.AddYubiKey(new FakeYubiKey("backup", serial: 3003), password: "backup-pw");
        }

        using var opened = Open(new FakeYubiKey("backup", serial: 3003), password: "backup-pw");
        opened.Extract("a.txt", _temp["out"]);
        Assert.Equal([7], File.ReadAllBytes(_temp["out/a.txt"]));
    }

    [Fact]
    public void RemovedYubiKeyNoLongerOpens()
    {
        var (vault, _) = CreateVault();
        using (vault)
        {
            var backup = vault.AddYubiKey(new FakeYubiKey("backup", serial: 3003), null);
            vault.RemoveSlot(backup.Id);
        }
        Assert.Throws<WrongKeyException>(() => Open(new FakeYubiKey("backup", serial: 3003)));
    }

    [Fact]
    public void TheOnlyYubiKeyCannotBeRemoved()
    {
        var (vault, _) = CreateVault();
        using (vault)
            Assert.Throws<VaultException>(() => vault.RemoveSlot(vault.Slots.First(s => s.Type == KeySlotType.YubiKey).Id));
    }

    [Fact]
    public void SameYubiKeyCannotBeRegisteredTwice()
    {
        var (vault, _) = CreateVault();
        using (vault)
            Assert.Throws<VaultException>(() => vault.AddYubiKey(new FakeYubiKey("primary", serial: 1001), null));
    }

    [Fact]
    public void TamperedBlobFailsToExtract()
    {
        string source = _temp.WriteFile("in/a.txt", RandomNumberGenerator.GetBytes(3000));
        var (vault, _) = CreateVault();
        using (vault)
            vault.Add(source);

        string blob = Directory.EnumerateFiles(Path.Combine(VaultFolder, "data"), "*.yvb", SearchOption.AllDirectories).Single();
        var bytes = File.ReadAllBytes(blob);
        bytes[100] ^= 0xFF;
        File.WriteAllBytes(blob, bytes);

        using var reopened = Open();
        Assert.Throws<VaultException>(() => reopened.Extract("a.txt", _temp["out"]));
        Assert.False(File.Exists(_temp["out/a.txt"]));
        Assert.Empty(Directory.EnumerateFiles(_temp["out"]));
    }

    [Fact]
    public void SwappedBlobsAreDetected()
    {
        _temp.WriteFile("in/x/a.txt", RandomNumberGenerator.GetBytes(100));
        _temp.WriteFile("in/x/b.txt", RandomNumberGenerator.GetBytes(100));
        var (vault, _) = CreateVault();
        using (vault)
            vault.Add(_temp["in/x"]);

        var blobs = Directory.EnumerateFiles(Path.Combine(VaultFolder, "data"), "*.yvb", SearchOption.AllDirectories).ToList();
        var first = File.ReadAllBytes(blobs[0]);
        File.Copy(blobs[1], blobs[0], overwrite: true);
        File.WriteAllBytes(blobs[1], first);

        using var reopened = Open();
        Assert.Throws<VaultException>(() => reopened.Extract("x", _temp["out"]));
    }

    [Fact]
    public void TamperedHeaderSlotIsRejected()
    {
        CreateVault().Vault.Dispose();
        string headerPath = Path.Combine(VaultFolder, Vault.HeaderFileName);
        // Changing a slot's type or password flag invalidates its wrapped key.
        File.WriteAllText(headerPath, File.ReadAllText(headerPath).Replace("\"k1\"", "\"k9\""));
        Assert.Throws<WrongKeyException>(() => Open());
    }

    [Fact]
    public void PathsCannotEscapeTheVault()
    {
        var (vault, _) = CreateVault();
        using (vault)
        {
            string source = _temp.WriteFile("in/a.txt", [1]);
            Assert.Throws<ArgumentException>(() => vault.Add(source, "../outside"));
            Assert.Throws<ArgumentException>(() => vault.Extract("../../etc", _temp["out"]));
        }
    }

    [Fact]
    public void CreateRefusesNonEmptyFolder()
    {
        _temp.WriteFile("vault/existing.txt", [1]);
        Assert.Throws<VaultException>(() => CreateVault());
    }

    [Fact]
    public void LockedVaultCannotBeUsed()
    {
        var (vault, _) = CreateVault();
        vault.Dispose();
        Assert.Throws<ObjectDisposedException>(() => vault.Extract("/", _temp["out"]));
    }
}
