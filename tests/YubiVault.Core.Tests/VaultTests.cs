using System.Security.Cryptography;
using YubiVault.Core;

namespace YubiVault.Core.Tests;

public class VaultTests : IDisposable
{
    readonly TempFolder _temp = new();
    readonly FakeYubiKey _key = new("primary", serial: 1001);

    public void Dispose() => _temp.Dispose();

    string VaultFilePath => _temp["test.yvault"];

    (Vault Vault, string Recovery) CreateVault(string? password = null) =>
        Vault.Create(VaultFilePath, _key, password, Fast.Options);

    Vault Open(FakeYubiKey? key = null, string? password = null) =>
        Vault.OpenWithYubiKey(VaultFilePath, key ?? _key, () => password ?? throw new Exception("No password expected"), Fast.Options);

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

        Assert.Equal([VaultFilePath], Directory.EnumerateFiles(_temp.Path));
        string bytes = System.Text.Encoding.Latin1.GetString(File.ReadAllBytes(VaultFilePath));
        Assert.DoesNotContain("TOP SECRET", bytes);
        Assert.DoesNotContain("secret-plans", bytes);
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
            Assert.True(vault.WastedBytes > 0);
            vault.Compact();
            Assert.Equal(0, vault.WastedBytes);
        }
        using var reopened = Open();
        reopened.Extract("notes.txt", _temp["out"]);
        Assert.Equal("version 2", File.ReadAllText(_temp["out/notes.txt"]));
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
        using var reopened = Open();
        Assert.Empty(reopened.Entries);
    }

    [Fact]
    public void LargeDeletionsCompactTheFile()
    {
        string big = _temp.WriteFile("in/big.bin", RandomNumberGenerator.GetBytes(3 << 20));
        string small = _temp.WriteFile("in/small.txt", "keep me"u8.ToArray());
        var (vault, _) = CreateVault();
        using (vault)
        {
            vault.Add(big);
            vault.Add(small);
            Assert.True(vault.FileSize > 3 << 20);
            vault.Remove("big.bin");
            Assert.True(vault.FileSize < 1 << 20);
            Assert.Equal(0, vault.WastedBytes);
        }
        Assert.False(File.Exists(VaultFilePath + ".compacting"));
        using var reopened = Open();
        reopened.Extract("small.txt", _temp["out"]);
        Assert.Equal("keep me", File.ReadAllText(_temp["out/small.txt"]));
    }

    [Fact]
    public void AnInterruptedWriteLeavesThePreviousState()
    {
        string source = _temp.WriteFile("in/a.txt", [1, 2, 3]);
        var (vault, _) = CreateVault();
        using (vault)
            vault.Add(source);
        // Bytes written after the last commit (e.g. power loss mid-add) are ignored and dropped.
        using (var file = new FileStream(VaultFilePath, FileMode.Append))
            file.Write(RandomNumberGenerator.GetBytes(5000));
        using (var reopened = Open())
        {
            Assert.Single(reopened.Entries);
            reopened.Add(_temp.WriteFile("in/b.txt", [4]));
        }
        using var again = Open();
        Assert.Equal(2, again.Entries.Count);
    }

    [Fact]
    public void ADamagedSuperblockFallsBackToThePreviousCommit()
    {
        string source = _temp.WriteFile("in/a.txt", [1]);
        var (vault, _) = CreateVault();
        using (vault)
            vault.Add(source); // second commit, written to the first superblock
        using (var file = new FileStream(VaultFilePath, FileMode.Open))
        {
            file.Position = 20;
            file.WriteByte(0xFF);
        }
        using var reopened = Open();
        Assert.Empty(reopened.Entries);
    }

    [Fact]
    public void AnOpenVaultCannotBeOpenedTwice()
    {
        if (!OperatingSystem.IsWindows())
            return; // file sharing modes are only enforced on Windows
        var (vault, _) = CreateVault();
        using (vault)
        {
            Assert.NotEmpty(Vault.ReadKeySlots(VaultFilePath));
            var e = Assert.Throws<VaultException>(() => Open());
            Assert.Contains("open in another", e.Message);
        }
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

        using var recovered = Vault.OpenWithRecoveryCode(VaultFilePath, recovery.ToLowerInvariant(), Fast.Options);
        recovered.Extract("a.txt", _temp["out"]);
        Assert.Equal([42], File.ReadAllBytes(_temp["out/a.txt"]));
    }

    [Fact]
    public void WrongRecoveryCodeIsRejected()
    {
        CreateVault().Vault.Dispose();
        string other = Keys.RecoveryCode.Format(Keys.RecoveryCode.Generate());
        Assert.Throws<WrongKeyException>(() => Vault.OpenWithRecoveryCode(VaultFilePath, other, Fast.Options));
    }

    [Fact]
    public void NewRecoveryCodeReplacesTheOldOne()
    {
        var (vault, oldCode) = CreateVault();
        string newCode;
        using (vault)
            newCode = vault.RegenerateRecoveryCode();

        Assert.Throws<WrongKeyException>(() => Vault.OpenWithRecoveryCode(VaultFilePath, oldCode, Fast.Options));
        using var reopened = Vault.OpenWithRecoveryCode(VaultFilePath, newCode, Fast.Options);
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
        long offset;
        using (vault)
        {
            vault.Add(source);
            offset = vault.Entries.Single().Offset;
        }

        var bytes = File.ReadAllBytes(VaultFilePath);
        bytes[offset + 100] ^= 0xFF;
        File.WriteAllBytes(VaultFilePath, bytes);

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
        VaultEntry a, b;
        using (vault)
        {
            vault.Add(_temp["in/x"]);
            (a, b) = (vault.Entries[0], vault.Entries[1]);
        }

        var bytes = File.ReadAllBytes(VaultFilePath);
        Assert.Equal(a.Length, b.Length);
        var first = bytes.AsSpan((int)a.Offset, (int)a.Length).ToArray();
        bytes.AsSpan((int)b.Offset, (int)b.Length).CopyTo(bytes.AsSpan((int)a.Offset));
        first.CopyTo(bytes.AsSpan((int)b.Offset));
        File.WriteAllBytes(VaultFilePath, bytes);

        using var reopened = Open();
        Assert.Throws<VaultException>(() => reopened.Extract("x", _temp["out"]));
    }

    [Fact]
    public void TamperedHeaderSlotIsRejected()
    {
        CreateVault().Vault.Dispose();
        // Changing a slot's id, type or password flag invalidates its wrapped key.
        var text = System.Text.Encoding.Latin1.GetString(File.ReadAllBytes(VaultFilePath));
        Assert.Contains("\"k1\"", text);
        File.WriteAllBytes(VaultFilePath, System.Text.Encoding.Latin1.GetBytes(text.Replace("\"k1\"", "\"k9\"")));
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
    public void CreateRefusesAnExistingFile()
    {
        _temp.WriteFile("test.yvault", [1]);
        Assert.Throws<VaultException>(() => CreateVault());
        Assert.Equal([1], File.ReadAllBytes(VaultFilePath));
    }

    [Fact]
    public void LockedVaultCannotBeUsed()
    {
        var (vault, _) = CreateVault();
        vault.Dispose();
        Assert.Throws<ObjectDisposedException>(() => vault.Extract("/", _temp["out"]));
    }
}

public class Fido2VaultTests : IDisposable
{
    readonly TempFolder _temp = new();
    readonly FakeSecurityKey _key = new("security-key-1");

    public void Dispose() => _temp.Dispose();

    string VaultFilePath => _temp["test.yvault"];

    [Fact]
    public void SecurityKeyCreatesAndOpensTheVault()
    {
        string source = _temp.WriteFile("in/a.txt", [5, 6]);
        var (vault, _) = Vault.Create(VaultFilePath, _key, Fast.Options);
        using (vault)
            vault.Add(source);

        var slot = Assert.Single(Vault.ReadKeySlots(VaultFilePath), s => s.Type == KeySlotType.Fido2);
        Assert.NotNull(slot.CredentialId);
        Assert.Equal(Vault.Fido2SaltSize, slot.Challenge!.Length);

        using var reopened = Vault.OpenWithFido2(VaultFilePath, _key, Fast.Options);
        reopened.Extract("a.txt", _temp["out"]);
        Assert.Equal([5, 6], File.ReadAllBytes(_temp["out/a.txt"]));
    }

    [Fact]
    public void OpeningAsksTheKeyOnce()
    {
        Vault.Create(VaultFilePath, _key, Fast.Options).Vault.Dispose();
        var key = new FakeSecurityKey("security-key-1");
        using (Vault.OpenWithFido2(VaultFilePath, key, Fast.Options)) { }
        Assert.Equal(1, key.Requests);
    }

    [Fact]
    public void AnotherSecurityKeyCannotOpen()
    {
        Vault.Create(VaultFilePath, _key, Fast.Options).Vault.Dispose();
        Assert.ThrowsAny<VaultException>(() => Vault.OpenWithFido2(VaultFilePath, new FakeSecurityKey("other"), Fast.Options));
    }

    [Fact]
    public void RecoveryCodeOpensASecurityKeyVault()
    {
        var (vault, recovery) = Vault.Create(VaultFilePath, _key, Fast.Options);
        vault.Dispose();
        using var opened = Vault.OpenWithRecoveryCode(VaultFilePath, recovery, Fast.Options);
    }

    [Fact]
    public void SecondSecurityKeyAndYubiKeyOtpCanBeAdded()
    {
        var (vault, _) = Vault.Create(VaultFilePath, _key, Fast.Options);
        using (vault)
        {
            vault.AddSecurityKey(new FakeSecurityKey("security-key-2"));
            vault.AddYubiKey(new FakeYubiKey("otp", serial: 7), null);
        }
        using (Vault.OpenWithFido2(VaultFilePath, new FakeSecurityKey("security-key-2"), Fast.Options)) { }
        using (Vault.OpenWithYubiKey(VaultFilePath, new FakeYubiKey("otp", serial: 7), () => "", Fast.Options)) { }
    }

    [Fact]
    public void OnlySecurityKeyCannotBeRemoved()
    {
        var (vault, _) = Vault.Create(VaultFilePath, _key, Fast.Options);
        using (vault)
            Assert.Throws<VaultException>(() => vault.RemoveSlot(vault.Slots.First(s => s.Type == KeySlotType.Fido2).Id));
    }
}

public class VaultMoveTests : IDisposable
{
    readonly TempFolder _temp = new();
    readonly FakeYubiKey _key = new("primary", serial: 1001);

    public void Dispose() => _temp.Dispose();

    Vault NewVaultWith(params string[] files)
    {
        foreach (var file in files)
            _temp.WriteFile(Path.Combine("in", file), [1]);
        var (vault, _) = Vault.Create(_temp["test.yvault"], _key, null, Fast.Options);
        foreach (var top in files.Select(f => f.Split('/')[0]).Distinct())
            vault.Add(_temp[Path.Combine("in", top)]);
        return vault;
    }

    [Fact]
    public void RenamesAFileAndKeepsItAfterReopen()
    {
        using (var vault = NewVaultWith("a.txt"))
            Assert.Equal(1, vault.Move("a.txt", "b.txt"));
        using var reopened = Vault.OpenWithYubiKey(_temp["test.yvault"], _key, () => "", Fast.Options);
        Assert.Equal("b.txt", Assert.Single(reopened.Entries).Path);
        reopened.Extract("b.txt", _temp["out"]);
        Assert.True(File.Exists(_temp["out/b.txt"]));
    }

    [Fact]
    public void MovesAWholeFolder()
    {
        using var vault = NewVaultWith("docs/x.txt", "docs/sub/y.txt", "other.txt");
        Assert.Equal(2, vault.Move("docs", "Archive/docs"));
        Assert.Equal(["Archive/docs/sub/y.txt", "Archive/docs/x.txt", "other.txt"], vault.Entries.Select(e => e.Path).Order());
    }

    [Fact]
    public void RefusesToOverwriteOrNestIntoItself()
    {
        using var vault = NewVaultWith("a.txt", "b.txt", "docs/x.txt");
        Assert.Throws<VaultException>(() => vault.Move("a.txt", "b.txt"));
        Assert.Throws<VaultException>(() => vault.Move("docs", "docs/inner"));
        Assert.Throws<VaultException>(() => vault.Move("missing", "z"));
    }

    [Fact]
    public void KeySlotsCanBeReadWhileLocked()
    {
        using (Vault.Create(_temp["test.yvault"], _key, "pw", Fast.Options).Vault) { }
        var slots = Vault.ReadKeySlots(_temp["test.yvault"]);
        Assert.Contains(slots, s => s.Type == KeySlotType.YubiKey && s.RequiresPassword && s.Serial == 1001);
        Assert.Contains(slots, s => s.Type == KeySlotType.Recovery);
    }
}
