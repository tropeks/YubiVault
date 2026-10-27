using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using YubiVault.Core.Crypto;
using YubiVault.Core.Keys;

namespace YubiVault.Core;

/// <summary>
/// An unlocked vault folder. Layout: <c>vault.yv</c> (key slots), <c>index.yv</c> (encrypted list of
/// files) and <c>data/</c> (one encrypted blob per file, named at random).
/// </summary>
public sealed class Vault : IDisposable
{
    public const string HeaderFileName = "vault.yv";
    public const string IndexFileName = "index.yv";
    public const string DataFolderName = "data";
    public const int ChallengeSize = 64;

    static readonly byte[] IndexContext = "index"u8.ToArray();
    static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    readonly string _folder;
    readonly VaultHeader _header;
    readonly VaultOptions _options;
    readonly byte[] _masterKey;
    List<VaultEntry> _entries;
    bool _disposed;

    Vault(string folder, VaultHeader header, byte[] masterKey, List<VaultEntry> entries, VaultOptions options)
    {
        _folder = folder;
        _header = header;
        _masterKey = masterKey;
        _entries = entries;
        _options = options;
    }

    public string Folder => _folder;
    public IReadOnlyList<KeySlot> Slots => _header.Slots;
    public IReadOnlyList<VaultEntry> Entries => _entries;

    public static bool Exists(string folder) => File.Exists(Path.Combine(folder, HeaderFileName));

    /// <summary>Creates an empty vault opened by <paramref name="yubiKey"/> (plus <paramref name="password"/>, if given).</summary>
    /// <returns>The open vault and the recovery code to show the user once.</returns>
    public static (Vault Vault, string RecoveryCode) Create(string folder, IChallengeResponder yubiKey, string? password,
        VaultOptions? options = null)
    {
        options ??= VaultOptions.Default;
        folder = Path.GetFullPath(folder);
        if (Exists(folder))
            throw new VaultException($"There is already a vault in {folder}.");
        if (Directory.Exists(folder) && Directory.EnumerateFileSystemEntries(folder).Any())
            throw new VaultException($"The folder {folder} is not empty.");

        var header = new VaultHeader { VaultId = RandomNumberGenerator.GetBytes(16) };
        var masterKey = RandomNumberGenerator.GetBytes(KeyWrap.MasterKeySize);
        var vault = new Vault(folder, header, masterKey, [], options);
        try
        {
            vault.AddYubiKeySlot(yubiKey, password);
            string recovery = vault.AddRecoverySlot();
            Directory.CreateDirectory(Path.Combine(folder, DataFolderName));
            vault.SaveIndex();
            vault.SaveHeader();
            return (vault, recovery);
        }
        catch
        {
            vault.Dispose();
            throw;
        }
    }

    /// <summary>Opens the vault with a YubiKey. <paramref name="askPassword"/> is called only if the key's slot needs one.</summary>
    /// <exception cref="WrongKeyException">The YubiKey (or password) does not open this vault.</exception>
    public static Vault OpenWithYubiKey(string folder, IChallengeResponder yubiKey, Func<string> askPassword,
        VaultOptions? options = null)
    {
        var header = ReadHeader(folder);
        var candidates = header.Slots.Where(s => s.Type == KeySlotType.YubiKey && s.Challenge is not null).ToList();
        if (yubiKey.SerialNumber is int serial && candidates.Any(s => s.Serial == serial))
            candidates = candidates.Where(s => s.Serial == serial).ToList();
        if (candidates.Count == 0)
            throw new WrongKeyException("This vault has no YubiKey registered.");

        string? password = null;
        foreach (var slot in candidates)
        {
            if (slot.RequiresPassword)
                password ??= askPassword();
            byte[] response = yubiKey.Respond(slot.Challenge!);
            byte[] kek = KeyWrap.YubiKeyKek(response, slot.Challenge, slot.RequiresPassword ? password : null, slot.Argon2id);
            CryptographicOperations.ZeroMemory(response);
            byte[]? masterKey = KeyWrap.Unwrap(slot, kek, header.VaultId);
            CryptographicOperations.ZeroMemory(kek);
            if (masterKey is not null)
                return Load(folder, header, masterKey, options);
        }
        throw new WrongKeyException(candidates.Any(s => s.RequiresPassword)
            ? "Wrong YubiKey or wrong password."
            : "This YubiKey is not registered in this vault.");
    }

    /// <exception cref="FormatException">The code is not a valid recovery code.</exception>
    /// <exception cref="WrongKeyException">The code does not open this vault.</exception>
    public static Vault OpenWithRecoveryCode(string folder, string recoveryCode, VaultOptions? options = null)
    {
        var header = ReadHeader(folder);
        byte[] code = RecoveryCode.Parse(recoveryCode);
        try
        {
            foreach (var slot in header.Slots.Where(s => s.Type == KeySlotType.Recovery && s.Argon2id is not null))
            {
                byte[] kek = KeyWrap.RecoveryKek(code, slot.Argon2id!);
                byte[]? masterKey = KeyWrap.Unwrap(slot, kek, header.VaultId);
                CryptographicOperations.ZeroMemory(kek);
                if (masterKey is not null)
                    return Load(folder, header, masterKey, options);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(code);
        }
        throw new WrongKeyException("The recovery code does not open this vault.");
    }

    // ---- Key slots ----

    /// <summary>Registers another YubiKey. Files are not re-encrypted.</summary>
    public KeySlot AddYubiKey(IChallengeResponder yubiKey, string? password)
    {
        ThrowIfDisposed();
        var slot = AddYubiKeySlot(yubiKey, password);
        SaveHeader();
        return slot;
    }

    /// <summary>Replaces the recovery code; the old one stops working.</summary>
    public string RegenerateRecoveryCode()
    {
        ThrowIfDisposed();
        _header.Slots.RemoveAll(s => s.Type == KeySlotType.Recovery);
        string code = AddRecoverySlot();
        SaveHeader();
        return code;
    }

    public void RemoveSlot(string slotId)
    {
        ThrowIfDisposed();
        var slot = _header.Slots.FirstOrDefault(s => s.Id == slotId)
            ?? throw new VaultException($"No key slot with id {slotId}.");
        if (_header.Slots.Count == 1)
            throw new VaultException("Cannot remove the last way to open the vault.");
        if (slot.Type == KeySlotType.YubiKey && _header.Slots.Count(s => s.Type == KeySlotType.YubiKey) == 1)
            throw new VaultException("Cannot remove the only YubiKey; register another one first.");
        _header.Slots.Remove(slot);
        SaveHeader();
    }

    KeySlot AddYubiKeySlot(IChallengeResponder yubiKey, string? password)
    {
        if (yubiKey.SerialNumber is int serial && _header.Slots.Any(s => s.Serial == serial))
            throw new VaultException($"The YubiKey {serial} is already registered in this vault.");
        var slot = new KeySlot
        {
            Id = NewSlotId("k"),
            Type = KeySlotType.YubiKey,
            Label = yubiKey.Description,
            Serial = yubiKey.SerialNumber,
            CreatedUtc = DateTime.UtcNow,
            Challenge = RandomNumberGenerator.GetBytes(ChallengeSize),
            Argon2id = string.IsNullOrEmpty(password) ? null : KeyWrap.NewArgon2Settings(_options),
        };
        byte[] response = yubiKey.Respond(slot.Challenge);
        byte[] kek = KeyWrap.YubiKeyKek(response, slot.Challenge, slot.Argon2id is null ? null : password, slot.Argon2id);
        CryptographicOperations.ZeroMemory(response);
        KeyWrap.Wrap(slot, kek, _masterKey, _header.VaultId);
        CryptographicOperations.ZeroMemory(kek);
        _header.Slots.Add(slot);
        return slot;
    }

    string AddRecoverySlot()
    {
        byte[] code = RecoveryCode.Generate();
        var slot = new KeySlot
        {
            Id = NewSlotId("r"),
            Type = KeySlotType.Recovery,
            Label = "Recovery code",
            CreatedUtc = DateTime.UtcNow,
            Argon2id = KeyWrap.NewArgon2Settings(_options),
        };
        byte[] kek = KeyWrap.RecoveryKek(code, slot.Argon2id);
        KeyWrap.Wrap(slot, kek, _masterKey, _header.VaultId);
        CryptographicOperations.ZeroMemory(kek);
        _header.Slots.Add(slot);
        string text = RecoveryCode.Format(code);
        CryptographicOperations.ZeroMemory(code);
        return text;
    }

    string NewSlotId(string prefix)
    {
        for (int n = 1; ; n++)
        {
            string id = prefix + n;
            if (_header.Slots.All(s => s.Id != id))
                return id;
        }
    }

    // ---- Files ----

    /// <summary>Adds a file or a whole folder from disk into <paramref name="vaultFolder"/>, replacing files with the same path.</summary>
    /// <returns>Number of files added.</returns>
    public int Add(string sourcePath, string vaultFolder = "", IProgress<string>? progress = null)
    {
        ThrowIfDisposed();
        vaultFolder = VaultPath.Normalize(vaultFolder);
        sourcePath = Path.GetFullPath(sourcePath);
        string name = Path.GetFileName(sourcePath.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
        string target = VaultPath.Combine(vaultFolder, VaultPath.Normalize(name));

        if (File.Exists(sourcePath))
        {
            AddFile(sourcePath, target, progress);
            SaveIndex();
            return 1;
        }
        if (!Directory.Exists(sourcePath))
            throw new FileNotFoundException("Source not found.", sourcePath);

        int count = 0;
        try
        {
            foreach (var file in Directory.EnumerateFiles(sourcePath, "*", SearchOption.AllDirectories))
            {
                string relative = Path.GetRelativePath(sourcePath, file);
                AddFile(file, VaultPath.Combine(target, VaultPath.Normalize(relative)), progress);
                count++;
            }
        }
        finally
        {
            SaveIndex();
        }
        return count;
    }

    void AddFile(string sourceFile, string vaultPath, IProgress<string>? progress)
    {
        progress?.Report(vaultPath);
        string blobId = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16));
        string blobPath = BlobPath(blobId);
        Directory.CreateDirectory(Path.GetDirectoryName(blobPath)!);
        string temp = blobPath + ".tmp";
        var info = new FileInfo(sourceFile);
        try
        {
            using (var input = new FileStream(sourceFile, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 16))
            using (var output = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None, 1 << 16))
                CascadeCipher.Encrypt(input, output, _masterKey, BlobContext(blobId), _options.ChunkSizeLog2);
            File.Move(temp, blobPath);
        }
        catch
        {
            File.Delete(temp);
            throw;
        }

        var existing = _entries.FindIndex(e => e.Path == vaultPath);
        var entry = new VaultEntry { Path = vaultPath, BlobId = blobId, Size = info.Length, ModifiedUtc = info.LastWriteTimeUtc };
        if (existing >= 0)
        {
            string oldBlob = _entries[existing].BlobId;
            _entries[existing] = entry;
            SaveIndex();
            File.Delete(BlobPath(oldBlob));
        }
        else
        {
            if (_entries.Any(e => VaultPath.IsWithin(e.Path, vaultPath) || VaultPath.IsWithin(vaultPath, e.Path)))
            {
                File.Delete(blobPath);
                throw new VaultException($"{vaultPath} conflicts with an existing file or folder in the vault.");
            }
            _entries.Add(entry);
        }
    }

    /// <summary>Decrypts a file, or every file under a folder, into <paramref name="destinationFolder"/>.</summary>
    /// <returns>Number of files extracted.</returns>
    public int Extract(string vaultPath, string destinationFolder, bool overwrite = false, IProgress<string>? progress = null)
    {
        ThrowIfDisposed();
        vaultPath = VaultPath.Normalize(vaultPath);
        var selected = _entries.Where(e => VaultPath.IsWithin(e.Path, vaultPath)).ToList();
        if (selected.Count == 0)
            throw new VaultException($"Nothing in the vault at {(vaultPath.Length == 0 ? "/" : vaultPath)}.");

        string destination = Path.GetFullPath(destinationFolder);
        string parent = VaultPath.Parent(vaultPath);
        foreach (var entry in selected)
        {
            string relative = parent.Length == 0 ? entry.Path : entry.Path[(parent.Length + 1)..];
            string target = Path.GetFullPath(Path.Combine(destination, relative.Replace('/', Path.DirectorySeparatorChar)));
            if (!target.StartsWith(destination.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar, StringComparison.Ordinal))
                throw new VaultException($"Refusing to extract {entry.Path} outside the destination folder.");
            if (File.Exists(target) && !overwrite)
                throw new VaultException($"{target} already exists.");

            progress?.Report(entry.Path);
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            string temp = target + ".yvpart";
            try
            {
                using (var input = File.OpenRead(BlobPath(entry.BlobId)))
                using (var output = new FileStream(temp, FileMode.Create, FileAccess.Write, FileShare.None, 1 << 16))
                    CascadeCipher.Decrypt(input, output, _masterKey, BlobContext(entry.BlobId));
                File.Move(temp, target, overwrite);
                File.SetLastWriteTimeUtc(target, entry.ModifiedUtc);
            }
            catch (Exception e) when (e is not VaultException)
            {
                File.Delete(temp);
                throw new VaultException($"Could not decrypt {entry.Path}: the data is damaged or was tampered with.", e);
            }
        }
        return selected.Count;
    }

    /// <summary>Deletes a file, or a folder and everything in it, from the vault.</summary>
    /// <returns>Number of files removed.</returns>
    public int Remove(string vaultPath)
    {
        ThrowIfDisposed();
        vaultPath = VaultPath.Normalize(vaultPath);
        if (vaultPath.Length == 0)
            throw new VaultException("Refusing to remove the whole vault; name a file or folder.");
        var removed = _entries.Where(e => VaultPath.IsWithin(e.Path, vaultPath)).ToList();
        if (removed.Count == 0)
            throw new VaultException($"Nothing in the vault at {vaultPath}.");
        _entries = _entries.Except(removed).ToList();
        SaveIndex();
        foreach (var entry in removed)
            File.Delete(BlobPath(entry.BlobId));
        return removed.Count;
    }

    // ---- Storage ----

    static VaultHeader ReadHeader(string folder)
    {
        string path = Path.Combine(folder, HeaderFileName);
        if (!File.Exists(path))
            throw new VaultException($"No vault found in {Path.GetFullPath(folder)}.");
        VaultHeader? header;
        try
        {
            header = JsonSerializer.Deserialize<VaultHeader>(File.ReadAllBytes(path), JsonOptions);
        }
        catch (JsonException e)
        {
            throw new VaultException("The vault header is damaged.", e);
        }
        if (header is null || header.Format != VaultHeader.FormatName)
            throw new VaultException("Not a YubiVault vault.");
        if (header.Version != VaultHeader.CurrentVersion)
            throw new VaultException($"Unsupported vault version {header.Version}; update YubiVault.");
        return header;
    }

    static Vault Load(string folder, VaultHeader header, byte[] masterKey, VaultOptions? options)
    {
        folder = Path.GetFullPath(folder);
        var vault = new Vault(folder, header, masterKey, [], options ?? VaultOptions.Default);
        try
        {
            using var input = File.OpenRead(Path.Combine(folder, IndexFileName));
            using var plain = new MemoryStream();
            CascadeCipher.Decrypt(input, plain, masterKey, IndexContext);
            vault._entries = JsonSerializer.Deserialize<List<VaultEntry>>(plain.GetBuffer().AsSpan(0, (int)plain.Length)) ?? [];
            CryptographicOperations.ZeroMemory(plain.GetBuffer());
            return vault;
        }
        catch (Exception e)
        {
            vault.Dispose();
            throw new VaultException("The vault index is missing, damaged or was tampered with.", e);
        }
    }

    void SaveHeader() => WriteAtomically(Path.Combine(_folder, HeaderFileName),
        output => JsonSerializer.Serialize(output, _header, JsonOptions));

    void SaveIndex()
    {
        byte[] json = JsonSerializer.SerializeToUtf8Bytes(_entries);
        try
        {
            WriteAtomically(Path.Combine(_folder, IndexFileName), output =>
            {
                using var input = new MemoryStream(json, writable: false);
                CascadeCipher.Encrypt(input, output, _masterKey, IndexContext, _options.ChunkSizeLog2);
            });
        }
        finally
        {
            CryptographicOperations.ZeroMemory(json);
        }
    }

    static void WriteAtomically(string path, Action<Stream> write)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        string temp = path + ".tmp";
        using (var output = new FileStream(temp, FileMode.Create, FileAccess.Write, FileShare.None))
        {
            write(output);
            output.Flush(flushToDisk: true);
        }
        File.Move(temp, path, overwrite: true);
    }

    string BlobPath(string blobId) => Path.Combine(_folder, DataFolderName, blobId[..2], blobId + ".yvb");

    static byte[] BlobContext(string blobId) => Encoding.ASCII.GetBytes("blob:" + blobId);

    void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(_disposed, this);

    /// <summary>Locks the vault: the master key is wiped from memory.</summary>
    public void Dispose()
    {
        if (_disposed)
            return;
        CryptographicOperations.ZeroMemory(_masterKey);
        _disposed = true;
    }
}
