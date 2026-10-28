using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using YubiVault.Core.Crypto;
using YubiVault.Core.Keys;

namespace YubiVault.Core;

/// <summary>
/// An unlocked vault: a single <c>.yvault</c> file holding the key slots, the encrypted list of
/// files and one encrypted blob per file (see <see cref="VaultFile"/> and docs/format.md).
/// </summary>
public sealed class Vault : IDisposable
{
    public const string FileExtension = ".yvault";
    public const int ChallengeSize = 64;
    public const int Fido2SaltSize = 32;
    public const string Fido2RelyingPartyId = "yubivault";

    /// <summary>Saves compact the file by themselves once this much (and a quarter of it) is unused.</summary>
    const long MinWasteToCompact = 1 << 20;

    static readonly byte[] IndexContext = "index"u8.ToArray();
    static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    readonly string _path;
    readonly VaultHeader _header;
    readonly VaultOptions _options;
    const string NoHiddenVault = "No hidden vault opens with this password.";

    readonly byte[] _masterKey;
    VaultFile _file;
    readonly HiddenStore? _hidden;
    List<VaultEntry> _entries;
    bool _disposed;

    Vault(string path, VaultFile file, VaultHeader header, byte[] masterKey, List<VaultEntry> entries, VaultOptions options,
        HiddenStore? hidden = null)
    {
        _path = path;
        _file = file;
        _header = header;
        _masterKey = masterKey;
        _entries = entries;
        _options = options;
        _hidden = hidden;
    }

    /// <summary>Full path of the vault file.</summary>
    public string FilePath => _path;

    /// <summary>Key slots of the vault; a hidden vault shows none (its slots are hidden too).</summary>
    public IReadOnlyList<KeySlot> Slots => _hidden is null ? _header.Slots : [];
    public IReadOnlyList<VaultEntry> Entries => _entries;

    /// <summary>True for a hidden vault opened from inside another vault's padding.</summary>
    public bool IsHidden => _hidden is not null;

    /// <summary>Bytes of random padding in the vault file (where a hidden vault may live).</summary>
    public long Padding => _header.Padding;

    /// <summary>Size of the vault file in bytes.</summary>
    public long FileSize => _file.Length;

    /// <summary>Space for files in a hidden vault; null for a normal vault.</summary>
    public long? HiddenCapacity => _hidden?.Capacity;

    /// <summary>Space still free in a hidden vault, counting space a compaction would free; null for a normal vault.</summary>
    public long? HiddenFreeBytes => _hidden is null ? null : _hidden.Capacity - (_hidden.End - HiddenStore.RecordsStart) + WastedBytes;

    /// <summary>Bytes taken by deleted or replaced files, freed by <see cref="Compact"/>.</summary>
    public long WastedBytes => _hidden is null
        ? _file.End - VaultFile.DataStart - _header.Padding - _file.HeaderLength - _file.IndexLength - _entries.Sum(e => e.Length)
        : _hidden.End - HiddenStore.RecordsStart - _hidden.IndexLength - _entries.Sum(e => e.Length);

    IRecordStore Store => (IRecordStore?)_hidden ?? _file;

    public static bool Exists(string path) => VaultFile.LooksLikeVault(path);

    /// <summary>Reads the key slots of a locked vault, e.g. to know which kind of key will open it.</summary>
    public static IReadOnlyList<KeySlot> ReadKeySlots(string path)
    {
        using var file = VaultFile.Open(path, writable: false);
        return ReadHeader(file).Slots;
    }

    /// <summary>Creates an empty vault file opened by <paramref name="yubiKey"/> (plus <paramref name="password"/>, if given).</summary>
    /// <returns>The open vault and the recovery code to show the user once.</returns>
    public static (Vault Vault, string RecoveryCode) Create(string path, IChallengeResponder yubiKey, string? password,
        VaultOptions? options = null) =>
        CreateWith(path, options, vault => vault.AddYubiKeySlot(yubiKey, password));

    /// <summary>Creates an empty vault file opened by a FIDO2 security key (PIN and touch).</summary>
    /// <returns>The open vault and the recovery code to show the user once.</returns>
    public static (Vault Vault, string RecoveryCode) Create(string path, IFido2Authenticator securityKey, VaultOptions? options = null) =>
        CreateWith(path, options, vault => vault.AddFido2Slot(securityKey));

    static (Vault Vault, string RecoveryCode) CreateWith(string path, VaultOptions? options, Action<Vault> addFirstKey)
    {
        options ??= VaultOptions.Default;
        path = Path.GetFullPath(path);
        if (File.Exists(path) || Directory.Exists(path))
            throw new VaultException($"{path} already exists.");
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);

        var header = new VaultHeader { VaultId = RandomNumberGenerator.GetBytes(16) };
        var masterKey = RandomNumberGenerator.GetBytes(KeyWrap.MasterKeySize);
        var vault = new Vault(path, VaultFile.Create(path), header, masterKey, [], options);
        try
        {
            addFirstKey(vault);
            string recovery = vault.AddRecoverySlot();
            vault.Save(header: true);
            return (vault, recovery);
        }
        catch
        {
            vault.Dispose();
            File.Delete(path);
            throw;
        }
    }

    /// <summary>Opens the vault with a FIDO2 security key registered in it (one PIN entry and touch).</summary>
    /// <exception cref="WrongKeyException">The key is not registered in this vault.</exception>
    public static Vault OpenWithFido2(string path, IFido2Authenticator securityKey, VaultOptions? options = null) =>
        Open(path, options, header =>
        {
            var slots = header.Slots
                .Where(s => s.Type == KeySlotType.Fido2 && s.CredentialId is not null && s.Challenge is not null)
                .ToList();
            if (slots.Count == 0)
                throw new WrongKeyException("This vault has no security key registered.");

            foreach (var group in slots.GroupBy(s => s.RelyingPartyId ?? Fido2RelyingPartyId))
            {
                var (credentialId, secret) = securityKey.GetSecret(group.Key,
                    group.Select(s => (s.CredentialId!, s.Challenge!)).ToList());
                var slot = group.FirstOrDefault(s => s.CredentialId!.AsSpan().SequenceEqual(credentialId));
                if (slot is null)
                    continue;
                byte[] kek = KeyWrap.Fido2Kek(secret, slot.Challenge);
                CryptographicOperations.ZeroMemory(secret);
                byte[]? masterKey = KeyWrap.Unwrap(slot, kek, header.VaultId);
                CryptographicOperations.ZeroMemory(kek);
                if (masterKey is not null)
                    return masterKey;
            }
            throw new WrongKeyException("This security key is not registered in this vault.");
        });

    /// <summary>Opens the vault with a YubiKey. <paramref name="askPassword"/> is called only if the key's slot needs one.</summary>
    /// <exception cref="WrongKeyException">The YubiKey (or password) does not open this vault.</exception>
    public static Vault OpenWithYubiKey(string path, IChallengeResponder yubiKey, Func<string> askPassword,
        VaultOptions? options = null) =>
        Open(path, options, header =>
        {
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
                    return masterKey;
            }
            throw new WrongKeyException(candidates.Any(s => s.RequiresPassword)
                ? "Wrong YubiKey or wrong password."
                : "This YubiKey is not registered in this vault.");
        });

    /// <exception cref="FormatException">The code is not a valid recovery code.</exception>
    /// <exception cref="WrongKeyException">The code does not open this vault.</exception>
    public static Vault OpenWithRecoveryCode(string path, string recoveryCode, VaultOptions? options = null)
    {
        byte[] code = RecoveryCode.Parse(recoveryCode);
        try
        {
            return Open(path, options, header =>
            {
                foreach (var slot in header.Slots.Where(s => s.Type == KeySlotType.Recovery && s.Argon2id is not null))
                {
                    byte[] kek = KeyWrap.RecoveryKek(code, slot.Argon2id!);
                    byte[]? masterKey = KeyWrap.Unwrap(slot, kek, header.VaultId);
                    CryptographicOperations.ZeroMemory(kek);
                    if (masterKey is not null)
                        return masterKey;
                }
                throw new WrongKeyException("The recovery code does not open this vault.");
            });
        }
        finally
        {
            CryptographicOperations.ZeroMemory(code);
        }
    }

    static Vault Open(string path, VaultOptions? options, Func<VaultHeader, byte[]> unwrapMasterKey)
    {
        path = Path.GetFullPath(path);
        var file = VaultFile.Open(path, writable: true);
        Vault? vault = null;
        try
        {
            var header = ReadHeader(file);
            vault = new Vault(path, file, header, unwrapMasterKey(header), [], options ?? VaultOptions.Default);
            vault._entries = vault.ReadIndex();
            return vault;
        }
        catch
        {
            if (vault is not null)
                vault.Dispose();
            else
                file.Dispose();
            throw;
        }
    }

    // ---- Hidden vault ----

    /// <summary>Opens the hidden vault inside a vault file with its password and security key (one PIN entry and touch).</summary>
    /// <exception cref="WrongKeyException">No hidden vault opens with this password and key.</exception>
    public static Vault OpenHidden(string path, string password, IFido2Authenticator securityKey, VaultOptions? options = null)
    {
        options ??= VaultOptions.Default;
        return OpenHiddenWith(path, options, (file, header) =>
        {
            byte[] slotKey = PasswordSlotKey(file, password, options);
            try
            {
                var payload = HiddenSlots.Find(file, slotKey, header.VaultId);
                if (payload is null || payload[0] != HiddenSlots.PasswordAndKey)
                    throw new WrongKeyException(NoHiddenVault);
                var (credentialId, salt) = HiddenSlots.ReadPasswordPayload(payload);
                var (_, secret) = securityKey.GetSecret(Fido2RelyingPartyId, [(credentialId, salt)]);
                byte[] kek = KeyWrap.HiddenFido2Kek(secret, slotKey, salt);
                CryptographicOperations.ZeroMemory(secret);
                byte[]? masterKey = HiddenSlots.UnwrapPasswordPayload(payload, kek, header.VaultId);
                CryptographicOperations.ZeroMemory(kek);
                CryptographicOperations.ZeroMemory(payload);
                return masterKey ?? throw new WrongKeyException("This security key does not open the hidden vault.");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(slotKey);
            }
        });
    }

    /// <summary>Opens the hidden vault inside a vault file with the hidden vault's own recovery code.</summary>
    /// <exception cref="FormatException">The code is not a valid recovery code.</exception>
    /// <exception cref="WrongKeyException">No hidden vault opens with this code.</exception>
    public static Vault OpenHiddenWithRecoveryCode(string path, string recoveryCode, VaultOptions? options = null)
    {
        options ??= VaultOptions.Default;
        byte[] code = RecoveryCode.Parse(recoveryCode);
        try
        {
            return OpenHiddenWith(path, options, (file, header) =>
            {
                byte[] slotKey = KeyWrap.HiddenSlotKey(code, HiddenSlots.ReadSalt(file), options, HiddenSlots.RecoveryInfo);
                var payload = HiddenSlots.Find(file, slotKey, header.VaultId);
                CryptographicOperations.ZeroMemory(slotKey);
                if (payload is null || payload[0] != HiddenSlots.Recovery)
                    throw new WrongKeyException("No hidden vault opens with this recovery code.");
                byte[] masterKey = HiddenSlots.ReadRecoveryPayload(payload);
                CryptographicOperations.ZeroMemory(payload);
                return masterKey;
            });
        }
        finally
        {
            CryptographicOperations.ZeroMemory(code);
        }
    }

    static Vault OpenHiddenWith(string path, VaultOptions options, Func<VaultFile, VaultHeader, byte[]> unwrapMasterKey)
    {
        path = Path.GetFullPath(path);
        var file = VaultFile.Open(path, writable: true);
        Vault? vault = null;
        HiddenStore? store = null;
        byte[]? masterKey = null;
        try
        {
            var header = ReadHeader(file);
            if (header.Version < 2 || header.Padding < HiddenStore.MinimumSize)
                throw new WrongKeyException(NoHiddenVault);
            masterKey = unwrapMasterKey(file, header);
            store = HiddenStore.Open(file, VaultFile.DataStart, header.Padding, masterKey)
                ?? throw new VaultException("The hidden vault is damaged.");
            vault = new Vault(path, file, header, masterKey, [], options, store);
            vault._entries = vault.ReadIndex();
            return vault;
        }
        catch
        {
            if (vault is not null)
            {
                vault.Dispose();
            }
            else
            {
                store?.Dispose();
                if (masterKey is not null)
                    CryptographicOperations.ZeroMemory(masterKey);
                file.Dispose();
            }
            throw;
        }
    }

    static byte[] PasswordSlotKey(VaultFile file, string password, VaultOptions options)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(password);
        try
        {
            return KeyWrap.HiddenSlotKey(bytes, HiddenSlots.ReadSalt(file), options, HiddenSlots.PasswordInfo);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    /// <summary>
    /// Creates a hidden vault of <paramref name="size"/> bytes inside this vault's file, opened by
    /// <paramref name="password"/> together with <paramref name="securityKey"/>. The file is rewritten
    /// with fresh random padding, which destroys any hidden vault already in it.
    /// </summary>
    /// <returns>The hidden vault's own recovery code, to show the user once.</returns>
    public string CreateHiddenVault(string password, IFido2Authenticator securityKey, long size)
    {
        ThrowIfDisposed();
        ThrowIfHidden();
        if (string.IsNullOrEmpty(password))
            throw new VaultException("A hidden vault needs its own password.");
        if (size < HiddenStore.MinimumSize)
            throw new VaultException("The space for a hidden vault must be at least 1 MiB.");

        // Talk to the key first: a cancelled PIN prompt then leaves the file untouched.
        byte[] fido2Salt = RandomNumberGenerator.GetBytes(Fido2SaltSize);
        byte[] credentialId = securityKey.MakeCredential(Fido2RelyingPartyId, RandomNumberGenerator.GetBytes(16), "YubiVault");
        var (usedCredential, secret) = securityKey.GetSecret(Fido2RelyingPartyId, [(credentialId, fido2Salt)]);
        if (!usedCredential.AsSpan().SequenceEqual(credentialId))
            throw new VaultException("The security key answered with an unexpected credential.");

        byte[] hiddenKey = RandomNumberGenerator.GetBytes(KeyWrap.MasterKeySize);
        byte[] code = RecoveryCode.Generate();
        byte[]? slotKey = null, kek = null, recoveryKey = null;
        try
        {
            Rewrite(size, keepReserved: false);
            byte[] salt = HiddenSlots.ReadSalt(_file);
            slotKey = PasswordSlotKey(_file, password, _options);
            kek = KeyWrap.HiddenFido2Kek(secret, slotKey, fido2Salt);
            recoveryKey = KeyWrap.HiddenSlotKey(code, salt, _options, HiddenSlots.RecoveryInfo);

            var (passwordSlot, recoverySlot) = HiddenSlots.PickTwo();
            HiddenSlots.Write(_file, passwordSlot, slotKey,
                HiddenSlots.PasswordPayload(credentialId, fido2Salt, kek, hiddenKey, _header.VaultId), _header.VaultId);
            HiddenSlots.Write(_file, recoverySlot, recoveryKey, HiddenSlots.RecoveryPayload(hiddenKey), _header.VaultId);
            using var store = HiddenStore.Create(_file, VaultFile.DataStart, size, hiddenKey);
            store.Commit(output => WriteIndex([], output, hiddenKey));
            return RecoveryCode.Format(code);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secret);
            CryptographicOperations.ZeroMemory(hiddenKey);
            CryptographicOperations.ZeroMemory(code);
            foreach (var key in new[] { slotKey, kek, recoveryKey })
                if (key is not null)
                    CryptographicOperations.ZeroMemory(key);
        }
    }

    /// <summary>
    /// Rewrites the vault file with <paramref name="size"/> bytes of fresh random padding (0 removes it).
    /// Padding hides how much the vault really holds; it also destroys any hidden vault in the file.
    /// </summary>
    public void SetPadding(long size)
    {
        ThrowIfDisposed();
        ThrowIfHidden();
        ArgumentOutOfRangeException.ThrowIfNegative(size);
        Rewrite(size, keepReserved: false);
    }

    void ThrowIfHidden()
    {
        if (_hidden is not null)
            throw new VaultException("The keys of a hidden vault cannot be changed.");
    }

    // ---- Key slots ----

    /// <summary>Registers another YubiKey. Files are not re-encrypted.</summary>
    public KeySlot AddYubiKey(IChallengeResponder yubiKey, string? password)
    {
        ThrowIfDisposed();
        ThrowIfHidden();
        var slot = AddYubiKeySlot(yubiKey, password);
        SaveHeader();
        return slot;
    }

    /// <summary>Registers another FIDO2 security key. Files are not re-encrypted.</summary>
    public KeySlot AddSecurityKey(IFido2Authenticator securityKey)
    {
        ThrowIfDisposed();
        ThrowIfHidden();
        var slot = AddFido2Slot(securityKey);
        SaveHeader();
        return slot;
    }

    /// <summary>Replaces the recovery code; the old one stops working.</summary>
    public string RegenerateRecoveryCode()
    {
        ThrowIfDisposed();
        ThrowIfHidden();
        _header.Slots.RemoveAll(s => s.Type == KeySlotType.Recovery);
        string code = AddRecoverySlot();
        SaveHeader();
        return code;
    }

    public void RemoveSlot(string slotId)
    {
        ThrowIfDisposed();
        ThrowIfHidden();
        var slot = _header.Slots.FirstOrDefault(s => s.Id == slotId)
            ?? throw new VaultException($"No key slot with id {slotId}.");
        if (_header.Slots.Count == 1)
            throw new VaultException("Cannot remove the last way to open the vault.");
        if (slot.IsHardwareKey && _header.Slots.Count(s => s.IsHardwareKey) == 1)
            throw new VaultException("Cannot remove the only security key; register another one first.");
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

    KeySlot AddFido2Slot(IFido2Authenticator securityKey)
    {
        var slot = new KeySlot
        {
            Id = NewSlotId("k"),
            Type = KeySlotType.Fido2,
            Label = securityKey.Description,
            CreatedUtc = DateTime.UtcNow,
            RelyingPartyId = Fido2RelyingPartyId,
            Challenge = RandomNumberGenerator.GetBytes(Fido2SaltSize),
        };
        slot.CredentialId = securityKey.MakeCredential(Fido2RelyingPartyId, RandomNumberGenerator.GetBytes(16), "YubiVault");
        // Registering already asks for the PIN and a touch; reading the secret asks once more.
        var (usedCredential, secret) = securityKey.GetSecret(Fido2RelyingPartyId, [(slot.CredentialId, slot.Challenge)]);
        if (!usedCredential.AsSpan().SequenceEqual(slot.CredentialId))
            throw new VaultException("The security key answered with an unexpected credential.");
        byte[] kek = KeyWrap.Fido2Kek(secret, slot.Challenge);
        CryptographicOperations.ZeroMemory(secret);
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
            Save();
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
            Save();
        }
        return count;
    }

    void AddFile(string sourceFile, string vaultPath, IProgress<string>? progress)
    {
        int existing = _entries.FindIndex(e => e.Path == vaultPath);
        if (existing < 0 && _entries.Any(e => VaultPath.IsWithin(e.Path, vaultPath) || VaultPath.IsWithin(vaultPath, e.Path)))
            throw new VaultException($"{vaultPath} conflicts with an existing file or folder in the vault.");

        progress?.Report(vaultPath);
        string blobId = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16));
        var info = new FileInfo(sourceFile);
        (long, long) Append()
        {
            using var input = new FileStream(sourceFile, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 16);
            return Store.Append(output => CascadeCipher.Encrypt(input, output, _masterKey, BlobContext(blobId), _options.ChunkSizeLog2));
        }
        long offset, length;
        try
        {
            (offset, length) = Append();
        }
        catch (HiddenVaultFullException) when (WastedBytes > 0)
        {
            Compact(); // a hidden vault cannot grow: reuse the space of deleted files
            (offset, length) = Append();
        }

        var entry = new VaultEntry
        {
            Path = vaultPath, BlobId = blobId, Offset = offset, Length = length,
            Size = info.Length, ModifiedUtc = info.LastWriteTimeUtc,
        };
        if (existing >= 0)
            _entries[existing] = entry;
        else
            _entries.Add(entry);
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
                using (var input = Store.OpenRecord(entry.Offset, entry.Length))
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

    /// <summary>Renames or moves a file, or a folder and everything in it. Only the index changes.</summary>
    /// <returns>Number of files moved.</returns>
    public int Move(string vaultPath, string newVaultPath)
    {
        ThrowIfDisposed();
        vaultPath = VaultPath.Normalize(vaultPath);
        newVaultPath = VaultPath.Normalize(newVaultPath);
        if (vaultPath.Length == 0 || newVaultPath.Length == 0)
            throw new VaultException("Name a file or folder to move, and where to.");
        if (vaultPath == newVaultPath)
            return 0;
        if (VaultPath.IsWithin(newVaultPath, vaultPath))
            throw new VaultException("Cannot move a folder into itself.");
        var moved = _entries.Where(e => VaultPath.IsWithin(e.Path, vaultPath)).ToList();
        if (moved.Count == 0)
            throw new VaultException($"Nothing in the vault at {vaultPath}.");
        var others = _entries.Except(moved).ToList();
        if (others.Any(e => VaultPath.IsWithin(e.Path, newVaultPath) || VaultPath.IsWithin(newVaultPath, e.Path)))
            throw new VaultException($"{newVaultPath} already exists in the vault.");
        foreach (var entry in moved)
            entry.Path = newVaultPath + entry.Path[vaultPath.Length..];
        Save();
        return moved.Count;
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
        Save();
        return removed.Count;
    }

    /// <summary>
    /// Rewrites the vault file without the space left by deleted or replaced files. The new file
    /// is written next to the old one and replaces it only once complete.
    /// </summary>
    /// <remarks>A hidden vault is compacted in place instead, which an interruption can damage.</remarks>
    public void Compact()
    {
        ThrowIfDisposed();
        if (_hidden is not null)
        {
            var moved = _hidden.Slide(_entries);
            _hidden.Commit(output => WriteIndex(moved, output));
            _entries = moved;
            return;
        }
        Rewrite(_header.Padding, keepReserved: _header.Version >= 2);
    }

    /// <summary>Copies the live records into a new file with <paramref name="padding"/>, which then replaces the vault file.</summary>
    /// <param name="keepReserved">Copy the key area and padding as they are (and any hidden vault in them); else fill them with random bytes.</param>
    void Rewrite(long padding, bool keepReserved)
    {
        string temp = _path + ".compacting";
        File.Delete(temp);
        var compacted = new List<VaultEntry>(_entries.Count);
        var (oldVersion, oldPadding) = (_header.Version, _header.Padding);
        _header.Version = VaultHeader.CurrentVersion;
        _header.Padding = padding;
        try
        {
            using (var target = VaultFile.Create(temp, padding, keepReserved ? _file : null))
            {
                foreach (var entry in _entries)
                {
                    using var source = _file.OpenRecord(entry.Offset, entry.Length);
                    var (offset, length) = target.Append(output => source.CopyTo(output, 1 << 20));
                    compacted.Add(new VaultEntry
                    {
                        Path = entry.Path, BlobId = entry.BlobId, Offset = offset, Length = length,
                        Size = entry.Size, ModifiedUtc = entry.ModifiedUtc,
                    });
                }
                target.Commit(SerializeHeader(), output => WriteIndex(compacted, output));
            }
        }
        catch
        {
            File.Delete(temp);
            (_header.Version, _header.Padding) = (oldVersion, oldPadding);
            throw;
        }

        _file.Dispose();
        try
        {
            File.Move(temp, _path, overwrite: true);
            _entries = compacted;
        }
        catch
        {
            File.Delete(temp);
            throw;
        }
        finally
        {
            _file = VaultFile.Open(_path, writable: true);
        }
    }

    // ---- Storage ----

    static VaultHeader ReadHeader(VaultFile file)
    {
        var header = ParseHeader(file.ReadHeader());
        if (header.Padding < 0 || VaultFile.DataStart + header.Padding > file.End || (header.Version < 2 && header.Padding != 0))
            throw new VaultException("The vault header is damaged.");
        return header;
    }

    static VaultHeader ParseHeader(byte[] json)
    {
        VaultHeader? header;
        try
        {
            header = JsonSerializer.Deserialize<VaultHeader>(json, JsonOptions);
        }
        catch (JsonException e)
        {
            throw new VaultException("The vault header is damaged.", e);
        }
        if (header is null || header.Format != VaultHeader.FormatName)
            throw new VaultException("Not a YubiVault vault.");
        if (header.Version is < VaultHeader.MinVersion or > VaultHeader.CurrentVersion)
            throw new VaultException($"Unsupported vault version {header.Version}; update YubiVault.");
        return header;
    }

    byte[] SerializeHeader() => JsonSerializer.SerializeToUtf8Bytes(_header, JsonOptions);

    List<VaultEntry> ReadIndex()
    {
        try
        {
            using var input = Store.OpenIndex();
            using var plain = new MemoryStream();
            CascadeCipher.Decrypt(input, plain, _masterKey, IndexContext);
            var entries = JsonSerializer.Deserialize<List<VaultEntry>>(plain.GetBuffer().AsSpan(0, (int)plain.Length)) ?? [];
            CryptographicOperations.ZeroMemory(plain.GetBuffer());
            return entries;
        }
        catch (Exception e)
        {
            throw new VaultException("The vault index is damaged or was tampered with.", e);
        }
    }

    void WriteIndex(List<VaultEntry> entries, Stream output) => WriteIndex(entries, output, _masterKey);

    void WriteIndex(List<VaultEntry> entries, Stream output, byte[] masterKey)
    {
        byte[] json = JsonSerializer.SerializeToUtf8Bytes(entries);
        try
        {
            using var input = new MemoryStream(json, writable: false);
            CascadeCipher.Encrypt(input, output, masterKey, IndexContext, _options.ChunkSizeLog2);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(json);
        }
    }

    /// <summary>Commits the index (and the header, if it changed), then compacts if a quarter of the file is unused.</summary>
    void Save(bool header = false)
    {
        if (_hidden is not null)
        {
            try
            {
                _hidden.Commit(output => WriteIndex(_entries, output));
            }
            catch (HiddenVaultFullException) when (WastedBytes > 0)
            {
                Compact();
            }
            return;
        }
        _file.Commit(header ? SerializeHeader() : null, output => WriteIndex(_entries, output));
        long wasted = WastedBytes;
        if (wasted >= MinWasteToCompact && wasted * 4 >= _file.End)
        {
            try
            {
                Compact();
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                // The save is committed and the vault intact; the space is reclaimed on a later save.
            }
        }
    }

    void SaveHeader() => Save(header: true);

    static byte[] BlobContext(string blobId) => Encoding.ASCII.GetBytes("blob:" + blobId);

    void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(_disposed, this);

    /// <summary>Locks the vault: the master key is wiped from memory and the file is closed.</summary>
    public void Dispose()
    {
        if (_disposed)
            return;
        CryptographicOperations.ZeroMemory(_masterKey);
        _hidden?.Dispose();
        _file.Dispose();
        _disposed = true;
    }
}
