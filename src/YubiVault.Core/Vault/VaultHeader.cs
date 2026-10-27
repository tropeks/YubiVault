using System.Text.Json.Serialization;

namespace YubiVault.Core;

/// <summary>Contents of <c>vault.yv</c>: everything needed to unwrap the master key, nothing secret in the clear.</summary>
public sealed class VaultHeader
{
    public const string FormatName = "YubiVault";
    public const int CurrentVersion = 1;

    [JsonPropertyName("format")] public string Format { get; set; } = FormatName;
    [JsonPropertyName("version")] public int Version { get; set; } = CurrentVersion;
    [JsonPropertyName("vaultId")] public byte[] VaultId { get; set; } = [];
    [JsonPropertyName("slots")] public List<KeySlot> Slots { get; set; } = [];
}

public static class KeySlotType
{
    public const string YubiKey = "yubikey";
    public const string Fido2 = "fido2";
    public const string Recovery = "recovery";
}

/// <summary>One way to open the vault: a copy of the master key wrapped under a key-encryption key.</summary>
public sealed class KeySlot
{
    [JsonPropertyName("id")] public string Id { get; set; } = "";
    [JsonPropertyName("type")] public string Type { get; set; } = "";
    [JsonPropertyName("label")] public string Label { get; set; } = "";
    [JsonPropertyName("createdUtc")] public DateTime CreatedUtc { get; set; }

    /// <summary>YubiKey serial number, used to pick the right slot without extra touches.</summary>
    [JsonPropertyName("serial")] public int? Serial { get; set; }

    /// <summary>FIDO2 credential id (fido2 slots).</summary>
    [JsonPropertyName("credentialId")] public byte[]? CredentialId { get; set; }

    /// <summary>FIDO2 relying party id the credential was created for (fido2 slots).</summary>
    [JsonPropertyName("rpId")] public string? RelyingPartyId { get; set; }

    /// <summary>Challenge sent to the key: the HMAC-SHA1 challenge (yubikey slots) or hmac-secret salt (fido2 slots).</summary>
    [JsonPropertyName("challenge")] public byte[]? Challenge { get; set; }

    /// <summary>Argon2id settings for the optional password (YubiKey slots) or the recovery code.</summary>
    [JsonPropertyName("argon2id")] public Argon2Settings? Argon2id { get; set; }

    [JsonPropertyName("nonce")] public byte[] Nonce { get; set; } = [];
    [JsonPropertyName("wrappedKey")] public byte[] WrappedKey { get; set; } = [];

    [JsonIgnore] public bool RequiresPassword => Type == KeySlotType.YubiKey && Argon2id is not null;

    [JsonIgnore] public bool IsHardwareKey => Type is KeySlotType.YubiKey or KeySlotType.Fido2;
}

public sealed class Argon2Settings
{
    [JsonPropertyName("salt")] public byte[] Salt { get; set; } = [];
    [JsonPropertyName("memoryKiB")] public long MemoryKiB { get; set; }
    [JsonPropertyName("passes")] public long Passes { get; set; }
}

/// <summary>A file stored in the vault, as listed in the encrypted index.</summary>
public sealed class VaultEntry
{
    /// <summary>Path inside the vault, '/'-separated, no leading slash.</summary>
    [JsonPropertyName("path")] public string Path { get; set; } = "";
    [JsonPropertyName("blob")] public string BlobId { get; set; } = "";
    [JsonPropertyName("size")] public long Size { get; set; }
    [JsonPropertyName("modifiedUtc")] public DateTime ModifiedUtc { get; set; }
}
