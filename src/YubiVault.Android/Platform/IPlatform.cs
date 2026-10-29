using YubiVault.Fido2;

namespace YubiVault.Android.Platform;

/// <summary>A vault document the user picked (a content:// URI) that the app may read and write later.</summary>
public sealed record VaultDocument(string Uri, string DisplayName);

/// <summary>
/// What the views need from Android. Implemented by AndroidPlatform (MainActivity side); the views only
/// see this interface. All methods may be called from the UI thread; long work runs off it.
/// </summary>
public interface IPlatform
{
    /// <summary>
    /// Waits until a FIDO2 key is plugged in over USB (asking the USB permission if needed) or held to
    /// the phone over NFC, and opens it. Throws OperationCanceledException when cancelled.
    /// </summary>
    Task<ICtapConnection> ConnectKeyAsync(CancellationToken cancellationToken);

    /// <summary>True if the phone has NFC turned on (the views mention "hold the key to the phone" only then).</summary>
    bool NfcAvailable { get; }

    /// <summary>System picker for an existing .yvault file; keeps read/write permission. Null if cancelled.</summary>
    Task<VaultDocument?> PickVaultAsync();

    /// <summary>System "save as" picker for a new vault named <paramref name="suggestedName"/>.yvault. Null if cancelled.</summary>
    Task<VaultDocument?> CreateVaultDocumentAsync(string suggestedName);

    /// <summary>Vaults opened before, most recent first (persisted URI permissions still held).</summary>
    IReadOnlyList<VaultDocument> RecentVaults { get; }

    void AddRecent(VaultDocument document);

    void RemoveRecent(VaultDocument document);

    /// <summary>Copies the document into a private working file and returns its path (Vault works on paths).</summary>
    Task<string> CopyToWorkingFileAsync(VaultDocument document);

    /// <summary>Writes the working file back over the document (after changes, and when locking).</summary>
    Task SaveWorkingFileAsync(string workingPath, VaultDocument document);

    /// <summary>Lets the user pick files to encrypt; each is copied to a private temp path with its original name. Empty if cancelled.</summary>
    Task<IReadOnlyList<string>> PickFilesToAddAsync();

    /// <summary>Opens a decrypted temp file in another app (ACTION_VIEW through a FileProvider).</summary>
    void OpenFile(string path);

    /// <summary>Asks where to save a decrypted file (system "save as") and copies it there. False if cancelled.</summary>
    Task<bool> SaveFileAsAsync(string path);

    /// <summary>Private folder for decrypted temp files; wiped when the vault locks and at start-up.</summary>
    string TempFolder { get; }

    /// <summary>The installed app's version (versionName), to compare with releases.</summary>
    Version AppVersion { get; }

    /// <summary>Private folder for downloaded updates; emptied before each download.</summary>
    string UpdateFolder { get; }

    /// <summary>Hands a downloaded, verified APK to the system installer, which asks the user to confirm.</summary>
    void InstallPackage(string apkPath);

    /// <summary>Opens a web page in the browser (release notes).</summary>
    void OpenLink(string url);

    /// <summary>Copies text to the clipboard (the recovery code), marked sensitive so Android hides it.</summary>
    void CopySensitiveText(string text);
}
