using YubiVault.Android.Platform;
using YubiVault.Core;

namespace YubiVault.Android.Views;

/// <summary>
/// An unlocked vault. <see cref="Vault"/> works on a private working copy of the user's document;
/// every change is written back to the document right away.
/// </summary>
sealed class VaultSession(Vault vault, VaultDocument document, string workingPath)
{
    public Vault Vault { get; } = vault;
    public VaultDocument Document { get; } = document;
    public string WorkingPath { get; } = workingPath;

    /// <summary>True while the document is behind the working copy (a write-back failed).</summary>
    public bool Unsaved { get; private set; }

    public string Name => Path.GetFileNameWithoutExtension(Document.DisplayName);

    /// <summary>Writes the working copy back to the document; on failure the change stays pending.</summary>
    public async Task SaveAsync(MainView main)
    {
        Unsaved = true;
        await main.RunAsync(Resources.MobileStrings.SavingVault, () => main.Platform.SaveWorkingFileAsync(WorkingPath, Document));
        Unsaved = false;
    }

    /// <summary>Closes the vault, writes back anything pending and removes the decrypted files.</summary>
    /// <returns>False if the vault could not be written back; the working copy is then kept.</returns>
    public async Task<bool> LockAsync(MainView main)
    {
        Vault.Dispose();
        bool saved = true;
        if (Unsaved)
        {
            try
            {
                await SaveAsync(main);
            }
            catch (Exception e)
            {
                saved = false;
                await main.AlertAsync(Resources.Strings.ErrorTitle, Resources.MobileStrings.CouldNotSave + "\n\n" + e.Message);
            }
        }
        main.WipeTempFolder();
        if (saved)
        {
            try
            {
                File.Delete(WorkingPath);
            }
            catch (IOException)
            {
            }
        }
        return saved;
    }
}
