using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Android.App;
using Android.Content;
using Android.Database;
using Android.Nfc;
using Android.OS;
using Android.Provider;
using Android.Webkit;
using AndroidX.Core.Content;
using Avalonia.Threading;
using YubiVault.Fido2;
using AndroidUri = Android.Net.Uri;

namespace YubiVault.Android.Platform;

/// <summary>
/// The Android side of <see cref="IPlatform"/>: security keys over USB and NFC, the system file pickers
/// (Storage Access Framework), working copies of vaults, and sharing decrypted files with other apps.
/// </summary>
public sealed class AndroidPlatform : IPlatform
{
    const string FileProviderAuthority = "io.github.tropeks.yubivault.files";
    const string RecentKey = "recent-vaults";
    const int MaxRecent = 10;

    static AndroidPlatform? _current;

    Activity _activity;
    readonly Dictionary<int, TaskCompletionSource<(Result Result, Intent? Data)>> _pendingResults = [];
    int _nextRequestCode = 4100;
    VaultDocument? _pendingOpen;

    AndroidPlatform(Activity activity)
    {
        _activity = activity;
        // Decrypted leftovers from a previous run (the app was killed while a vault was open).
        WipeFolder(TempFolder);
    }

    public static AndroidPlatform Current => _current ?? throw new InvalidOperationException("The activity has not started yet.");

    /// <summary>Called by the activity on every OnCreate (Android may recreate it).</summary>
    public static void Attach(Activity activity)
    {
        if (_current is null)
            _current = new AndroidPlatform(activity);
        else
            _current._activity = activity;
    }

    Context Context => _activity;

    ContentResolver Resolver => _activity.ContentResolver!;

    // ---- .yvault files opened from other apps ----

    /// <summary>Raised on the UI thread when another app asks to open a vault (VIEW intent) while the app runs.</summary>
    public event Action<VaultDocument>? OpenRequested;

    /// <summary>The vault another app asked to open at start-up, if any; returns it once.</summary>
    public VaultDocument? TakePendingOpen()
    {
        var document = _pendingOpen;
        _pendingOpen = null;
        return document;
    }

    internal void HandleIntent(Intent? intent)
    {
        if (intent?.Action != Intent.ActionView || intent.Data is not { } uri)
            return;
        // Usually a temporary grant only; it lasts while the activity lives.
        TryTakePersistablePermission(uri, read: true, write: (intent.Flags & ActivityFlags.GrantWriteUriPermission) != 0);
        var document = new VaultDocument(uri.ToString()!, DisplayName(uri) ?? "Vault.yvault");
        intent.SetData(null);
        if (OpenRequested is { } handler)
            Dispatcher.UIThread.Post(() => handler(document));
        else
            _pendingOpen = document;
    }

    // ---- Security keys ----

    readonly object _waitLock = new();
    TaskCompletionSource<ICtapConnection>? _keyWaiter;

    public bool NfcAvailable => NfcAdapter.GetDefaultAdapter(Context)?.IsEnabled == true;

    public async Task<ICtapConnection> ConnectKeyAsync(CancellationToken cancellationToken)
    {
        var waiter = new TaskCompletionSource<ICtapConnection>(TaskCreationOptions.RunContinuationsAsynchronously);
        lock (_waitLock)
        {
            _keyWaiter?.TrySetCanceled();
            _keyWaiter = waiter;
        }
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        using var registration = cancellationToken.Register(() => waiter.TrySetCanceled(cancellationToken));
        EnableReaderMode();
        var usb = Task.Run(() => UsbSearch(waiter, stop.Token), stop.Token);
        ICtapConnection? connection = null;
        try
        {
            connection = await waiter.Task;
            // Turning reader mode off drops the tag, so it stays on until the NFC exchange is over.
            return connection.IsNfc ? new ReaderModeConnection(this, connection) : connection;
        }
        finally
        {
            stop.Cancel();
            lock (_waitLock)
            {
                if (_keyWaiter == waiter)
                    _keyWaiter = null;
            }
            if (connection is not { IsNfc: true })
                DisableReaderMode();
            try
            {
                await usb;
            }
            catch (Exception)
            {
                // The search was stopped or the device failed; the result above is what counts.
            }
        }
    }

    /// <summary>An NFC key connection that turns reader mode off once it is closed (unless a new wait has begun).</summary>
    sealed class ReaderModeConnection(AndroidPlatform platform, ICtapConnection inner) : ICtapConnection
    {
        public bool IsNfc => true;

        public Action<bool>? TouchNotifier
        {
            get => inner.TouchNotifier;
            set => inner.TouchNotifier = value;
        }

        public byte[] SendCbor(byte[] request, CancellationToken cancellationToken) => inner.SendCbor(request, cancellationToken);

        public void Dispose()
        {
            inner.Dispose();
            lock (platform._waitLock)
            {
                if (platform._keyWaiter is not null)
                    return;
            }
            platform.DisableReaderMode();
        }
    }

    /// <summary>Hands a freshly opened key to the waiter, or closes it if someone else won the race.</summary>
    static void Offer(TaskCompletionSource<ICtapConnection> waiter, ICtapConnection connection)
    {
        if (!waiter.TrySetResult(connection))
            connection.Dispose();
    }

    async Task UsbSearch(TaskCompletionSource<ICtapConnection> waiter, CancellationToken cancellationToken)
    {
        var skipped = new HashSet<string>();
        while (!waiter.Task.IsCompleted)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ICtapConnection? connection = null;
            try
            {
                connection = await UsbKeys.TryOpenAsync(Context, skipped, cancellationToken);
            }
            catch (Java.Lang.Exception)
            {
                // Unplugged halfway; look again.
            }
            if (connection is not null)
            {
                Offer(waiter, connection);
                return;
            }
            await Task.Delay(500, cancellationToken);
        }
    }

    void EnableReaderMode()
    {
        _activity.RunOnUiThread(() =>
        {
            var adapter = NfcAdapter.GetDefaultAdapter(_activity);
            if (adapter?.IsEnabled != true)
                return;
            try
            {
                adapter.EnableReaderMode(_activity, new NfcReader(this),
                    NfcReaderFlags.NfcA | NfcReaderFlags.NfcB | NfcReaderFlags.SkipNdefCheck, null);
            }
            catch (Java.Lang.IllegalStateException)
            {
                // Not in the foreground; OnResumed turns it on again.
            }
        });
    }

    void DisableReaderMode()
    {
        _activity.RunOnUiThread(() =>
        {
            try
            {
                NfcAdapter.GetDefaultAdapter(_activity)?.DisableReaderMode(_activity);
            }
            catch (Java.Lang.IllegalStateException)
            {
            }
        });
    }

    /// <summary>Android turns reader mode off when the activity pauses; turn it back on while we wait.</summary>
    internal void OnResumed()
    {
        lock (_waitLock)
        {
            if (_keyWaiter is null)
                return;
        }
        EnableReaderMode();
    }

    sealed class NfcReader(AndroidPlatform platform) : Java.Lang.Object, NfcAdapter.IReaderCallback
    {
        public void OnTagDiscovered(Tag? tag)
        {
            TaskCompletionSource<ICtapConnection>? waiter;
            lock (platform._waitLock)
                waiter = platform._keyWaiter;
            if (tag is null || waiter is null || waiter.Task.IsCompleted)
                return;
            var connection = NfcKeys.TryOpen(tag);
            if (connection is not null)
                Offer(waiter, connection);
        }
    }

    // ---- Activity results ----

    Task<(Result Result, Intent? Data)> StartForResultAsync(Intent intent)
    {
        var completion = new TaskCompletionSource<(Result, Intent?)>(TaskCreationOptions.RunContinuationsAsynchronously);
        int requestCode;
        lock (_pendingResults)
        {
            requestCode = _nextRequestCode++;
            _pendingResults[requestCode] = completion;
        }
        try
        {
            _activity.StartActivityForResult(intent, requestCode);
        }
        catch (ActivityNotFoundException)
        {
            lock (_pendingResults)
                _pendingResults.Remove(requestCode);
            completion.TrySetResult((Result.Canceled, null));
        }
        return completion.Task;
    }

    internal void OnActivityResult(int requestCode, Result resultCode, Intent? data)
    {
        TaskCompletionSource<(Result, Intent?)>? completion;
        lock (_pendingResults)
        {
            if (!_pendingResults.Remove(requestCode, out completion))
                return;
        }
        completion.TrySetResult((resultCode, data));
    }

    // ---- Vault documents ----

    public async Task<VaultDocument?> PickVaultAsync()
    {
        var intent = new Intent(Intent.ActionOpenDocument)
            .AddCategory(Intent.CategoryOpenable)
            .SetType("*/*")
            .AddFlags(ActivityFlags.GrantReadUriPermission | ActivityFlags.GrantWriteUriPermission
                | ActivityFlags.GrantPersistableUriPermission);
        var (result, data) = await StartForResultAsync(intent);
        if (result != Result.Ok || data?.Data is not { } uri)
            return null;
        TryTakePersistablePermission(uri, read: true, write: true);
        return new VaultDocument(uri.ToString()!, DisplayName(uri) ?? "Vault.yvault");
    }

    public async Task<VaultDocument?> CreateVaultDocumentAsync(string suggestedName)
    {
        string name = suggestedName.EndsWith(Core.Vault.FileExtension, StringComparison.OrdinalIgnoreCase)
            ? suggestedName
            : suggestedName + Core.Vault.FileExtension;
        var intent = new Intent(Intent.ActionCreateDocument)
            .AddCategory(Intent.CategoryOpenable)
            .SetType("application/octet-stream")
            .PutExtra(Intent.ExtraTitle, name)
            .AddFlags(ActivityFlags.GrantReadUriPermission | ActivityFlags.GrantWriteUriPermission
                | ActivityFlags.GrantPersistableUriPermission);
        var (result, data) = await StartForResultAsync(intent);
        if (result != Result.Ok || data?.Data is not { } uri)
            return null;
        TryTakePersistablePermission(uri, read: true, write: true);
        return new VaultDocument(uri.ToString()!, DisplayName(uri) ?? name);
    }

    void TryTakePersistablePermission(AndroidUri uri, bool read, bool write)
    {
        var flags = (read ? ActivityFlags.GrantReadUriPermission : 0) | (write ? ActivityFlags.GrantWriteUriPermission : 0);
        try
        {
            Resolver.TakePersistableUriPermission(uri, flags);
        }
        catch (Java.Lang.SecurityException) when (write)
        {
            TryTakePersistablePermission(uri, read, write: false);
        }
        catch (Java.Lang.SecurityException)
        {
            // Not persistable (e.g. a one-off VIEW grant); it works until the app closes.
        }
    }

    string? DisplayName(AndroidUri uri)
    {
        try
        {
            using ICursor? cursor = Resolver.Query(uri, [IOpenableColumns.DisplayName], null, null, null);
            if (cursor?.MoveToFirst() == true && !cursor.IsNull(0))
                return cursor.GetString(0);
        }
        catch (Java.Lang.Exception)
        {
        }
        return uri.LastPathSegment is { } segment ? Path.GetFileName(segment) : null;
    }

    public IReadOnlyList<VaultDocument> RecentVaults
    {
        get
        {
            var held = Resolver.PersistedUriPermissions.Select(p => p.Uri?.ToString()).ToHashSet();
            return LoadRecent().Where(d => held.Contains(d.Uri)).ToList();
        }
    }

    public void AddRecent(VaultDocument document)
    {
        var list = LoadRecent().Where(d => d.Uri != document.Uri).Prepend(document).Take(MaxRecent).ToList();
        SaveRecent(list);
    }

    public void RemoveRecent(VaultDocument document)
    {
        SaveRecent(LoadRecent().Where(d => d.Uri != document.Uri).ToList());
        try
        {
            Resolver.ReleasePersistableUriPermission(AndroidUri.Parse(document.Uri)!,
                ActivityFlags.GrantReadUriPermission | ActivityFlags.GrantWriteUriPermission);
        }
        catch (Java.Lang.SecurityException)
        {
        }
    }

    ISharedPreferences Preferences => Context.GetSharedPreferences("yubivault", FileCreationMode.Private)!;

    List<VaultDocument> LoadRecent()
    {
        try
        {
            string? json = Preferences.GetString(RecentKey, null);
            return json is null ? [] : JsonSerializer.Deserialize<List<VaultDocument>>(json) ?? [];
        }
        catch (JsonException)
        {
            return [];
        }
    }

    void SaveRecent(List<VaultDocument> list)
    {
        using var editor = Preferences.Edit()!;
        editor.PutString(RecentKey, JsonSerializer.Serialize(list));
        editor.Apply();
    }

    /// <summary>Private folder for working copies of vaults (encrypted, so they are not wiped).</summary>
    string WorkingFolder => Directory.CreateDirectory(Path.Combine(Context.FilesDir!.AbsolutePath, "working")).FullName;

    public Task<string> CopyToWorkingFileAsync(VaultDocument document) => Task.Run(() =>
    {
        // One working file per document, named after a hash of its URI; Vault may write a
        // "<name>.yvault.compacting" file next to it.
        string id = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(document.Uri)))[..16];
        string path = Path.Combine(WorkingFolder, id + Core.Vault.FileExtension);
        using var input = Resolver.OpenInputStream(AndroidUri.Parse(document.Uri)!)
            ?? throw new IOException($"Cannot read {document.DisplayName}.");
        using var output = new FileStream(path, FileMode.Create, FileAccess.Write);
        input.CopyTo(output);
        return path;
    });

    public Task SaveWorkingFileAsync(string workingPath, VaultDocument document) => Task.Run(() =>
    {
        var uri = AndroidUri.Parse(document.Uri)!;
        using var input = new FileStream(workingPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        using var output = OpenForOverwrite(uri) ?? throw new IOException($"Cannot write {document.DisplayName}.");
        input.CopyTo(output);
        output.Flush();
    });

    /// <summary>"wt" truncates; a few providers only know "w" (which then truncates on its own or is overwritten fully).</summary>
    Stream? OpenForOverwrite(AndroidUri uri)
    {
        try
        {
            return Resolver.OpenOutputStream(uri, "wt");
        }
        catch (Java.Lang.IllegalArgumentException)
        {
            return Resolver.OpenOutputStream(uri, "w");
        }
        catch (Java.IO.FileNotFoundException)
        {
            return Resolver.OpenOutputStream(uri, "w");
        }
    }

    // ---- Plain files ----

    public string TempFolder => Directory.CreateDirectory(Path.Combine(Context.CacheDir!.AbsolutePath, "decrypted")).FullName;

    /// <summary>Plain copies of files picked for encryption, inside <see cref="TempFolder"/> so they go when it is wiped.</summary>
    string ImportFolder => Directory.CreateDirectory(Path.Combine(TempFolder, ".import")).FullName;

    public async Task<IReadOnlyList<string>> PickFilesToAddAsync()
    {
        var intent = new Intent(Intent.ActionOpenDocument)
            .AddCategory(Intent.CategoryOpenable)
            .SetType("*/*")
            .PutExtra(Intent.ExtraAllowMultiple, true)
            .AddFlags(ActivityFlags.GrantReadUriPermission);
        var (result, data) = await StartForResultAsync(intent);
        if (result != Result.Ok || data is null)
            return [];
        var uris = new List<AndroidUri>();
        if (data.ClipData is { } clip)
        {
            for (int i = 0; i < clip.ItemCount; i++)
                if (clip.GetItemAt(i)?.Uri is { } uri)
                    uris.Add(uri);
        }
        else if (data.Data is { } single)
        {
            uris.Add(single);
        }
        return await Task.Run(() =>
        {
            // Each file in its own folder so that names never clash and stay exactly as they were.
            var paths = new List<string>();
            foreach (var uri in uris)
            {
                string folder = Directory.CreateDirectory(Path.Combine(ImportFolder, Guid.NewGuid().ToString("N"))).FullName;
                string path = Path.Combine(folder, SafeFileName(DisplayName(uri) ?? "file"));
                using var input = Resolver.OpenInputStream(uri) ?? throw new IOException($"Cannot read {uri}.");
                using var output = new FileStream(path, FileMode.CreateNew, FileAccess.Write);
                input.CopyTo(output);
                paths.Add(path);
            }
            return (IReadOnlyList<string>)paths;
        });
    }

    public void OpenFile(string path)
    {
        var uri = FileProvider.GetUriForFile(Context, FileProviderAuthority, new Java.IO.File(path));
        var intent = new Intent(Intent.ActionView)
            .SetDataAndType(uri, MimeType(path))
            .AddFlags(ActivityFlags.GrantReadUriPermission);
        try
        {
            _activity.StartActivity(Intent.CreateChooser(intent, (string?)null));
        }
        catch (ActivityNotFoundException e)
        {
            throw new InvalidOperationException($"No app on this phone can open {Path.GetFileName(path)}.", e);
        }
    }

    public async Task<bool> SaveFileAsAsync(string path)
    {
        var intent = new Intent(Intent.ActionCreateDocument)
            .AddCategory(Intent.CategoryOpenable)
            .SetType(MimeType(path))
            .PutExtra(Intent.ExtraTitle, Path.GetFileName(path));
        var (result, data) = await StartForResultAsync(intent);
        if (result != Result.Ok || data?.Data is not { } uri)
            return false;
        await Task.Run(() =>
        {
            using var input = File.OpenRead(path);
            using var output = OpenForOverwrite(uri) ?? throw new IOException($"Cannot write {Path.GetFileName(path)}.");
            input.CopyTo(output);
        });
        return true;
    }

    static string MimeType(string path)
    {
        string extension = Path.GetExtension(path).TrimStart('.').ToLowerInvariant();
        return MimeTypeMap.Singleton?.GetMimeTypeFromExtension(extension) ?? "application/octet-stream";
    }

    static string SafeFileName(string name)
    {
        string clean = string.Concat(name.Select(c => c is '/' or '\0' ? '_' : c)).Trim();
        return clean is "" or "." or ".." ? "file" : clean;
    }

    static void WipeFolder(string folder)
    {
        try
        {
            foreach (var entry in Directory.EnumerateFileSystemEntries(folder))
            {
                if (Directory.Exists(entry))
                    Directory.Delete(entry, recursive: true);
                else
                    File.Delete(entry);
            }
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }

    // ---- Clipboard ----

    public void CopySensitiveText(string text)
    {
        var clipboard = (ClipboardManager)Context.GetSystemService(Context.ClipboardService)!;
        var clip = ClipData.NewPlainText("YubiVault", text)!;
        // Keeps the code out of the clipboard preview (Android 13+), and older keyboards' suggestions.
        var extras = new PersistableBundle();
        extras.PutBoolean("android.content.extra.IS_SENSITIVE", true);
        clip.Description!.Extras = extras;
        clipboard.PrimaryClip = clip;
    }
}
