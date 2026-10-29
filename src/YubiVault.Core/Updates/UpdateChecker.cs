using System.Globalization;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;
using NSec.Cryptography;

namespace YubiVault.Core.Updates;

/// <summary>A published release newer than the running app, with the files its signed checksum list covers.</summary>
/// <param name="Version">The release version, from its tag (v1.2.3).</param>
/// <param name="VersionText">The version as written in the file names ("1.2.3").</param>
/// <param name="PageUrl">The release page, for "what's new".</param>
/// <param name="Files">File name → download URL and SHA-256, only for files the signature covers.</param>
public sealed record UpdateRelease(
    Version Version,
    string VersionText,
    string PageUrl,
    IReadOnlyDictionary<string, UpdateFile> Files);

public sealed record UpdateFile(string Name, string Url, byte[] Sha256);

/// <summary>
/// Looks for a newer YubiVault release on GitHub and downloads its files. Every release carries
/// SHA256SUMS.txt and SHA256SUMS.txt.sig, an Ed25519 signature made with the project's release key,
/// whose public half is built into the app. Only files listed in a correctly signed list are offered,
/// and a download is used only if its hash matches. Because the signed file names hold the version
/// (YubiVault-1.2.3-win-x64.exe), renaming an old release's tag cannot pass it off as a newer one.
/// </summary>
public sealed class UpdateChecker
{
    public const string Repository = "tropeks/YubiVault";
    public const string ChecksumsName = "SHA256SUMS.txt";
    public const string SignatureName = "SHA256SUMS.txt.sig";

    // Public half of the release signing key (Ed25519, raw 32 bytes).
    static readonly byte[] ReleasePublicKey = Convert.FromBase64String("S1XX5ffWisX/+JblMxnY0kbfsNJgDj7kLXCcsP5MI2I=");

    const long MaxChecksumsSize = 64 * 1024;
    const long MaxFileSize = 512L * 1024 * 1024;

    readonly HttpClient _http;
    readonly byte[] _publicKey;
    readonly string _releasesUrl;

    public UpdateChecker(HttpClient http) : this(http, ReleasePublicKey, $"https://api.github.com/repos/{Repository}/releases?per_page=20") { }

    internal UpdateChecker(HttpClient http, byte[] publicKey, string releasesUrl)
    {
        _http = http;
        _publicKey = publicKey;
        _releasesUrl = releasesUrl;
    }

    /// <summary>A client with the headers GitHub asks for.</summary>
    public static HttpClient CreateHttpClient()
    {
        var http = new HttpClient { Timeout = TimeSpan.FromMinutes(10) };
        http.DefaultRequestHeaders.UserAgent.ParseAdd("YubiVault-Updater");
        return http;
    }

    /// <summary>The newest signed release above <paramref name="current"/>, or null if there is none.</summary>
    /// <exception cref="HttpRequestException">GitHub could not be reached.</exception>
    /// <exception cref="UpdateException">The newest release is not correctly signed.</exception>
    public async Task<UpdateRelease?> FindNewerAsync(Version current, CancellationToken cancellationToken = default)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, _releasesUrl);
        request.Headers.Accept.ParseAdd("application/vnd.github+json");
        using var response = await _http.SendAsync(request, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        var releases = await response.Content.ReadFromJsonAsync<List<GitHubRelease>>(cancellationToken).ConfigureAwait(false) ?? [];

        // All 0.x releases are marked pre-release on GitHub, so those count too; drafts don't.
        var newest = releases
            .Where(r => !r.Draft)
            .Select(r => (Release: r, Version: TryParseTag(r.TagName, out var v) ? v : null))
            .Where(r => r.Version is not null && r.Version > current)
            .OrderByDescending(r => r.Version)
            .FirstOrDefault();
        if (newest.Version is null)
            return null;

        var assets = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var asset in newest.Release.Assets)
            assets.TryAdd(asset.Name, asset.DownloadUrl);
        if (!assets.TryGetValue(ChecksumsName, out var sumsUrl) || !assets.TryGetValue(SignatureName, out var sigUrl))
            throw new UpdateException($"Release {newest.Release.TagName} has no signed checksum list.");
        byte[] sums = await DownloadSmallAsync(sumsUrl, cancellationToken).ConfigureAwait(false);
        byte[] signature = await DownloadSmallAsync(sigUrl, cancellationToken).ConfigureAwait(false);
        var hashes = VerifyChecksums(sums, signature, _publicKey);

        var files = new Dictionary<string, UpdateFile>(StringComparer.Ordinal);
        foreach (var (name, hash) in hashes)
        {
            if (assets.TryGetValue(name, out var url))
                files[name] = new UpdateFile(name, url, hash);
        }
        string versionText = VersionText(newest.Release.TagName);
        return new UpdateRelease(newest.Version, versionText, newest.Release.HtmlUrl, files);
    }

    /// <summary>
    /// Downloads <paramref name="file"/> to <paramref name="destination"/> and checks its hash; on a
    /// mismatch nothing is left behind. Progress goes from 0 to 1.
    /// </summary>
    public async Task DownloadAsync(UpdateFile file, string destination, IProgress<double>? progress = null,
        CancellationToken cancellationToken = default)
    {
        string partial = destination + ".part";
        try
        {
            using (var response = await _http.GetAsync(file.Url, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false))
            {
                response.EnsureSuccessStatusCode();
                long? total = response.Content.Headers.ContentLength;
                if (total > MaxFileSize)
                    throw new UpdateException($"{file.Name} is unexpectedly large.");
                using var hash = System.Security.Cryptography.IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                await using (var source = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false))
                await using (var target = new FileStream(partial, FileMode.Create, FileAccess.Write, FileShare.None))
                {
                    byte[] buffer = new byte[81920];
                    long done = 0;
                    int read;
                    while ((read = await source.ReadAsync(buffer, cancellationToken).ConfigureAwait(false)) > 0)
                    {
                        done += read;
                        if (done > MaxFileSize)
                            throw new UpdateException($"{file.Name} is unexpectedly large.");
                        hash.AppendData(buffer, 0, read);
                        await target.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
                        if (total > 0)
                            progress?.Report((double)done / total.Value);
                    }
                }
                if (!CryptographicOperations.FixedTimeEquals(hash.GetHashAndReset(), file.Sha256))
                    throw new UpdateException($"{file.Name} does not match its signed checksum.");
            }
            File.Move(partial, destination, overwrite: true);
        }
        finally
        {
            File.Delete(partial);
        }
    }

    async Task<byte[]> DownloadSmallAsync(string url, CancellationToken cancellationToken)
    {
        using var response = await _http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        if (response.Content.Headers.ContentLength > MaxChecksumsSize)
            throw new UpdateException("The checksum list is unexpectedly large.");
        byte[] data = await response.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
        return data.Length <= MaxChecksumsSize ? data : throw new UpdateException("The checksum list is unexpectedly large.");
    }

    /// <summary>The version as the release workflow writes it in file names: the tag without a leading "v".</summary>
    static string VersionText(string tag) => tag.StartsWith('v') ? tag[1..] : tag;

    /// <summary>"v1.2.3" or "1.2.3" → 1.2.3. Anything else (pre-release suffixes, other tags) is not an update.</summary>
    public static bool TryParseTag(string? tag, out Version version)
    {
        version = new Version();
        if (string.IsNullOrEmpty(tag))
            return false;
        string[] parts = VersionText(tag).Split('.');
        if (parts.Length != 3)
            return false;
        int[] numbers = new int[3];
        for (int i = 0; i < 3; i++)
        {
            if (parts[i].Length is 0 or > 6 || !parts[i].All(char.IsAsciiDigit)
                || (parts[i].Length > 1 && parts[i][0] == '0'))
                return false;
            numbers[i] = int.Parse(parts[i], CultureInfo.InvariantCulture);
        }
        version = new Version(numbers[0], numbers[1], numbers[2]);
        return true;
    }

    /// <summary>
    /// Checks the Ed25519 signature over the checksum list and parses it (sha256sum output:
    /// "hash  name" or "hash *name"). Throws <see cref="UpdateException"/> if anything is off.
    /// </summary>
    internal static IReadOnlyDictionary<string, byte[]> VerifyChecksums(byte[] checksums, byte[] signature, byte[] publicKey)
    {
        var algorithm = SignatureAlgorithm.Ed25519;
        var key = NSec.Cryptography.PublicKey.Import(algorithm, publicKey, KeyBlobFormat.RawPublicKey);
        if (signature.Length != algorithm.SignatureSize || !algorithm.Verify(key, checksums, signature))
            throw new UpdateException("The release's checksum list is not signed by the YubiVault release key.");

        var result = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        foreach (string raw in Encoding.UTF8.GetString(checksums).Split('\n'))
        {
            string line = raw.TrimEnd('\r');
            if (line.Length == 0)
                continue;
            if (line.Length < 67 || line[64] != ' ' || (line[65] != ' ' && line[65] != '*'))
                throw new UpdateException("The release's checksum list is malformed.");
            byte[] hash;
            try
            {
                hash = Convert.FromHexString(line.AsSpan(0, 64));
            }
            catch (FormatException)
            {
                throw new UpdateException("The release's checksum list is malformed.");
            }
            string name = line[66..];
            if (name.Contains('/') || name.Contains('\\') || !result.TryAdd(name, hash))
                throw new UpdateException("The release's checksum list is malformed.");
        }
        return result;
    }

    sealed class GitHubRelease
    {
        [JsonPropertyName("tag_name")] public string TagName { get; set; } = "";
        [JsonPropertyName("html_url")] public string HtmlUrl { get; set; } = "";
        [JsonPropertyName("draft")] public bool Draft { get; set; }
        [JsonPropertyName("assets")] public List<GitHubAsset> Assets { get; set; } = [];
    }

    sealed class GitHubAsset
    {
        [JsonPropertyName("name")] public string Name { get; set; } = "";
        [JsonPropertyName("browser_download_url")] public string DownloadUrl { get; set; } = "";
    }
}

public sealed class UpdateException(string message) : Exception(message);
