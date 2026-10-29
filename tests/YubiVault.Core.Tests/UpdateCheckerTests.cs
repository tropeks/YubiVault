using System.Net;
using System.Security.Cryptography;
using System.Text;
using NSec.Cryptography;
using YubiVault.Core.Updates;

namespace YubiVault.Core.Tests;

public class UpdateCheckerTests
{
    static readonly byte[] AppBytes = "new app"u8.ToArray();

    [Theory]
    [InlineData("v1.2.3", 1, 2, 3)]
    [InlineData("v0.10.0", 0, 10, 0)]
    [InlineData("0.2.1", 0, 2, 1)]
    public void ParsesReleaseTags(string tag, int major, int minor, int patch)
    {
        Assert.True(UpdateChecker.TryParseTag(tag, out var version));
        Assert.Equal(new Version(major, minor, patch), version);
    }

    [Theory]
    [InlineData("v1.2")]
    [InlineData("v1.2.3-beta")]
    [InlineData("v1.02.3")]
    [InlineData("v1.2.3.4")]
    [InlineData("v")]
    [InlineData(null)]
    public void IgnoresOtherTags(string? tag) => Assert.False(UpdateChecker.TryParseTag(tag, out _));

    [Fact]
    public async Task OffersTheNewestSignedRelease()
    {
        using var key = NewKey();
        var server = new FakeGitHub(key, ("v0.2.0", "0.2.0"), ("v0.3.0", "0.3.0"), ("v0.1.0", "0.1.0"));
        var release = await server.Checker.FindNewerAsync(new Version(0, 1, 0));

        Assert.NotNull(release);
        Assert.Equal(new Version(0, 3, 0), release.Version);
        Assert.Equal("0.3.0", release.VersionText);
        Assert.True(release.Files.ContainsKey("YubiVault-0.3.0-win-x64.exe"));
    }

    [Fact]
    public async Task NothingWhenUpToDate()
    {
        using var key = NewKey();
        var server = new FakeGitHub(key, ("v0.2.0", "0.2.0"));
        Assert.Null(await server.Checker.FindNewerAsync(new Version(0, 2, 0)));
    }

    [Fact]
    public async Task RefusesAListSignedWithAnotherKey()
    {
        using var key = NewKey();
        using var other = NewKey();
        var server = new FakeGitHub(key, ("v0.2.0", "0.2.0")) { SigningKey = other };
        await Assert.ThrowsAsync<UpdateException>(() => server.Checker.FindNewerAsync(new Version(0, 1, 0)));
    }

    [Fact]
    public async Task RefusesAnEditedList()
    {
        using var key = NewKey();
        var server = new FakeGitHub(key, ("v0.2.0", "0.2.0")) { TamperWithList = true };
        await Assert.ThrowsAsync<UpdateException>(() => server.Checker.FindNewerAsync(new Version(0, 1, 0)));
    }

    [Fact]
    public async Task AnOldReleaseUnderANewTagOffersNoFiles()
    {
        // Retagging 0.1.0's files as v9.0.0: the signed names still say 0.1.0, so nothing matches 9.0.0.
        using var key = NewKey();
        var server = new FakeGitHub(key, ("v9.0.0", "0.1.0"));
        var release = await server.Checker.FindNewerAsync(new Version(0, 1, 0));
        Assert.NotNull(release);
        Assert.False(release.Files.ContainsKey("YubiVault-9.0.0-win-x64.exe"));
    }

    [Fact]
    public async Task DownloadChecksTheHash()
    {
        using var key = NewKey();
        var server = new FakeGitHub(key, ("v0.2.0", "0.2.0"));
        var release = (await server.Checker.FindNewerAsync(new Version(0, 1, 0)))!;
        string dir = Directory.CreateTempSubdirectory().FullName;
        try
        {
            string target = Path.Combine(dir, "app");
            await server.Checker.DownloadAsync(release.Files["YubiVault-0.2.0-win-x64.exe"], target);
            Assert.Equal(AppBytes, File.ReadAllBytes(target));

            server.ServeWrongFile = true;
            string bad = Path.Combine(dir, "bad");
            await Assert.ThrowsAsync<UpdateException>(() => server.Checker.DownloadAsync(release.Files["YubiVault-0.2.0-win-x64.exe"], bad));
            Assert.Empty(Directory.GetFiles(dir, "bad*"));
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    static Key NewKey() => Key.Create(SignatureAlgorithm.Ed25519, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });

    /// <summary>Answers the releases API and asset downloads from memory.</summary>
    sealed class FakeGitHub : HttpMessageHandler
    {
        readonly Key _trusted;
        readonly (string Tag, string FileVersion)[] _releases;

        public FakeGitHub(Key trusted, params (string Tag, string FileVersion)[] releases)
        {
            _trusted = trusted;
            _releases = releases;
            SigningKey = trusted;
            Checker = new UpdateChecker(new HttpClient(this), trusted.PublicKey.Export(KeyBlobFormat.RawPublicKey), "https://api.test/releases");
        }

        public UpdateChecker Checker { get; }
        public Key SigningKey { get; set; }
        public bool TamperWithList { get; set; }
        public bool ServeWrongFile { get; set; }

        string Sums(string fileVersion) =>
            $"{Convert.ToHexStringLower(SHA256.HashData(AppBytes))}  YubiVault-{fileVersion}-win-x64.exe\n";

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            string url = request.RequestUri!.ToString();
            byte[] body;
            if (url == "https://api.test/releases")
            {
                var json = new StringBuilder("[");
                foreach (var (tag, fileVersion) in _releases)
                {
                    string b = $"https://dl.test/{tag}/";
                    json.Append($$"""
                        {"tag_name":"{{tag}}","html_url":"https://page.test/{{tag}}","draft":false,"assets":[
                          {"name":"SHA256SUMS.txt","browser_download_url":"{{b}}sums"},
                          {"name":"SHA256SUMS.txt.sig","browser_download_url":"{{b}}sig"},
                          {"name":"YubiVault-{{fileVersion}}-win-x64.exe","browser_download_url":"{{b}}app"},
                          {"name":"YubiVault-{{tag[1..]}}-win-x64.exe","browser_download_url":"{{b}}renamed"}]},
                        """);
                }
                body = Encoding.UTF8.GetBytes(json.ToString().TrimEnd(',') + "]");
            }
            else
            {
                string tag = url.Split('/')[3];
                string fileVersion = _releases.First(r => r.Tag == tag).FileVersion;
                byte[] sums = Encoding.UTF8.GetBytes(Sums(fileVersion));
                body = url.EndsWith("/sums") ? (TamperWithList ? Encoding.UTF8.GetBytes(Sums(fileVersion) + new string('0', 64) + "  extra\n") : sums)
                    : url.EndsWith("/sig") ? SignatureAlgorithm.Ed25519.Sign(SigningKey, sums)
                    : ServeWrongFile ? "tampered"u8.ToArray() : AppBytes;
            }
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(body) });
        }
    }
}
