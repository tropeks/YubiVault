using YubiVault.Core;
using YubiVault.Core.Keys;

namespace YubiVault.Core.Tests;

/// <summary>Credentials of the current web relying party and of the legacy one, side by side.</summary>
public class RelyingPartyTests : IDisposable
{
    const string Password = "correct horse battery staple";

    readonly TempFolder _temp = new();

    public void Dispose() => _temp.Dispose();

    string VaultFilePath => _temp["test.yvault"];

    [Fact]
    public void NewSecurityKeysUseTheWebRelyingParty()
    {
        var key = new RelyingPartyKey("key-1");
        var (vault, _) = Vault.Create(VaultFilePath, key, Fast.Options);
        using (vault)
        {
            var slot = Assert.Single(vault.Slots, s => s.Type == KeySlotType.Fido2);
            Assert.Equal(Vault.Fido2RelyingPartyId, slot.RelyingPartyId);
        }
        Assert.All(key.RelyingParties, rp => Assert.Equal(Vault.Fido2RelyingPartyId, rp));
    }

    [Fact]
    public void ALegacyKeyStillOpensAfterTheCurrentKeysAreTried()
    {
        var current = new RelyingPartyKey("key-1");
        var legacy = new RelyingPartyKey("key-2");
        var (vault, _) = Vault.Create(VaultFilePath, current, Fast.Options);
        using (vault)
            vault.AddSecurityKey(legacy, Vault.LegacyFido2RelyingPartyId);

        legacy.RelyingParties.Clear();
        using (var opened = Vault.OpenWithFido2(VaultFilePath, legacy, Fast.Options))
            Assert.Equal(2, opened.Slots.Count(s => s.Type == KeySlotType.Fido2));
        Assert.Equal([Vault.Fido2RelyingPartyId, Vault.LegacyFido2RelyingPartyId], legacy.RelyingParties);

        current.RelyingParties.Clear();
        using (Vault.OpenWithFido2(VaultFilePath, current, Fast.Options))
        {
        }
        Assert.Equal([Vault.Fido2RelyingPartyId], current.RelyingParties);
    }

    [Fact]
    public void AnUnknownKeyIsRejectedAfterBothRelyingParties()
    {
        var (vault, _) = Vault.Create(VaultFilePath, new RelyingPartyKey("key-1"), Fast.Options);
        using (vault)
            vault.AddSecurityKey(new RelyingPartyKey("key-2"), Vault.LegacyFido2RelyingPartyId);

        var stranger = new RelyingPartyKey("key-3");
        Assert.Throws<WrongKeyException>(() => Vault.OpenWithFido2(VaultFilePath, stranger, Fast.Options));
        Assert.Equal([Vault.Fido2RelyingPartyId, Vault.LegacyFido2RelyingPartyId], stranger.RelyingParties);
    }

    [Theory]
    [InlineData(Vault.Fido2RelyingPartyId)]
    [InlineData(Vault.LegacyFido2RelyingPartyId)]
    public void AHiddenVaultRemembersItsKeysRelyingParty(string relyingPartyId)
    {
        var key = new RelyingPartyKey("key-1");
        var (vault, _) = Vault.Create(VaultFilePath, key, Fast.Options);
        using (vault)
            vault.CreateHiddenVault(Password, key, 1 << 20, relyingPartyId);

        key.RelyingParties.Clear();
        using (var hidden = Vault.OpenHidden(VaultFilePath, Password, key, Fast.Options))
            Assert.True(hidden.IsHidden);
        Assert.Equal([relyingPartyId], key.RelyingParties);
    }

    [Fact]
    public void AKeyThatReturnsTheSecretOnCreationIsAskedOnce()
    {
        var key = new RelyingPartyKey("key-1") { SecretOnCreation = true };
        var (vault, _) = Vault.Create(VaultFilePath, key, Fast.Options);
        vault.Dispose();
        Assert.Single(key.RelyingParties);

        key.SecretOnCreation = false;
        using (Vault.OpenWithFido2(VaultFilePath, key, Fast.Options))
        {
        }
    }

    /// <summary>A security key whose credentials belong to the relying party they were made for, like a real one.</summary>
    sealed class RelyingPartyKey(string deviceSecret) : IFido2Authenticator
    {
        readonly FakeSecurityKey _device = new(deviceSecret);
        readonly Dictionary<string, string> _owners = [];

        public List<string> RelyingParties { get; } = [];
        public bool SecretOnCreation { get; set; }

        public (byte[] CredentialId, byte[]? Secret) MakeCredential(string relyingPartyId, byte[] userId, string userName, byte[] salt)
        {
            byte[] id = MakeCredential(relyingPartyId, userId, userName);
            return (id, SecretOnCreation ? _device.GetSecret(relyingPartyId, [(id, salt)]).Secret : null);
        }
        public string Description => "Fake security key";

        public byte[] MakeCredential(string relyingPartyId, byte[] userId, string userName)
        {
            RelyingParties.Add(relyingPartyId);
            byte[] id = _device.MakeCredential(relyingPartyId, userId, userName);
            _owners[Convert.ToHexString(id)] = relyingPartyId;
            return id;
        }

        public (byte[] CredentialId, byte[] Secret) GetSecret(string relyingPartyId, IReadOnlyList<(byte[] CredentialId, byte[] Salt)> credentials)
        {
            RelyingParties.Add(relyingPartyId);
            var mine = credentials.Where(c => _owners.GetValueOrDefault(Convert.ToHexString(c.CredentialId)) == relyingPartyId).ToList();
            if (mine.Count == 0)
                throw new WrongKeyException("This security key is not registered in this vault.");
            return _device.GetSecret(relyingPartyId, mine);
        }
    }
}
