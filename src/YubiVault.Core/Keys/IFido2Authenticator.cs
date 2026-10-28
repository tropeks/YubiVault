namespace YubiVault.Core.Keys;

/// <summary>
/// A FIDO2 security key used through its hmac-secret (PRF) extension: for a given credential and salt,
/// the key returns a 32-byte secret it computes internally and never reveals otherwise.
/// </summary>
public interface IFido2Authenticator
{
    /// <summary>Human-readable name for the key slot, e.g. "Security key".</summary>
    string Description { get; }

    /// <summary>Creates a new non-discoverable credential with hmac-secret enabled; returns its id.</summary>
    byte[] MakeCredential(string relyingPartyId, byte[] userId, string userName);

    /// <summary>
    /// Asks the user's key for the secret of one of <paramref name="credentials"/> (one PIN entry and touch).
    /// </summary>
    /// <returns>The credential the key used, and its 32-byte secret for that credential's salt.</returns>
    (byte[] CredentialId, byte[] Secret) GetSecret(string relyingPartyId, IReadOnlyList<(byte[] CredentialId, byte[] Salt)> credentials);

    /// <summary>
    /// Creates a credential like <see cref="MakeCredential(string, byte[], string)"/> and, when the key can do both
    /// in one request, also returns its secret for <paramref name="salt"/>; otherwise the secret is null.
    /// </summary>
    (byte[] CredentialId, byte[]? Secret) MakeCredential(string relyingPartyId, byte[] userId, string userName, byte[] salt) =>
        (MakeCredential(relyingPartyId, userId, userName), null);
}
