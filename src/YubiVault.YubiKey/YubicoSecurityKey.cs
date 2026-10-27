using System.Security.Cryptography;
using System.Text;
using Yubico.YubiKey;
using Yubico.YubiKey.Fido2;
using YubiVault.Core;
using YubiVault.Core.Keys;

namespace YubiVault.YubiKey;

/// <summary>
/// A Yubico FIDO2 key (YubiKey 5, Security Key by Yubico) reached directly over USB HID with the Yubico
/// SDK, for Linux and macOS where there is no system WebAuthn dialog. The PIN is asked through
/// <see cref="AskPin"/> and touches are announced through <see cref="TouchNotifier"/>.
/// </summary>
/// <remarks>
/// Secrets match those read through the Windows WebAuthn API, which turns each salt into
/// SHA-256("WebAuthn PRF" || 0x00 || salt) before passing it to hmac-secret; this class does the same,
/// so a vault opens with the same key on every system.
/// </remarks>
public sealed class YubicoSecurityKey : IFido2Authenticator
{
    static readonly byte[] PrfPrefix = Encoding.ASCII.GetBytes("WebAuthn PRF\0");

    /// <summary>Asks the user for the key's PIN; gets the retries left, or null on the first try. Null cancels.</summary>
    public required Func<int?, string?> AskPin { get; init; }

    /// <summary>Called when the key waits for a touch, and with false once it no longer does.</summary>
    public Action<bool>? TouchNotifier { get; init; }

    public string Description => "Security key (FIDO2)";

    /// <summary>True if a Yubico key with FIDO2 is connected (other brands are not reachable this way).</summary>
    public static bool IsConnected() => FindDevice() is not null;

    public byte[] MakeCredential(string relyingPartyId, byte[] userId, string userName)
    {
        using var fido2 = OpenSession();
        RequireHmacSecret(fido2);
        var parameters = new MakeCredentialParameters(
            new RelyingParty(relyingPartyId) { Name = "YubiVault" },
            new UserEntity(userId) { Name = userName, DisplayName = userName })
        {
            ClientDataHash = RandomNumberGenerator.GetBytes(32),
        };
        parameters.AddOption(AuthenticatorOptions.rk, false);
        parameters.AddHmacSecretExtension(fido2.AuthenticatorInfo);
        var data = Run(() => fido2.MakeCredential(parameters));
        return (data.AuthenticatorData.CredentialId?.Id ?? throw new VaultException("The security key returned no credential."))
            .ToArray();
    }

    public (byte[] CredentialId, byte[] Secret) GetSecret(string relyingPartyId,
        IReadOnlyList<(byte[] CredentialId, byte[] Salt)> credentials)
    {
        using var fido2 = OpenSession();
        RequireHmacSecret(fido2);
        // CTAP takes one salt per request, so each credential is tried on its own. A credential that
        // was made on another key is rejected before any touch is asked for.
        foreach (var (credentialId, salt) in credentials)
        {
            var parameters = new GetAssertionParameters(new RelyingParty(relyingPartyId), RandomNumberGenerator.GetBytes(32));
            parameters.AllowCredential(new CredentialId { Id = credentialId });
            parameters.RequestHmacSecretExtension(PrfSalt(salt));
            IReadOnlyList<GetAssertionData> assertions;
            try
            {
                assertions = Run(() => fido2.GetAssertions(parameters));
            }
            catch (Fido2Exception e) when (e.Status == CtapStatus.NoCredentials)
            {
                continue;
            }
            var assertion = assertions[0];
            byte[] secret = assertion.AuthenticatorData.GetHmacSecretExtension(fido2.AuthProtocol);
            if (secret.Length < 32)
                throw new VaultException("The security key did not return an hmac-secret.");
            return (assertion.CredentialId.Id.ToArray(), secret[..32]);
        }
        throw new WrongKeyException("This security key is not registered in this vault.");
    }

    static byte[] PrfSalt(byte[] salt) => SHA256.HashData([.. PrfPrefix, .. salt]);

    Fido2Session OpenSession()
    {
        var device = FindDevice()
            ?? throw new VaultException("No security key found. Plug in your YubiKey or Security Key by Yubico.");
        return new Fido2Session(device) { KeyCollector = CollectKey };
    }

    static IYubiKeyDevice? FindDevice() =>
        YubiKeyDevice.FindByTransport(Transport.HidFido).FirstOrDefault();

    static void RequireHmacSecret(Fido2Session fido2)
    {
        if (!fido2.AuthenticatorInfo.IsExtensionSupported("hmac-secret"))
            throw new VaultException("This security key does not support the FIDO2 hmac-secret extension.");
        if (fido2.AuthenticatorInfo.GetOptionValue(AuthenticatorOptions.clientPin) != OptionValue.True)
            throw new VaultException("Set a FIDO2 PIN on your security key first (for example with Yubico Authenticator).");
    }

    bool CollectKey(KeyEntryData data)
    {
        switch (data.Request)
        {
            case KeyEntryRequest.VerifyFido2Pin:
                string? pin = AskPin(data.IsRetry ? data.RetriesRemaining : null);
                if (pin is null)
                    return false;
                byte[] bytes = Encoding.UTF8.GetBytes(pin);
                try
                {
                    data.SubmitValue(bytes);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(bytes);
                }
                return true;
            case KeyEntryRequest.TouchRequest:
                TouchNotifier?.Invoke(true);
                return true;
            case KeyEntryRequest.Release:
                TouchNotifier?.Invoke(false);
                return true;
            default:
                return false;
        }
    }

    static T Run<T>(Func<T> action)
    {
        try
        {
            return action();
        }
        catch (OperationCanceledException e)
        {
            throw new VaultException("Cancelled.", e);
        }
        catch (Fido2Exception e) when (e.Status == CtapStatus.PinNotSet)
        {
            throw new VaultException("Set a FIDO2 PIN on your security key first (for example with Yubico Authenticator).", e);
        }
        catch (Fido2Exception e) when (e.Status is CtapStatus.PinInvalid or CtapStatus.PinBlocked or CtapStatus.PinAuthInvalid)
        {
            throw new WrongKeyException(e.Status == CtapStatus.PinInvalid
                ? "Wrong PIN."
                : "The security key's PIN is blocked. Remove and reinsert the key, or reset it.");
        }
    }
}
