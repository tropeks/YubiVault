using System.Security.Cryptography;
using System.Text;
using YubiVault.Core;
using YubiVault.Core.Keys;

namespace YubiVault.Fido2;

/// <summary>
/// Any FIDO2 security key with hmac-secret, reached through this library's own CTAP2 client over a
/// connection the platform opens (USB HID or NFC on Android). The PIN is asked before the key is
/// reached, so over NFC the key only has to be held to the phone for the exchange itself.
/// </summary>
/// <remarks>
/// Secrets match those read through the Windows WebAuthn API and <c>YubicoSecurityKey</c>: each salt is
/// turned into SHA-256("WebAuthn PRF" || 0x00 || salt) and the PIN is always verified, so a vault opens
/// with the same key on every system.
/// </remarks>
public sealed class CtapSecurityKey(Func<CancellationToken, ICtapConnection> connect) : IFido2Authenticator
{
    static readonly byte[] PrfPrefix = Encoding.ASCII.GetBytes("WebAuthn PRF\0");

    // Creating a vault or adding a key takes two exchanges; the PIN that worked for the first is
    // reused for the second, so it is typed once per operation (one instance per operation).
    string? _pin;

    /// <summary>Asks the user for the key's PIN; gets the retries left after a wrong PIN, or null on the first try. Null cancels.</summary>
    public required Func<int?, string?> AskPin { get; init; }

    /// <summary>Called when the key waits for a touch, and with false once it no longer does.</summary>
    public Action<bool>? TouchNotifier { get; init; }

    public CancellationToken CancellationToken { get; init; }

    public string Description => "Security key (FIDO2)";

    public byte[] MakeCredential(string relyingPartyId, byte[] userId, string userName) =>
        WithPinToken(relyingPartyId, (session, token) =>
            session.MakeCredential(relyingPartyId, "YubiVault", userId, userName, token));

    public (byte[] CredentialId, byte[] Secret) GetSecret(string relyingPartyId,
        IReadOnlyList<(byte[] CredentialId, byte[] Salt)> credentials) =>
        WithPinToken(relyingPartyId, (session, token) =>
        {
            // One salt per request, so each credential is tried on its own. A credential that was made
            // on another key is rejected before any touch is asked for.
            foreach (var (credentialId, salt) in credentials)
            {
                try
                {
                    return (credentialId, session.GetHmacSecret(relyingPartyId, credentialId, PrfSalt(salt), token));
                }
                catch (CtapException e) when (e.Status == CtapStatus.NoCredentials)
                {
                }
            }
            throw new WrongKeyException("This security key is not registered in this vault.");
        });

    static byte[] PrfSalt(byte[] salt) => SHA256.HashData([.. PrfPrefix, .. salt]);

    T WithPinToken<T>(string rpId, Func<Ctap2Session, byte[], T> action)
    {
        int? retries = null;
        while (true)
        {
            string pin = (retries is null ? _pin : null) ?? AskPin(retries) ?? throw new VaultException("Cancelled.");
            using var connection = Connect();
            connection.TouchNotifier = TouchNotifier;
            try
            {
                var session = new Ctap2Session(connection, CancellationToken);
                if (!session.SupportsHmacSecret)
                    throw new VaultException("This security key does not support the FIDO2 hmac-secret extension.");
                if (session.PinIsSet != true)
                    throw new VaultException("Set a FIDO2 PIN on your security key first (for example with Yubico Authenticator).");
                byte[] token;
                try
                {
                    token = session.GetPinToken(pin, rpId);
                }
                catch (CtapException e) when (e.Status == CtapStatus.PinInvalid)
                {
                    _pin = null;
                    retries = session.GetPinRetries();
                    if (retries == 0)
                        throw new WrongKeyException("The security key's PIN is blocked. Reset the key's FIDO2 app to use it again.");
                    continue;
                }
                _pin = pin;
                try
                {
                    return action(session, token);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(token);
                }
            }
            catch (OperationCanceledException e)
            {
                throw new VaultException("Cancelled.", e);
            }
            catch (CtapException e)
            {
                throw Translate(e);
            }
        }
    }

    ICtapConnection Connect()
    {
        try
        {
            return connect(CancellationToken);
        }
        catch (OperationCanceledException e)
        {
            throw new VaultException("Cancelled.", e);
        }
    }

    static Exception Translate(CtapException e) => e.Status switch
    {
        CtapStatus.PinNotSet => new VaultException("Set a FIDO2 PIN on your security key first (for example with Yubico Authenticator).", e),
        CtapStatus.PinBlocked => new WrongKeyException("The security key's PIN is blocked. Reset the key's FIDO2 app to use it again."),
        CtapStatus.PinAuthBlocked => new WrongKeyException("Too many wrong PINs. Remove and reinsert the key, then try again."),
        CtapStatus.PinAuthInvalid => new WrongKeyException("The security key rejected the PIN token. Try again."),
        CtapStatus.KeepaliveCancel => new VaultException("Cancelled.", e),
        CtapStatus.UserActionTimeout or CtapStatus.ActionTimeout => new VaultException("The security key was not touched in time.", e),
        CtapStatus.OperationDenied or CtapStatus.NotAllowed => new VaultException("The security key refused the request.", e),
        _ => new VaultException(e.Message, e),
    };
}
