using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Android.App;
using Android.OS;
using AndroidX.Core.Content;
using AndroidX.Credentials;
using AndroidX.Credentials.Exceptions;
using YubiVault.Core;
using YubiVault.Core.Keys;

namespace YubiVault.Android.Platform;

/// <summary>Android's own security key prompt could not be used; the app's CTAP client can take over.</summary>
sealed class NativeKeyUnavailableException(string message) : Exception(message);

/// <summary>
/// A security key used through Android's own FIDO2 stack (Credential Manager), which asks for the PIN and
/// the touch itself. It works only for <see cref="Vault.Fido2RelyingPartyId"/>, whose assetlinks.json lists
/// this app and its signing certificate. The PRF secret it returns is the same as the CTAP hmac-secret
/// path computes, so vaults open either way.
/// </summary>
/// <remarks>Blocking calls: use from a worker thread; the prompt runs on the UI thread.</remarks>
sealed class NativeSecurityKey(Activity activity, CancellationToken cancellationToken) : IFido2Authenticator
{
    public string Description => "Security key";

    public static bool Supports(string relyingPartyId) => relyingPartyId == Vault.Fido2RelyingPartyId;

    /// <exception cref="System.OperationCanceledException">The user closed the prompt.</exception>
    /// <exception cref="NativeKeyUnavailableException">The phone's prompt failed; try the app's own.</exception>
    public byte[] MakeCredential(string relyingPartyId, byte[] userId, string userName)
    {
        var create = new JsonObject
        {
            ["rp"] = new JsonObject { ["id"] = relyingPartyId, ["name"] = "YubiVault" },
            ["user"] = new JsonObject { ["id"] = Base64Url(userId), ["name"] = userName, ["displayName"] = userName },
            ["challenge"] = Base64Url(RandomNumberGenerator.GetBytes(32)),
            ["pubKeyCredParams"] = new JsonArray(new JsonObject { ["type"] = "public-key", ["alg"] = -7 }),
            ["timeout"] = 120000,
            ["attestation"] = "none",
            // No authenticatorAttachment: Android rejects "cross-platform" for security keys (tested on Android 16).
            ["authenticatorSelection"] = new JsonObject
            {
                ["residentKey"] = "discouraged",
                ["requireResidentKey"] = false,
                ["userVerification"] = "required",
            },
            ["hints"] = new JsonArray("security-key"),
        };
        var response = Await<CreatePublicKeyCredentialResponse>((manager, callback, signal, executor) =>
            manager.CreateCredentialAsync(activity, new CreatePublicKeyCredentialRequest(create.ToJsonString()), signal, executor, callback));
        var registration = JsonNode.Parse(response.RegistrationResponseJson)!;
        // Without the attachment Android also offers passkey managers; a vault needs the hardware key.
        if ((string?)registration["authenticatorAttachment"] == "platform")
            throw new VaultException("That passkey was saved on the phone or in a password manager. Choose your security key instead (\"Save another way\", then NFC or USB).");
        return FromBase64Url((string?)registration["rawId"] ?? (string)registration["id"]!);
    }

    /// <exception cref="System.OperationCanceledException">The user closed the prompt.</exception>
    /// <exception cref="NativeKeyUnavailableException">The phone's prompt failed; try the app's own.</exception>
    public (byte[] CredentialId, byte[] Secret) GetSecret(string relyingPartyId, IReadOnlyList<(byte[] CredentialId, byte[] Salt)> credentials)
    {
        var allow = new JsonArray();
        var bySalt = new JsonObject();
        foreach (var (id, salt) in credentials)
        {
            allow.Add(new JsonObject { ["type"] = "public-key", ["id"] = Base64Url(id) });
            bySalt[Base64Url(id)] = new JsonObject { ["first"] = Base64Url(salt) };
        }
        // The browser-style PRF input; Android hashes the salt as Windows does, so the secret matches the CTAP path.
        var prf = credentials.Count == 1
            ? new JsonObject { ["eval"] = new JsonObject { ["first"] = Base64Url(credentials[0].Salt) } }
            : new JsonObject { ["evalByCredential"] = bySalt };
        var get = new JsonObject
        {
            ["challenge"] = Base64Url(RandomNumberGenerator.GetBytes(32)),
            ["rpId"] = relyingPartyId,
            ["timeout"] = 120000,
            ["userVerification"] = "required",
            ["allowCredentials"] = allow,
            ["hints"] = new JsonArray("security-key"),
            ["extensions"] = new JsonObject { ["prf"] = prf },
        };
        var request = new GetCredentialRequest.Builder().AddCredentialOption(new GetPublicKeyCredentialOption(get.ToJsonString())).Build();
        var response = Await<GetCredentialResponse>((manager, callback, signal, executor) =>
            manager.GetCredentialAsync(activity, request, signal, executor, callback));
        if (response.Credential is not PublicKeyCredential credential)
            throw new NativeKeyUnavailableException("Android returned something other than a security key credential.");
        var assertion = JsonNode.Parse(credential.AuthenticationResponseJson)!;
        string? first = (string?)assertion["clientExtensionResults"]?["prf"]?["results"]?["first"];
        if (first is null)
            throw new NativeKeyUnavailableException("Android's prompt did not return the key's PRF secret.");
        byte[] used = FromBase64Url((string?)assertion["rawId"] ?? (string)assertion["id"]!);
        byte[] secret = FromBase64Url(first);
        if (secret.Length != 32)
            throw new NativeKeyUnavailableException("Android's prompt returned a PRF secret of unexpected length.");
        return (used, secret);
    }

    T Await<T>(Action<ICredentialManager, ICredentialManagerCallback, CancellationSignal, Java.Util.Concurrent.IExecutor> start)
        where T : Java.Lang.Object
    {
        var completion = new TaskCompletionSource<T>(TaskCreationOptions.RunContinuationsAsynchronously);
        var signal = new CancellationSignal();
        using var registration = cancellationToken.Register(signal.Cancel);
        activity.RunOnUiThread(() =>
        {
            try
            {
                start(CredentialManager.Create(activity), new Callback<T>(completion), signal, ContextCompat.GetMainExecutor(activity)!);
            }
            catch (Exception e)
            {
                completion.TrySetException(new NativeKeyUnavailableException(e.Message));
            }
        });
        return completion.Task.GetAwaiter().GetResult();
    }

    sealed class Callback<T>(TaskCompletionSource<T> completion) : Java.Lang.Object, ICredentialManagerCallback where T : Java.Lang.Object
    {
        public void OnResult(Java.Lang.Object? result)
        {
            if (result is T value)
                completion.TrySetResult(value);
            else
                completion.TrySetException(new NativeKeyUnavailableException("Android returned no credential."));
        }

        public void OnError(Java.Lang.Object e)
        {
            var error = Throwable(e);
            if (error is CreateCredentialCancellationException or GetCredentialCancellationException)
                completion.TrySetException(new System.OperationCanceledException());
            else
                completion.TrySetException(new NativeKeyUnavailableException(Describe(error, e)));
        }
    }

    static string Describe(Java.Lang.Throwable? error, Java.Lang.Object raw)
    {
        string? type = error switch
        {
            CreateCredentialException c => c.Type,
            GetCredentialException g => g.Type,
            _ => null,
        };
        string? message = error switch
        {
            CreateCredentialException c => c.ErrorMessage?.ToString(),
            GetCredentialException g => g.ErrorMessage?.ToString(),
            _ => null,
        } ?? error?.Message;
        string text = string.Join(": ", new[] { type, message }.Where(t => !string.IsNullOrEmpty(t)));
        return text.Length > 0 ? text : raw.ToString();
    }

    static Java.Lang.Throwable? Throwable(Java.Lang.Object error)
    {
        try
        {
            return global::Android.Runtime.Extensions.JavaCast<Java.Lang.Throwable>(error);
        }
        catch (Exception)
        {
            return null;
        }
    }

    static string Base64Url(byte[] data) => Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    static byte[] FromBase64Url(string text)
    {
        string s = text.Replace('-', '+').Replace('_', '/');
        return Convert.FromBase64String(s.PadRight(s.Length + (4 - s.Length % 4) % 4, '='));
    }
}

/// <summary>
/// The key the app hands to the vault on Android: credentials of <see cref="Vault.Fido2RelyingPartyId"/> go
/// through the phone's own prompt, older ones (and any case the phone's prompt cannot handle, such as a build
/// whose signature assetlinks.json does not list) through the app's CTAP client with its own PIN prompt.
/// </summary>
sealed class PhoneSecurityKey(NativeSecurityKey? native, IFido2Authenticator ctap, Action<string> onFallback) : IFido2Authenticator
{
    bool _nativeFailed;

    public string Description => ctap.Description;

    public byte[] MakeCredential(string relyingPartyId, byte[] userId, string userName) =>
        Route(relyingPartyId, key => key.MakeCredential(relyingPartyId, userId, userName));

    public (byte[] CredentialId, byte[] Secret) GetSecret(string relyingPartyId, IReadOnlyList<(byte[] CredentialId, byte[] Salt)> credentials) =>
        Route(relyingPartyId, key => key.GetSecret(relyingPartyId, credentials));

    T Route<T>(string relyingPartyId, Func<IFido2Authenticator, T> call)
    {
        if (native is null || _nativeFailed || !NativeSecurityKey.Supports(relyingPartyId))
            return call(ctap);
        try
        {
            return call(native);
        }
        catch (NativeKeyUnavailableException e)
        {
            _nativeFailed = true;
            onFallback(e.Message);
            return call(ctap);
        }
    }
}
