using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using YubiVault.Core;
using YubiVault.Core.Keys;
using static YubiVault.YubiKey.WebAuthnNative;

namespace YubiVault.YubiKey;

/// <summary>
/// Any FIDO2 security key (YubiKey 5, Security Key by Yubico, ...) reached through the Windows WebAuthn
/// API. Windows shows its own dialog for the PIN and touch, and no administrator rights are needed.
/// </summary>
public sealed class WindowsSecurityKey(IntPtr ownerWindow) : IFido2Authenticator
{
    const int TimeoutMilliseconds = 120_000;

    public string Description => "Security key (FIDO2)";

    public static bool IsSupported(out string reason)
    {
        if (!OperatingSystem.IsWindows())
        {
            reason = "FIDO2 security keys are supported on Windows only.";
            return false;
        }
        int version;
        try
        {
            version = WebAuthNGetApiVersionNumber();
        }
        catch (Exception e) when (e is DllNotFoundException or EntryPointNotFoundException)
        {
            reason = "This version of Windows has no WebAuthn support. Windows 11 is required.";
            return false;
        }
        if (version < MinimumApiVersionForHmacSecret)
        {
            reason = $"This version of Windows (WebAuthn API {version}) cannot read hmac-secret. Update to Windows 11 22H2 or later.";
            return false;
        }
        reason = "";
        return true;
    }

    public byte[] MakeCredential(string relyingPartyId, byte[] userId, string userName)
    {
        EnsureSupported();
        using var pins = new Pins();
        var rp = new RpEntityInformation { Version = 1, Id = relyingPartyId, Name = "YubiVault" };
        var user = new UserEntityInformation
        {
            Version = 1, IdLength = userId.Length, Id = pins.Pin(userId), Name = userName, DisplayName = userName,
        };
        var algorithm = pins.PinStruct(new CoseCredentialParameter
        {
            Version = 1, CredentialType = CredentialTypePublicKey, Algorithm = CoseAlgorithmEcdsaP256Sha256,
        });
        var parameters = new CoseCredentialParameters { Count = 1, Parameters = algorithm };
        var clientData = ClientDataFor("webauthn.create", relyingPartyId, pins);

        // "hmac-secret": BOOL TRUE asks the key to enable the extension for this credential.
        var enable = pins.PinStruct(1);
        var extension = pins.PinStruct(new Extension
        {
            Identifier = pins.PinString(ExtensionHmacSecret), Length = sizeof(int), Value = enable,
        });
        var options = new MakeCredentialOptions
        {
            Version = 3,
            TimeoutMilliseconds = TimeoutMilliseconds,
            Extensions = new Extensions { Count = 1, Items = extension },
            AuthenticatorAttachment = AuthenticatorAttachmentCrossPlatform,
            RequireResidentKey = 0,
            UserVerificationRequirement = UserVerificationRequired,
            AttestationConveyancePreference = AttestationConveyanceNone,
        };

        int hr = WebAuthNAuthenticatorMakeCredential(ownerWindow, ref rp, ref user, ref parameters, ref clientData, ref options,
            out IntPtr result);
        ThrowOnError(hr, "register the security key");
        try
        {
            var attestation = Marshal.PtrToStructure<CredentialAttestation>(result);
            return Copy(attestation.CredentialId, attestation.CredentialIdLength);
        }
        finally
        {
            WebAuthNFreeCredentialAttestation(result);
        }
    }

    public (byte[] CredentialId, byte[] Secret) GetSecret(string relyingPartyId,
        IReadOnlyList<(byte[] CredentialId, byte[] Salt)> credentials)
    {
        EnsureSupported();
        using var pins = new Pins();
        var clientData = ClientDataFor("webauthn.get", relyingPartyId, pins);

        var allowed = new Credential[credentials.Count];
        var salts = new CredentialWithHmacSecretSalt[credentials.Count];
        for (int i = 0; i < credentials.Count; i++)
        {
            var (id, salt) = credentials[i];
            IntPtr idPtr = pins.Pin(id);
            allowed[i] = new Credential
            {
                Version = 1, IdLength = id.Length, Id = idPtr, CredentialType = pins.PinString(CredentialTypePublicKey),
            };
            salts[i] = new CredentialWithHmacSecretSalt
            {
                CredentialIdLength = id.Length,
                CredentialId = idPtr,
                Salt = pins.PinStruct(new HmacSecretSalt { FirstLength = salt.Length, First = pins.Pin(salt) }),
            };
        }
        var saltValues = pins.PinStruct(new HmacSecretSaltValues
        {
            CredentialSaltCount = salts.Length, CredentialSalts = pins.PinArray(salts),
        });
        var options = new GetAssertionOptions
        {
            Version = 6,
            TimeoutMilliseconds = TimeoutMilliseconds,
            CredentialList = new Credentials { Count = allowed.Length, Items = pins.PinArray(allowed) },
            AuthenticatorAttachment = AuthenticatorAttachmentCrossPlatform,
            UserVerificationRequirement = UserVerificationRequired,
            HmacSecretSaltValues = saltValues,
        };

        int hr = WebAuthNAuthenticatorGetAssertion(ownerWindow, relyingPartyId, ref clientData, ref options, out IntPtr result);
        ThrowOnError(hr, "read the security key");
        try
        {
            var assertion = Marshal.PtrToStructure<Assertion>(result);
            if (assertion.Version < 4 || assertion.HmacSecret == IntPtr.Zero)
                throw new VaultException("The security key did not return an hmac-secret. It may not support the FIDO2 hmac-secret extension.");
            var hmac = Marshal.PtrToStructure<HmacSecretSalt>(assertion.HmacSecret);
            if (hmac.FirstLength != 32)
                throw new VaultException("The security key returned an hmac-secret of unexpected length.");
            return (Copy(assertion.Credential.Id, assertion.Credential.IdLength), Copy(hmac.First, hmac.FirstLength));
        }
        finally
        {
            WebAuthNFreeAssertion(result);
        }
    }

    static void EnsureSupported()
    {
        if (!IsSupported(out string reason))
            throw new VaultException(reason);
    }

    static ClientData ClientDataFor(string type, string relyingPartyId, Pins pins)
    {
        // There is no web origin and nothing verifies the signature; the challenge only has to be fresh.
        string challenge = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        byte[] json = Encoding.UTF8.GetBytes($"{{\"type\":\"{type}\",\"challenge\":\"{challenge}\",\"origin\":\"app://{relyingPartyId}\"}}");
        return new ClientData { Version = 1, JsonLength = json.Length, Json = pins.Pin(json), HashAlgorithmId = HashAlgorithmSha256 };
    }

    static void ThrowOnError(int hr, string action)
    {
        if (hr == 0)
            return;
        string message = hr switch
        {
            NteUserCancelled => "The security key request was cancelled or timed out.",
            NteNotFound => "This security key is not registered in this vault.",
            _ => $"Could not {action}: {ErrorName(hr)} (0x{hr:X8}).",
        };
        throw new VaultException(message);
    }

    static string ErrorName(int hr)
    {
        try
        {
            return Marshal.PtrToStringUni(WebAuthNGetErrorName(hr)) ?? "unknown error";
        }
        catch (Exception)
        {
            return "unknown error";
        }
    }

    static byte[] Copy(IntPtr source, int length)
    {
        var bytes = new byte[length];
        if (length > 0)
            Marshal.Copy(source, bytes, 0, length);
        return bytes;
    }

    /// <summary>Unmanaged copies of the inputs, freed (and wiped) when the call is done.</summary>
    sealed class Pins : IDisposable
    {
        readonly List<(IntPtr Pointer, int Length)> _blocks = [];

        public IntPtr Pin(byte[] bytes)
        {
            IntPtr p = Marshal.AllocHGlobal(Math.Max(1, bytes.Length));
            Marshal.Copy(bytes, 0, p, bytes.Length);
            _blocks.Add((p, bytes.Length));
            return p;
        }

        public IntPtr PinString(string text)
        {
            IntPtr p = Marshal.StringToHGlobalUni(text);
            _blocks.Add((p, 0));
            return p;
        }

        public IntPtr PinStruct<T>(T value) where T : struct
        {
            int size = Marshal.SizeOf<T>();
            IntPtr p = Marshal.AllocHGlobal(size);
            Marshal.StructureToPtr(value, p, false);
            _blocks.Add((p, size));
            return p;
        }

        public IntPtr PinArray<T>(T[] values) where T : struct
        {
            int size = Marshal.SizeOf<T>();
            IntPtr p = Marshal.AllocHGlobal(Math.Max(1, size * values.Length));
            for (int i = 0; i < values.Length; i++)
                Marshal.StructureToPtr(values[i], p + i * size, false);
            _blocks.Add((p, size * values.Length));
            return p;
        }

        public void Dispose()
        {
            foreach (var (pointer, length) in _blocks)
            {
                for (int i = 0; i < length; i++)
                    Marshal.WriteByte(pointer, i, 0);
                Marshal.FreeHGlobal(pointer);
            }
        }
    }
}
