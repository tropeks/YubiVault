using System.Runtime.InteropServices;

namespace YubiVault.YubiKey;

// P/Invoke declarations for the Windows WebAuthn API (webauthn.h). Only the fields YubiVault uses are
// read; structures are declared up to the version that carries the hmac-secret (PRF) fields.
static class WebAuthnNative
{
    const string Dll = "webauthn.dll";

    public const int AuthenticatorAttachmentCrossPlatform = 2;
    public const int UserVerificationRequired = 1;
    public const int AttestationConveyanceNone = 1;
    public const int CoseAlgorithmEcdsaP256Sha256 = -7;
    public const string CredentialTypePublicKey = "public-key";
    public const string HashAlgorithmSha256 = "SHA-256";
    public const string ExtensionHmacSecret = "hmac-secret";

    /// <summary>API version that added hmac-secret salts to GetAssertion (Windows 11 22H2 and later).</summary>
    public const int MinimumApiVersionForHmacSecret = 4;

    public const int NteUserCancelled = unchecked((int)0x80090036);
    public const int NteNotFound = unchecked((int)0x80090011);
    public const int NteInvalidParameter = unchecked((int)0x80090027);

    [DllImport(Dll)]
    public static extern int WebAuthNGetApiVersionNumber();

    [DllImport(Dll)]
    public static extern int WebAuthNAuthenticatorMakeCredential(
        IntPtr hWnd,
        ref RpEntityInformation rpInformation,
        ref UserEntityInformation userInformation,
        ref CoseCredentialParameters pubKeyCredParams,
        ref ClientData clientData,
        ref MakeCredentialOptions options,
        out IntPtr credentialAttestation);

    [DllImport(Dll)]
    public static extern int WebAuthNAuthenticatorGetAssertion(
        IntPtr hWnd,
        [MarshalAs(UnmanagedType.LPWStr)] string rpId,
        ref ClientData clientData,
        ref GetAssertionOptions options,
        out IntPtr assertion);

    [DllImport(Dll)]
    public static extern void WebAuthNFreeCredentialAttestation(IntPtr credentialAttestation);

    [DllImport(Dll)]
    public static extern void WebAuthNFreeAssertion(IntPtr assertion);

    [DllImport(Dll)]
    public static extern IntPtr WebAuthNGetErrorName(int hr);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct RpEntityInformation
    {
        public int Version; // 1
        public string Id;
        public string Name;
        public string? Icon;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct UserEntityInformation
    {
        public int Version; // 1
        public int IdLength;
        public IntPtr Id;
        public string Name;
        public string? Icon;
        public string DisplayName;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct CoseCredentialParameter
    {
        public int Version; // 1
        public string CredentialType;
        public int Algorithm;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CoseCredentialParameters
    {
        public int Count;
        public IntPtr Parameters; // CoseCredentialParameter*
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct ClientData
    {
        public int Version; // 1
        public int JsonLength;
        public IntPtr Json;
        public string HashAlgorithmId;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct Credential
    {
        public int Version; // 1
        public int IdLength;
        public IntPtr Id;
        public IntPtr CredentialType; // LPCWSTR
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct Credentials
    {
        public int Count;
        public IntPtr Items; // Credential*
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct Extension
    {
        public IntPtr Identifier; // LPCWSTR
        public int Length;
        public IntPtr Value;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct Extensions
    {
        public int Count;
        public IntPtr Items; // Extension*
    }

    /// <summary>WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS, version 3.</summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct MakeCredentialOptions
    {
        public int Version;
        public int TimeoutMilliseconds;
        public Credentials CredentialList;
        public Extensions Extensions;
        public int AuthenticatorAttachment;
        public int RequireResidentKey; // BOOL
        public int UserVerificationRequirement;
        public int AttestationConveyancePreference;
        public int Flags;
        public IntPtr CancellationId; // v2
        public IntPtr ExcludeCredentialList; // v3
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct HmacSecretSalt
    {
        public int FirstLength;
        public IntPtr First;
        public int SecondLength;
        public IntPtr Second;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CredentialWithHmacSecretSalt
    {
        public int CredentialIdLength;
        public IntPtr CredentialId;
        public IntPtr Salt; // HmacSecretSalt*
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct HmacSecretSaltValues
    {
        public IntPtr GlobalSalt; // HmacSecretSalt*
        public int CredentialSaltCount;
        public IntPtr CredentialSalts; // CredentialWithHmacSecretSalt*
    }

    /// <summary>WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS, version 6.</summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct GetAssertionOptions
    {
        public int Version;
        public int TimeoutMilliseconds;
        public Credentials CredentialList;
        public Extensions Extensions;
        public int AuthenticatorAttachment;
        public int UserVerificationRequirement;
        public int Flags;
        public IntPtr U2fAppId; // v2
        public IntPtr U2fAppIdUsed; // v2, BOOL*
        public IntPtr CancellationId; // v3
        public IntPtr AllowCredentialList; // v4
        public int CredLargeBlobOperation; // v5
        public int CredLargeBlobLength; // v5
        public IntPtr CredLargeBlob; // v5
        public IntPtr HmacSecretSaltValues; // v6, HmacSecretSaltValues*
        public int BrowserInPrivateMode; // v6
    }

    /// <summary>Leading fields of WEBAUTHN_CREDENTIAL_ATTESTATION (version 1).</summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct CredentialAttestation
    {
        public int Version;
        public IntPtr FormatType;
        public int AuthenticatorDataLength;
        public IntPtr AuthenticatorData;
        public int AttestationLength;
        public IntPtr Attestation;
        public int AttestationDecodeType;
        public IntPtr AttestationDecode;
        public int AttestationObjectLength;
        public IntPtr AttestationObject;
        public int CredentialIdLength;
        public IntPtr CredentialId;
    }

    /// <summary>Leading fields of WEBAUTHN_ASSERTION up to version 4 (hmac-secret output).</summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct Assertion
    {
        public int Version;
        public int AuthenticatorDataLength;
        public IntPtr AuthenticatorData;
        public int SignatureLength;
        public IntPtr Signature;
        public Credential Credential;
        public int UserIdLength;
        public IntPtr UserId;
        public Extensions Extensions; // v2
        public int CredLargeBlobLength; // v3
        public IntPtr CredLargeBlob; // v3
        public int CredLargeBlobStatus; // v3
        public IntPtr HmacSecret; // v4, HmacSecretSalt*
    }
}
