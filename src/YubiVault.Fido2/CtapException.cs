namespace YubiVault.Fido2;

/// <summary>A CTAP2 error from the security key, or a broken exchange with it.</summary>
public class CtapException : Exception
{
    public CtapException(string message, Exception? inner = null) : base(message, inner) { }

    public CtapException(byte status) : base($"The security key reported error 0x{status:X2}.") => Status = status;

    /// <summary>The CTAP2 status code, or 0 when the error did not come from the key.</summary>
    public byte Status { get; }
}

/// <summary>CTAP2 status codes this client reacts to.</summary>
public static class CtapStatus
{
    public const byte Ok = 0x00;
    public const byte InvalidCommand = 0x01;
    public const byte KeepaliveCancel = 0x2D;
    public const byte NoCredentials = 0x2E;
    public const byte UserActionTimeout = 0x2F;
    public const byte NotAllowed = 0x30;
    public const byte PinInvalid = 0x31;
    public const byte PinBlocked = 0x32;
    public const byte PinAuthInvalid = 0x33;
    public const byte PinAuthBlocked = 0x34;
    public const byte PinNotSet = 0x35;
    public const byte PuatRequired = 0x36;
    public const byte OperationDenied = 0x27;
    public const byte ActionTimeout = 0x3A;
}
