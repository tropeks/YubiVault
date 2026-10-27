using Yubico.YubiKey;
using Yubico.YubiKey.Otp;
using YubiVault.Core.Keys;

namespace YubiVault.YubiKey;

/// <summary>A connected YubiKey answering HMAC-SHA1 challenges from OTP slot 2 (long press).</summary>
/// <remarks>The OTP application is reached over HID, which works on Windows without administrator rights.</remarks>
public sealed class YubiKeyResponder : IChallengeResponder
{
    const Slot ChallengeSlot = Slot.LongPress;
    readonly IYubiKeyDevice _device;

    YubiKeyResponder(IYubiKeyDevice device) => _device = device;

    /// <summary>Called when the key is waiting for a touch.</summary>
    public Action? TouchNotifier { get; set; }

    public int? SerialNumber => _device.SerialNumber;

    public string Description =>
        $"YubiKey {_device.FirmwareVersion.Major} {_device.FormFactor}" + (SerialNumber is int s ? $" ({s})" : "");

    public static IReadOnlyList<YubiKeyResponder> FindAll() =>
        YubiKeyDevice.FindAll().Select(d => new YubiKeyResponder(d)).ToList();

    /// <summary>True when slot 2 already holds a configuration (ours or another tool's, e.g. KeePassXC).</summary>
    public bool IsSlotConfigured
    {
        get
        {
            using var otp = new OtpSession(_device);
            return otp.IsLongPressConfigured;
        }
    }

    /// <summary>
    /// Programs slot 2 with a fresh random HMAC-SHA1 secret that requires a touch.
    /// Overwrites whatever the slot held before, so callers must confirm with the user first.
    /// </summary>
    public void ProgramSlot()
    {
        using var otp = new OtpSession(_device);
        var secret = new byte[20];
        try
        {
            otp.ConfigureChallengeResponse(ChallengeSlot)
                .UseHmacSha1()
                .GenerateKey(secret)
                .UseButton(true)
                .Execute();
        }
        finally
        {
            Array.Clear(secret);
        }
    }

    public byte[] Respond(byte[] challenge)
    {
        using var otp = new OtpSession(_device);
        var operation = otp.CalculateChallengeResponse(ChallengeSlot)
            .UseYubiOtp(false)
            .UseChallenge(challenge);
        if (TouchNotifier is not null)
            operation = operation.UseTouchNotifier(TouchNotifier);
        return operation.GetDataBytes().ToArray();
    }
}
