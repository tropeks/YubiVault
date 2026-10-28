using Android.Nfc;
using Android.Nfc.Tech;
using YubiVault.Fido2;

namespace YubiVault.Android.Platform;

/// <summary>Opens FIDO2 keys held to the phone (ISO-DEP over NFC).</summary>
static class NfcKeys
{
    /// <summary>Long enough for the key to work out a PIN token and an hmac-secret.</summary>
    const int TimeoutMilliseconds = 30_000;

    /// <summary>Opens the tag as a FIDO2 key; null if it is not one or it was taken away.</summary>
    public static ICtapConnection? TryOpen(Tag tag)
    {
        var isoDep = IsoDep.Get(tag);
        if (isoDep is null)
            return null;
        var channel = new IsoDepChannel(isoDep);
        try
        {
            isoDep.Connect();
            isoDep.Timeout = TimeoutMilliseconds;
            return new CtapNfcConnection(channel);
        }
        catch (Exception e) when (e is CtapException or Java.IO.IOException or Java.Lang.SecurityException)
        {
            channel.Dispose();
            return null;
        }
    }

    sealed class IsoDepChannel(IsoDep isoDep) : IApduChannel
    {
        public byte[] Transceive(byte[] apdu)
        {
            try
            {
                return isoDep.Transceive(apdu) ?? throw new CtapException("The security key sent nothing over NFC.");
            }
            catch (Java.IO.IOException e)
            {
                throw new CtapException("The security key was moved away from the phone. Hold it still until it is done.", e);
            }
        }

        public void Dispose()
        {
            try
            {
                isoDep.Close();
            }
            catch (Java.IO.IOException)
            {
            }
        }
    }
}
