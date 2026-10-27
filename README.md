# YubiVault

A portable vault for Windows that encrypts files and folders and only opens them with your **YubiKey** or other FIDO2 security key. A single `.exe`: no installation and no administrator rights, so it can live on a USB stick.

> **Status:** in development. There is no release ready for use yet.

## How it works

- **Your security key is the key.** YubiVault uses the FIDO2 hmac-secret (PRF) extension through Windows' own security key dialog: the secret never leaves the key, and every unlock asks for the key's PIN and a touch. Works with any YubiKey 5 or Security Key by Yubico, without administrator rights.
- **YubiKey 5 OTP mode (optional).** YubiKey 5 keys can instead use HMAC-SHA1 challenge-response (slot 2), optionally combined with a password.
- **Recovery.** When a vault is created, YubiVault shows a recovery code to print and keep safe. A second YubiKey can be registered later without re-encrypting anything.
- **Layered encryption.** Every file goes through AES-256-GCM and then XChaCha20-Poly1305, with independent keys derived by HKDF-SHA256. A future break in one algorithm is not enough to expose your data.
- **A vault is a folder.** Keep it on a USB stick, a disk, OneDrive or Google Drive. From the outside there are no file names, folders or structure, only encrypted blobs and an encrypted index.

## Roadmap

1. [x] Technical design
2. [ ] Encryption core and command-line tool, with tests
3. [ ] Vault desktop app (WPF)
4. [ ] Single portable executable for Windows x64

## Requirements

- Windows 10 or 11, 64-bit (OTP mode also works on Windows 10)
- A FIDO2 security key with hmac-secret and a PIN set (YubiKey 5 series, Security Key by Yubico, and others); FIDO2 needs Windows 11 22H2 or later

## Built with

C# and .NET 10, the [official Yubico .NET SDK](https://github.com/Yubico/Yubico.NET.SDK), [NSec](https://nsec.rocks/) (libsodium) for XChaCha20-Poly1305 and Argon2id, and Windows' native cryptography for AES-256-GCM.

## License

[GPLv3](LICENSE). YubiVault is an independent project and is not affiliated with Yubico. YubiKey is a registered trademark of Yubico AB.
