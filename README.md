# YubiVault

A portable vault for Windows that encrypts files and folders and only opens them with your **YubiKey**. A single `.exe`: no installation and no administrator rights, so it can live on a USB stick.

> **Status:** in development. There is no release ready for use yet.

## How it works

- **Your YubiKey is the key.** YubiVault uses the YubiKey's HMAC-SHA1 challenge-response mode (slot 2). The secret never leaves the key, and every unlock asks for a touch.
- **Optional password.** It can be combined with the YubiKey as a second factor, in case someone gets both the key and the vault.
- **Recovery.** When a vault is created, YubiVault shows a recovery code to print and keep safe. A second YubiKey can be registered later without re-encrypting anything.
- **Layered encryption.** Every file goes through AES-256-GCM and then XChaCha20-Poly1305, with independent keys derived by HKDF-SHA256. A future break in one algorithm is not enough to expose your data.
- **A vault is a folder.** Keep it on a USB stick, a disk, OneDrive or Google Drive. From the outside there are no file names, folders or structure, only encrypted blobs and an encrypted index.

## Roadmap

1. [x] Technical design
2. [ ] Encryption core and command-line tool, with tests
3. [ ] Vault desktop app (WPF)
4. [ ] Single portable executable for Windows x64

## Requirements

- Windows 10 or 11, 64-bit
- A YubiKey 5 series key (tested with the YubiKey 5 NFC)

## Built with

C# and .NET 10, the [official Yubico .NET SDK](https://github.com/Yubico/Yubico.NET.SDK), [NSec](https://nsec.rocks/) (libsodium) for XChaCha20-Poly1305 and Argon2id, and Windows' native cryptography for AES-256-GCM.

## License

[GPLv3](LICENSE). YubiVault is an independent project and is not affiliated with Yubico. YubiKey is a registered trademark of Yubico AB.
