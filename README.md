<img src="assets/yubivault.png" width="96" align="right" alt="" />

# YubiVault

A portable vault for Windows that encrypts files and folders and only opens them with your **YubiKey** or other FIDO2 security key. A single `.exe`: no installation and no administrator rights, so it can live on a USB stick.

> **Status:** early preview (0.x). Keep a copy of anything important outside the vault until 1.0.

## Getting started

1. Download `YubiVault-<version>-win-x64.zip` from [Releases](../../releases) and unzip it anywhere, even a USB stick.
2. Run `YubiVault.exe`, click **Create a new vault...**, pick a folder and a name, and follow Windows' prompts for your security key's PIN and a touch.
3. Print or write down the recovery code it shows. It is the only way in if you lose your key.
4. Drag files and folders into the window to encrypt them. Double-click to open, or select and **Extract**.

Optional: click **Open .yvault files with YubiVault** on the start screen so that double-clicking a vault opens it. It is registered for your user only and needs no administrator rights.

The zip also has `yubivault-cli.exe`, a command-line version (`yubivault-cli help`).

### Android (preview)

The Android app opens and creates the same `.yvault` files. Plug the security key into the phone's USB port (USB-C, or an OTG adapter) or hold an NFC key to the back of the phone, then type the key's PIN. Vaults are picked with Android's file picker, so they can live in Downloads, on an SD card or in Google Drive; the app works on a private copy and writes it back after each change and when it locks. Requires Android 8 or later. Each CI run builds a test APK (`YubiVault-android` artifact).

## How it works

- **Your security key is the key.** YubiVault uses the FIDO2 hmac-secret (PRF) extension through Windows' own security key dialog: the secret never leaves the key, and every unlock asks for the key's PIN and a touch. Works with any YubiKey 5 or Security Key by Yubico, without administrator rights.
- **YubiKey 5 OTP mode (optional).** YubiKey 5 keys can instead use HMAC-SHA1 challenge-response (slot 2), optionally combined with a password.
- **Recovery.** When a vault is created, YubiVault shows a recovery code to print and keep safe. A second YubiKey can be registered later without re-encrypting anything.
- **Layered encryption.** Every file goes through AES-256-GCM and then XChaCha20-Poly1305, with independent keys derived by HKDF-SHA256. A future break in one algorithm is not enough to expose your data.
- **Hidden vault (optional).** A second vault can live inside a vault's file, in space that looks like random padding, with its own password (plus your security key) and its own recovery code. Without that password nobody can tell it exists, even after opening the outer vault. It protects against someone who sees one copy of the file, not against someone who compares copies over time (see [docs/format.md](docs/format.md#hidden-vault)).
- **A vault is a single `.yvault` file.** Keep it on a USB stick, a disk, OneDrive or Google Drive. From the outside there are no file names, folders, sizes or structure, only encrypted data.

## Roadmap

1. [x] Technical design
2. [x] Encryption core and command-line tool, with tests
3. [x] Vault desktop app (WPF)
4. [x] Single portable executable for Windows x64, released from tags by GitHub Actions

## Requirements

- Windows 10 or 11, 64-bit (OTP mode also works on Windows 10)
- A FIDO2 security key with hmac-secret and a PIN set (YubiKey 5 series, Security Key by Yubico, and others); FIDO2 needs Windows 11 22H2 or later

## Built with

C# and .NET 10, the [official Yubico .NET SDK](https://github.com/Yubico/Yubico.NET.SDK), [NSec](https://nsec.rocks/) (libsodium) for XChaCha20-Poly1305 and Argon2id, and Windows' native cryptography for AES-256-GCM.

## License

[GPLv3](LICENSE). YubiVault is an independent project and is not affiliated with Yubico. YubiKey is a registered trademark of Yubico AB.
