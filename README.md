<img src="assets/yubivault.png" width="96" align="right" alt="" />

# YubiVault

A portable vault for Windows that encrypts files and folders and only opens them with your **YubiKey** or other FIDO2 security key. A single `.exe`: no installation and no administrator rights, so it can live on a USB stick.

> **Status:** early preview (0.x). Keep a copy of anything important outside the vault until 1.0.

## Getting started

### Windows

1. Download `YubiVault-<version>-win-x64.zip` from [Releases](../../releases) and unzip it anywhere, even a USB stick.
2. Run `YubiVault.exe`, click **Create a new vault...**, pick a folder and a name, and follow Windows' prompts for your security key's PIN and a touch.
3. Print or write down the recovery code it shows. It is the only way in if you lose your key.
4. Drag files and folders into the window to encrypt them. Double-click to open, or select and **Extract**.

Optional: click **Open .yvault files with YubiVault** on the start screen so that double-clicking a vault opens it. It is registered for your user only and needs no administrator rights.

The zip also has `yubivault-cli.exe`, a command-line version (`yubivault-cli help`).

### Linux

1. Download `YubiVault-<version>-linux-x64.tar.gz` (or `linux-arm64`) and unpack it: `tar xzf YubiVault-*.tar.gz`.
2. Run `./YubiVault` from that folder, or `./install.sh` to add it to your applications menu and open `.yvault` files with it. It installs for your user only, in `~/.local`, without root (`./install.sh --uninstall` removes it).
3. **Security key access.** YubiVault reads the key through `/dev/hidraw*`. On systemd 244 or later (Ubuntu 20.04+, Debian 11+, Fedora 32+ and most current distributions) the `uaccess` tag in systemd's `60-fido-id.rules` already gives the logged-in user access, so there is nothing to do. On older or non-systemd systems, install the bundled rule and replug the key:

   ```sh
   sudo cp share/70-yubivault-fido.rules /etc/udev/rules.d/
   sudo udevadm control --reload && sudo udevadm trigger
   ```

### macOS

1. Download `YubiVault-<version>-osx-arm64.zip` for Apple Silicon or `osx-x64` for Intel Macs, unzip it and drag `YubiVault.app` to Applications (or keep it on a USB stick).
2. YubiVault is free and not notarized by Apple, so the first launch is blocked: right-click the app, choose **Open**, then **Open** again. Or run `xattr -dr com.apple.quarantine YubiVault.app`.
3. `.yvault` files open with YubiVault from Finder. `yubivault-cli` in the zip is the command-line version.

## How it works

- **Your security key is the key.** YubiVault uses the FIDO2 hmac-secret (PRF) extension through Windows' own security key dialog: the secret never leaves the key, and every unlock asks for the key's PIN and a touch. Works with any YubiKey 5 or Security Key by Yubico, without administrator rights.
- **YubiKey 5 OTP mode (optional).** YubiKey 5 keys can instead use HMAC-SHA1 challenge-response (slot 2), optionally combined with a password.
- **Recovery.** When a vault is created, YubiVault shows a recovery code to print and keep safe. A second YubiKey can be registered later without re-encrypting anything.
- **Layered encryption.** Every file goes through AES-256-GCM and then XChaCha20-Poly1305, with independent keys derived by HKDF-SHA256. A future break in one algorithm is not enough to expose your data.
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
