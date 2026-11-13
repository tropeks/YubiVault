# Publishing on Google Play

The Play build is the same app without the self-updater: Play forbids apps that download and install their own
updates, so `-p:PlayStore=true` drops the update check, the update button and the `INTERNET` and
`REQUEST_INSTALL_PACKAGES` permissions, and builds an `.aab` instead of an `.apk`. The package name stays
`io.github.tropeks.yubivault`.

Every release ([releasing.md](releasing.md)) attaches `YubiVault-<version>-google-play.aab`, signed with the release
keystore, which serves as Play's **upload key**. Upload that file in Play Console. To build it by hand:

```sh
dotnet publish src/YubiVault.Android -c Release -p:PlayStore=true \
  -p:AndroidKeyStore=true -p:AndroidSigningKeyStore=yubivault-release.keystore -p:AndroidSigningKeyAlias=yubivault \
  -p:AndroidSigningStorePass=env:PW -p:AndroidSigningKeyPass=env:PW -o play
```

Delete `src/YubiVault.Android/obj` and `bin` first if you built the GitHub version in the same checkout.

## Play Console answers

| Section | Answer |
| --- | --- |
| App or game / Free or paid | App, free |
| Category | Tools |
| Privacy policy URL | https://github.com/tropeks/YubiVault/blob/main/docs/privacy-policy.md |
| Ads | No ads |
| App access | Some functionality is restricted: unlocking needs a FIDO2 security key (see below) |
| Content rating | Answer "No" to every question (no violence, user content, sharing, location or purchases) |
| Target audience | 18 and over (not designed for children) |
| News app | No |
| Data safety: collects or shares data? | **No** for every data type. The Play build has no internet permission. |
| Data safety: encrypted in transit? | Not applicable (no data leaves the device) |
| Data safety: users can request deletion? | Not applicable (nothing is collected) |
| Government app / financial features / health | No |

**App access note for reviewers:** "YubiVault opens encrypted vaults with a FIDO2 security key (for example a
YubiKey) over NFC or USB, plus its PIN. Without a key you can still browse the start page, the language and theme
settings, and the create-vault screen up to the step that asks for the key. The full source is at
https://github.com/tropeks/YubiVault."

## Store listing

**App name** (30 characters max): `YubiVault`

**Short description** (80 max):

> Encrypted file vault that opens only with your YubiKey or FIDO2 security key.

**Full description** (4000 max):

> YubiVault keeps your files in an encrypted vault that opens only with your YubiKey or another FIDO2 security key. Hold the key to the back of the phone (NFC) or plug it in (USB), enter its PIN, and your files are there.
>
> YOUR SECURITY KEY IS THE KEY
> Every unlock needs the key and its PIN. A recovery code, shown when you create the vault, gets you back in if you lose the key, and a second key can be added as a spare.
>
> ONE FILE, ANYWHERE
> A vault is a single .yvault file. Keep it on the phone or in Google Drive, OneDrive or Dropbox: YubiVault opens it from there and writes changes straight back. From the outside there are no file names, folders or sizes, only encrypted data.
>
> STRONG, LAYERED ENCRYPTION
> Every file is encrypted twice, with AES-256-GCM and XChaCha20-Poly1305, under independent keys.
>
> HIDDEN VAULT
> Optionally hide a second vault inside a vault's file, with its own key and recovery code. Nobody can tell it is there.
>
> LOCKS ITSELF
> The vault locks as soon as you leave the app, and decrypted copies of opened files are wiped.
>
> WINDOWS, MAC, LINUX AND ANDROID
> The same vault opens in the free YubiVault desktop app on Windows, macOS and Linux.
>
> PRIVATE BY DESIGN
> No account, no ads, no tracking, and no internet permission: your files never leave your control. YubiVault is free and open source (GPLv3): github.com/tropeks/YubiVault
>
> Available in English, Português, Español, Français, Русский, 日本語, 中文 (简体/繁體), हिन्दी, বাংলা and العربية.
>
> Status: early preview. Keep a copy of anything important outside the vault until version 1.0.
>
> YubiKey is a trademark of Yubico AB. YubiVault is an independent project, not affiliated with or endorsed by Yubico.

### Graphics

| Asset | Size | Source |
| --- | --- | --- |
| App icon | 512 × 512 PNG | `play-store-512.png` from the icon set |
| Feature graphic | 1024 × 500 PNG or JPEG | [assets/play-feature-graphic.png](../assets/play-feature-graphic.png) |
| Phone screenshots | 2 to 8, 16:9 or 9:16, 320 to 3840 px | [docs/screenshots](screenshots) (`android-*.png`) |
