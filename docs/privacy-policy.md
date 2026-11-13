# YubiVault privacy policy

_Last updated: 13 November 2026_

YubiVault is a free, open-source app ([source code](https://github.com/tropeks/YubiVault), GPLv3) that encrypts files
into vaults that open only with your FIDO2 security key. It is made by one developer, not a company, and has no
servers, accounts, ads, analytics or tracking.

## What YubiVault collects

**Nothing.** The developer never receives any data from the app: not your files, not your vaults, not your security
key's PIN, not usage statistics, not crash reports.

## What stays on your device

- **Your vaults** are files you choose where to keep: on the phone, on a USB stick, or in a cloud storage app you
  already use (such as Google Drive, OneDrive or Dropbox). YubiVault reads and writes them only through the file
  picker, and only the files you pick. Anything you store in a cloud app is handled by that app under its own policy;
  YubiVault only ever hands it encrypted data.
- **Your security key's PIN** is used only to talk to the key over NFC or USB, held in memory as a hash while a
  vault is open and wiped afterwards. It is never written to storage.
- **Decrypted copies** of files you open from a vault are kept in the app's private cache and wiped when the vault
  locks.
- **Settings** (theme, language, the list of recent vaults) are kept in the app's private storage on the device.
  Android backups of the app are turned off.

## Network access

- **Google Play version:** the app has no internet permission and never goes online. Updates come from Google Play.
- **Version downloaded from GitHub:** at start-up the app asks GitHub (`api.github.com`) whether a newer release
  exists, and downloads it if you choose to update. GitHub sees the request like any web request (for example your IP
  address), under [GitHub's privacy statement](https://docs.github.com/site-policy/privacy-policies/github-general-privacy-statement).
  No information about you or your vaults is sent. The check can be turned off on the start page.

## Permissions

- **NFC** and **USB** to talk to your security key.
- **Internet** and **install packages** (GitHub version only) for the optional update described above.

## Children

YubiVault is not directed at children and collects no data from anyone.

## Changes and contact

Changes to this policy are published in this file, with its history visible on GitHub. Questions: open an issue at
<https://github.com/tropeks/YubiVault/issues>.
