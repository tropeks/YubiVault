# Releasing

Pushing a `v*` tag (or publishing a release from the GitHub page) runs `.github/workflows/release.yml`,
which builds every platform, signs the Android APK, and attaches everything to the release with
`SHA256SUMS.txt` and its Ed25519 signature `SHA256SUMS.txt.sig`. The apps update only from releases
whose checksum list carries that signature.

## Repository secrets

Set these once under **Settings → Secrets and variables → Actions**. The release fails without them.

| Secret | What it is |
| --- | --- |
| `UPDATE_SIGNING_KEY` | The Ed25519 private key that signs `SHA256SUMS.txt`, in PEM form (`-----BEGIN PRIVATE KEY-----` …). Its public half is built into the apps (`UpdateChecker.ReleasePublicKey`) and kept in [update-public-key.pem](update-public-key.pem). |
| `ANDROID_KEYSTORE_BASE64` | The Android release keystore (PKCS#12, alias `yubivault`), base64-encoded on one line. |
| `ANDROID_KEYSTORE_PASSWORD` | The password of that keystore and of its key. |

Keep an offline copy of both keys. If the update key is lost, installed apps stop accepting updates until
users install a build with a new public key by hand. If the Android keystore is lost, Android refuses to
install new builds over the old app: users have to uninstall it first (their vaults are separate files and
are not affected).

## Versions

Tags are `vMAJOR.MINOR.PATCH`. The Android version code is `MAJOR*10000 + MINOR*100 + PATCH`, so minor and
patch stay below 100. Releases numbered 0.x are marked as pre-releases on GitHub; the apps still offer them.
