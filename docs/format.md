# Vault format (version 1)

A vault is a folder:

| Path | Contents |
| --- | --- |
| `vault.yv` | JSON header: format, version, vault id and key slots. Nothing secret in the clear. |
| `index.yv` | Encrypted JSON list of files: path, blob id, size, modification time. |
| `data/xx/<blob-id>.yvb` | One encrypted blob per file. Blob ids are 128 random bits in hex. |

## Keys

- **Master key:** 256 random bits per vault. It never changes and never touches the disk unencrypted.
- **Key slots:** each slot holds a copy of the master key wrapped with AES-256-GCM under a key-encryption key (KEK). The associated data binds the wrap to the vault id, slot id, slot type and password flag.
- **FIDO2 slot (`fido2`, default):** a non-discoverable credential created on the security key for relying party `yubivault`, with the hmac-secret extension and user verification (PIN) required. The slot stores the credential id and a random 32-byte salt. The key returns its hmac-secret (PRF) output for that salt through the Windows WebAuthn API. `KEK = HKDF-SHA256(ikm = secret, salt = salt, info = "YubiVault v1 fido2 kek")`. Works with any FIDO2 key that supports hmac-secret (YubiKey 5, Security Key by Yubico, ...).
- **YubiKey OTP slot (`yubikey`):** the YubiKey answers a random 64-byte challenge (stored in the slot) with HMAC-SHA1 from OTP slot 2. `KEK = HKDF-SHA256(ikm = response || Argon2id(password), salt = challenge, info = "YubiVault v1 yubikey kek")`. The password part is present only when the slot was created with a password.
- **Recovery slot:** a 160-bit random code, shown once as eight groups of four Base32 characters. `KEK = HKDF-SHA256(Argon2id(code), salt = argon2 salt, info = "YubiVault v1 recovery kek")`.
- **Argon2id defaults:** 64 MiB, 3 passes, parallelism 1, 16-byte random salt. The parameters are stored per slot.

## Encrypted streams (blobs and index)

```
header  = "YVF1" | version (1) | log2(chunk size) (1) | salt (32)
chunk_i = XChaCha20-Poly1305(k_x, n_x(i), AES-256-GCM(k_aes, n_aes(i), plaintext_i, ad), ad)
```

- `k_aes` and `k_x` are derived from the master key with HKDF-SHA256, using the stream's random salt and distinct info strings, so every file has its own pair of keys.
- Plaintext is split into 1 MiB chunks. Each chunk adds 32 bytes (two 16-byte tags).
- Nonces are the chunk counter (64-bit big-endian), zero padding and a final flag in the last byte (1 for the last chunk). A plaintext that ends on a chunk boundary is followed by an empty final chunk.
- The associated data `ad` is the header followed by a context: `blob:<blob-id>` for files and `index` for the index. Blobs therefore cannot be swapped or renamed, and truncation, reordering or duplication of chunks is detected.

Known limits of version 1: empty folders are not stored, and an attacker with write access to the vault folder can roll the whole vault back to an older consistent copy.
