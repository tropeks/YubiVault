# Vault format (version 2)

A vault is a single file, `<name>.yvault`:

| Offset | Contents |
| --- | --- |
| 0 | Superblock A (512-byte slot) |
| 512 | Superblock B (512-byte slot) |
| 1024 | Key area: 3072 random bytes, where hidden vault slots can live |
| 4096 | Padding: `padding` random bytes (0 by default), where a hidden vault can live |
| 4096 + padding | Records, appended one after another |

Records are never changed in place. There are three kinds:

- **Header:** JSON with format, version, vault id, key slots and padding size. Nothing secret in the clear.
- **Index:** an encrypted stream (see below) holding a JSON list of files: path, blob id, offset and length of the blob in the vault file, size and modification time.
- **Blob:** one encrypted stream per file. Blob ids are 128 random bits in hex; they appear only inside the encrypted index.

A superblock is `magic "YVAULT\0\x01" | generation | header offset | header length | index offset | index length | end of data | SHA-256 of the previous 56 bytes`, all integers 64-bit little-endian. The valid superblock with the highest generation is current; anything after its end of data is ignored and dropped on the next write.

**Writing.** New blobs, then a new header (only if the key slots changed) and a new index are appended and flushed to disk. Only then is the next generation written into the older superblock slot and flushed. A crash or power loss at any point leaves the previous generation intact.

**Compaction.** Deleted or replaced files leave unused records behind. When at least 1 MiB and a quarter of the file is unused, the live records are copied into a new file next to the vault (`<name>.yvault.compacting`), which then replaces the vault. `yubivault-cli compact` does it on demand. Blobs are copied as they are: they are bound to their blob id, not to their position. The key area and the padding are copied byte for byte, so a hidden vault in them survives.

**Locking.** While a vault is unlocked, its file is open for writing and other programs can only read it, so two windows cannot change the same vault.

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

## Hidden vault

A hidden vault is a second, independent vault inside the padding of a vault file. Every vault has the random key area and may have random padding (`yubivault-cli pad` adds some, which also hides how much the vault holds), so without the hidden vault's password nothing tells a vault with a hidden vault from one without.

- **Slots:** the key area holds a 16-byte salt, then six 500-byte slots. A slot is `nonce (12) | AES-256-GCM(slot key, payload) | tag (16)`, with associated data `"YubiVault v2 hidden slot|" + base64(vault id)`. Unused slots stay random. `slot key = HKDF-SHA256(Argon2id(secret, salt), salt, info)`, where the secret is the hidden password (info `"YubiVault v2 hidden password"`) or the hidden recovery code (info `"YubiVault v2 hidden recovery"`), with the vault options' Argon2id cost.
- **Password and security key:** that slot's payload holds a FIDO2 credential id (made for the hidden vault, never written in the clear), an hmac-secret salt and the hidden master key wrapped with AES-256-GCM under `HKDF-SHA256(secret || slot key, salt, "YubiVault v2 hidden fido2 kek")`. Opening needs both the password and the key.
- **Recovery code:** that slot's payload holds the hidden master key itself.
- **Records:** the padding, from its start, holds two 256-byte superblock slots (`nonce | AES-256-GCM(generation, index offset, index length, end) | tag`, random nonces) and then encrypted streams (index and blobs, as above, under the hidden master key). Everything after the superblocks is XORed with an AES-256-CTR keystream (counter = offset / 16), so even the stream headers look random. Keys: HKDF-SHA256 of the hidden master key with info `"YubiVault v2 hidden superblock"` and `"YubiVault v2 hidden mask"`.
- **Space:** the hidden vault has the fixed size of the padding. When it is full, it compacts in place, moving live records over deleted ones; unlike the outer compaction this is not crash-safe.
- **Creating** a hidden vault (`yubivault-cli hide`) rewrites the vault with a fresh random key area and padding, so it destroys any hidden vault that was there; so does `pad`.

Limits: deniability holds against someone who sees one copy of the file. Anyone with two copies from different times (backups, a cloud drive's version history) can see the padding change, which random padding never does on its own.

Version 1 files (no key area, no padding) are still read; the first compaction rewrites them as version 2.

Known limits: empty folders are not stored, and an attacker with write access to the vault file can roll the whole vault back to an older consistent copy, and can see the approximate total size of the files stored in it.
