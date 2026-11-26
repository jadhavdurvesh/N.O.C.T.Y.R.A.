# Security Policy

NOCTYRA is an early-stage private project. It is not yet audited and must not be used as the sole protection for high-value or safety-critical data.

## Non-negotiable implementation rules

- Use vetted AEAD and KDF implementations; never invent a cipher or KDF.
- Generate keys, salts, and nonces using an operating-system CSPRNG.
- Never reuse an AEAD nonce with the same key.
- Authenticate format metadata and chunk identity.
- Enforce strict input, decompression, image-dimension, decoded-allocation, and archive-size limits.
- Treat image-carrier checksums as corruption detection, never as authentication or encryption.
- Never promise steganographic undetectability; image carriers are optional and experimental.
- Avoid logging passwords, keys, plaintext filenames, or decrypted data.
- Do not write partially decrypted output to the final destination.
- Never automatically delete or overwrite source files.
- Treat interrupted extraction staging as recoverable data; cleanup must require an explicit user action, recognize only application-created markers, and avoid active operations.
- Review dependencies and commit Cargo.lock for applications.
- Fuzz untrusted parsers and image/container decoders. The NMF2 manifest and PNG/BMP image/carrier parsers have cargo-fuzz targets under `fuzz/`.


## Signing identities and trusted senders

- NCKV v1 stores an Ed25519 seed encrypted with the project's Argon2id + XChaCha20-Poly1305 password-encryption baseline. The cleartext public key is authenticated as associated data.
- NCTS v1 stores trusted sender public keys, labels, and local revocation flags inside an authenticated encrypted registry. A key is added only after the operator supplies the public key and confirms its full BLAKE3 fingerprint.
- Key rotation uses an NCRT v1 certificate signed by the currently trusted old key. A valid certificate proves key continuity only; it does not automatically add the successor to the local trust registry.
- Revocation is local to the encrypted registry. There is no global revocation service, transparency log, expiry mechanism, or automatic distribution yet.
- Registry rollback protection is not implemented. Restoring an older registry backup can restore a previously trusted key; operators must protect current registry backups and re-check fingerprints after recovery.
- Key-vault and trust-registry files are password encrypted, but active unlocked keys remain exposed to a compromised host. OS keychain / hardware-backed key storage is still pending.
- Unix CLI-created private vault and key files use mode 0600. Windows ACL hardening and platform-specific secure storage still require implementation and review.
- Password encryption does not protect weak passwords from offline guessing. Keep signing keys and trust-registry passwords strong and separate from the encrypted archives they authenticate.

## Reporting

Keep this repository private. Do not place real secrets, personal archives, or recovery keys in issues, commits, test fixtures, or CI logs.

## Release gate

A release requires passing tests, dependency review, malformed-input testing, cross-platform testing, and independent security review. A successful build alone is not evidence of security.
