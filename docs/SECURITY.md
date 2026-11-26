# Security Policy

NOCTYRA is an early-stage private project. It is not yet audited and must not be used as the sole protection for high-value or safety-critical data.

## Non-negotiable implementation rules

- Use vetted AEAD and KDF implementations; never invent a cipher or KDF.
- Generate keys, salts, and nonces using an operating-system CSPRNG.
- Never reuse an AEAD nonce with the same key.
- Authenticate format metadata and chunk identity.
- Enforce strict input, decompression, image-dimension, and archive-size limits.
- Avoid logging passwords, keys, plaintext filenames, or decrypted data.
- Do not write partially decrypted output to the final destination.
- Never automatically delete or overwrite source files.
- Treat interrupted extraction staging as recoverable data; cleanup must require an explicit user action, recognize only application-created markers, and avoid active operations.
- Review dependencies and commit Cargo.lock for applications.
- Fuzz untrusted parsers and image/container decoders. The NMF2 manifest has a cargo-fuzz target under `fuzz/`.

## Reporting

Keep this repository private. Do not place real secrets, personal archives, or recovery keys in issues, commits, test fixtures, or CI logs.

## Release gate

A release requires passing tests, dependency review, malformed-input testing, cross-platform testing, and independent security review. A successful build alone is not evidence of security.
