# NCT Container Format — Draft v1

Status: design draft; not frozen for interoperability. Extension: `.nct`.

## Goals
- Versioned, bounded, authenticated encrypted archive.
- Multiple files through an encrypted manifest.
- Streaming/chunked data for large files.
- Separate password/recovery key wrapping from payload encryption.

## Proposed conceptual envelope
1. Magic identifier.
2. Format version and flags.
3. KDF identifier and bounded KDF parameters.
4. Random salt.
5. AEAD algorithm identifier.
6. Wrapped DEK metadata and nonce.
7. Payload layout and chunking parameters.
8. Encrypted manifest and payload chunks.
9. Authenticated finalization record.

## Cryptographic direction
- Password KDF: Argon2id with parameters calibrated to target platforms and bounded on read.
- Payload AEAD: XChaCha20-Poly1305.
- Random DEK generated independently from the password.
- KEK derived from the password wraps the DEK.
- Optional recovery secret wraps the same DEK using a separate, domain-separated wrapping key.

These choices are design targets, not implemented or audited features.

## Chunking requirements
Each encrypted chunk must bind archive identity, format version, chunk index, and relevant layout metadata as associated data. Nonce allocation must guarantee uniqueness under a DEK. The authenticated finalization record must detect truncation and missing chunks.

## Parser requirements
Reject unknown critical flags, unsupported versions, unreasonable KDF parameters, overflowing lengths, duplicate chunk indexes, incomplete finalization, and malformed/truncated structures according to the finalized specification.

## Compatibility
A format version must never change meaning after release. An incompatible change requires a new version. A formal byte-level specification and test vectors are required before v1 is frozen.
