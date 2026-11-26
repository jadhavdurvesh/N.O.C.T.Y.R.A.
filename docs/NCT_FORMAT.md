# NCT Container Format — Draft v1

Status: first implementation committed; format remains draft pending review and test vectors. Extension: `.nct`.

## Binary layout
All integer fields are little-endian.

| Offset | Length | Field |
|---:|---:|---|
| 0 | 4 | Magic: ASCII `NCTY` |
| 4 | 2 | Format version: `1` |
| 6 | 16 | Argon2id salt |
| 22 | 24 | XChaCha20-Poly1305 nonce |
| 46 | 8 | Ciphertext length, including 16-byte AEAD tag |
| 54 | variable | Ciphertext and authentication tag |

The parser requires the input length to equal 54 plus the declared ciphertext length. It rejects unknown versions, truncation, trailing bytes, ciphertext shorter than the tag, and ciphertext above the current 1 GiB implementation bound.

## Authenticated data
The AEAD associated data is the 14-byte sequence:

`NCTY || version_u16_le || ciphertext_length_u64_le`

The salt and nonce are inputs to the KDF and AEAD respectively. They are not secret. Changes to authenticated fields cause authentication failure.

## Cryptographic profile
- KDF: Argon2id, version 1.3.
- Memory: 65,536 KiB.
- Iterations: 3.
- Parallelism: 1 lane.
- Derived key: 32 bytes.
- AEAD: XChaCha20-Poly1305.
- Salt: 16 bytes from OS-backed randomness.
- Nonce: 24 bytes from OS-backed randomness.

These parameters are compiled into the crypto crate rather than encoded as negotiable header fields. A future format revision must encode a profile identifier or bounded KDF parameters and reject unsafe values before running the KDF.

## API
- `seal(password, plaintext) -> Result<Vec<u8>, ContainerError>`
- `open(password, archive) -> Result<Vec<u8>, ContainerError>`

The API handles byte payloads. File-tree manifests, safe path handling, streaming encryption, chunking, DEK envelope wrapping, and recovery-key wrapping are not yet implemented.

## Security requirements
- Authenticate before returning plaintext.
- Reject malformed lengths before allocating the declared payload.
- Do not extract files until full archive authentication succeeds.
- Do not overwrite existing destination files.
- Add filesystem path and symlink protections when file archives are implemented.
- Fuzz the parser and maintain byte-level test vectors before freezing v1.

A format version must never change meaning after release. Incompatible changes require a new version. This draft is not yet frozen for external interoperability.
