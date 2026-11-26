# NOCTYRA Architecture

## Principles

1. Encryption is the security boundary; carrier concealment is optional and does not replace cryptography.
2. Use established, audited cryptographic primitives. Never design a proprietary cipher.
3. Keep the core independent of the user interface.
4. Treat all imported archives and images as hostile input.
5. Use explicit format versions, bounded parsing, and authenticated metadata.
6. Preserve original user files; never silently overwrite or delete them.

## Logical flow

```text
User files
  -> bounded compression (optional)
  -> versioned NCT archive manifest
  -> authenticated encryption
  -> encrypted archive payload
  -> optional CONSTELLATION packetization
  -> optional lossless PNG/BMP image carrier (NCAR v1 RGB-LSB frame)
  -> recipient carrier extraction and payload integrity check
  -> recipient validation and reassembly
  -> authenticated decryption
  -> safe extraction
```

## Crate responsibilities

- `noctyra-core`: orchestration and shared application-level types.
- `noctyra-crypto`: password KDF, random key generation, AEAD, key wrapping.
- `noctyra-container`: NCT serialization and bounded parsing.
- `noctyra-image`: bounded PNG/BMP loading, pixel access and encoding.
- `noctyra-steganography`: reversible experimental RGB-LSB carrier codec and NCAR payload framing.
- `noctyra-compression`: bounded compression/decompression.
- `noctyra-constellation`: packet manifests, identifiers, integrity and reassembly.
- `noctyra-recovery`: validation, duplicate/missing-part reporting and recovery orchestration.
- `noctyra-validation`: common limits and input validation.

## Key management model

The intended design is envelope encryption:
- A random data-encryption key (DEK) encrypts archive content.
- A password-derived key-encryption key (KEK) wraps the DEK.
- A separately generated recovery secret may wrap the same DEK.
- Password changes should re-wrap the DEK rather than re-encrypt all content.

The design must specify nonce uniqueness, key identifiers, associated data, version migration and memory-clearing limits before implementation.

## Image carrier boundary

The initial image lab accepts PNG and BMP only, checks file signatures and bounds compressed input, dimensions and decoded RGBA allocation. The experimental NCAR v1 frame carries an opaque payload with a length and BLAKE3 corruption-detection digest. RGB least-significant bits are modified; alpha is preserved. The intended payload is an already-encrypted NCT archive. The digest is not an authentication substitute: NCT AEAD must still verify. Lossy transforms, resizing, filtering, recompression by lossy services and many metadata/image optimizers may destroy the carrier. No undetectability guarantee is made.

## Desktop boundary

Tauri commands form a narrow interface. The frontend must not implement cryptography, choose raw nonces, or manipulate key bytes. Sensitive operations run in the Rust core and return minimal status/results.
