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
  -> optional lossless image carrier
  -> recipient validation and reassembly
  -> authenticated decryption
  -> safe extraction
```

## Crate responsibilities

- `noctyra-core`: orchestration and shared application-level types.
- `noctyra-crypto`: password KDF, random key generation, AEAD, key wrapping.
- `noctyra-container`: NCT serialization and bounded parsing.
- `noctyra-image`: PNG/BMP loading, saving, and metadata policy.
- `noctyra-steganography`: reversible experimental carrier codec interfaces.
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

## Desktop boundary

Tauri commands form a narrow interface. The frontend must not implement cryptography, choose raw nonces, or manipulate key bytes. Sensitive operations run in the Rust core and return minimal status/results.
