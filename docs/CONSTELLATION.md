# CONSTELLATION — Multi-Carrier Transport Protocol

Status: experimental v1 fragment and reassembly implementation. Not frozen for interoperability.

CONSTELLATION transports an already encrypted NCT payload across a set of independently handled carrier files. It is a transport and recovery format, not an encryption algorithm and not a promise of steganographic undetectability.

## Modes
- SINGLE: one carrier for a payload that fits within configured limits.
- CONSTELLATION: multiple carriers containing indexed payload fragments.
- DIRECT: transfer the encrypted NCT archive without image carriers.
- RECOVERY: inspect available carriers, validate them, and reconstruct when sufficient valid data is present.

## Protocol objectives
- Identify a transfer and its format version.
- Identify each fragment and its position.
- Detect duplicate, missing, modified, or foreign fragments.
- Bind recovery metadata to a signed, independently trusted sender identity.
- Add erasure-code redundancy for loss recovery.
- Reassemble the exact encrypted NCT byte stream before decryption.

## Implemented NCFR v1 fragment frame

Each fragment is an opaque byte record embedded as the NCAR payload:

| Offset | Length | Field |
|---:|---:|---|
| 0 | 4 | Magic: ASCII `NCFR` |
| 4 | 2 | Protocol version (little-endian, currently 1) |
| 6 | 16 | Random transfer identifier |
| 22 | 8 | Complete encrypted archive length |
| 30 | 4 | Zero-based fragment index |
| 34 | 4 | Total fragment count |
| 38 | 4 | Fragment data length |
| 42 | 32 | BLAKE3 digest of complete archive |
| 74 | 32 | BLAKE3 digest of this fragment's data |
| 106 | variable | Fragment data |

Default fragment data is 4 MiB; maximum is 8 MiB. A transfer is limited to 256 fragments and 1 GiB of archive data. Framing uses a random 128-bit transfer identifier. A deterministic-ID function exists only for test vectors.

The v1 digests are unkeyed corruption checks, not sender authentication. The transfer identifier is not a secret. The complete NCT archive must still pass its authenticated decryption before plaintext is trusted. NCMF v1 signed manifests now provide sender-key authentication when the recipient pins the expected Ed25519 public key.

NCFR v1 remains a standalone transport frame. Authenticated metadata for recovery sets is carried in NCMF v1; it does not retroactively authenticate legacy NCFR v1 transfers.

## Implemented reassembly rules
1. Treat every carrier and fragment as untrusted input.
2. Validate magic, version, lengths, and resource bounds before allocation.
3. Reject fragments with invalid authentication/integrity.
4. Detect duplicate indexes and conflicting transfer identifiers.
5. Report missing fragments explicitly.
6. Reconstruct only when all required data fragments are available or a formally specified erasure-recovery threshold is met.
7. Verify the complete reconstructed archive length and BLAKE3 digest.
8. Check the NCT magic and supported version.
9. Authenticate/decrypt the reconstructed NCT archive before trusting plaintext.
10. Never write recovered plaintext before successful cryptographic authentication.

The CLI currently supports splitting into NCFR files, embedding fragments into multiple supplied PNG/BMP cover images, inspecting missing indexes, and reassembling from out-of-order NCFR files or carrier images. CLI fragment generation uses a FragmentPlan to encode one fragment at a time rather than retaining a second full set of fragment copies in memory. The source encrypted archive is still currently read into memory; a fully streaming archive-to-fragment pipeline remains future work. The v1 implementation rejects duplicate indexes, mixed transfer IDs, malformed lengths, corrupt fragment digests, missing parts, and a final archive digest mismatch. It does not yet implement parity/recovery shards.

## NCRS recovery shard v1

NCRS is a separate, versioned recovery frame. NCFR v1 remains unchanged. NCRS v1 uses systematic Reed-Solomon coding over GF(2^8): the first k shards contain the archive split into fixed-size blocks (zero-padded at the end), followed by r parity shards. Any k distinct valid shards from the same transfer can reconstruct the original archive, subject to successful final digest verification.

| Offset | Length | Field |
|---:|---:|---|
| 0 | 4 | Magic: ASCII `NCRS` |
| 4 | 2 | Recovery frame version (little-endian, 1) |
| 6 | 16 | Random transfer identifier |
| 22 | 8 | Original archive length |
| 30 | 2 | Data shard count (k) |
| 32 | 2 | Parity shard count (r) |
| 34 | 2 | Zero-based shard index (0..k+r-1) |
| 36 | 4 | Fixed shard payload length |
| 40 | 32 | BLAKE3 digest of original archive |
| 72 | 32 | BLAKE3 digest of this shard payload |
| 104 | variable | Shard payload |

The current implementation uses the `reed-solomon-erasure` crate's GF(2^8) codec. Each transfer is bounded to 255 total shards, 8 MiB per shard, and 1 GiB of source archive data. At least one parity shard is required. The recovery API rejects duplicate indexes, mixed transfer metadata, malformed sizes and corrupt shard digests; it verifies the Reed-Solomon codeword and then verifies the reconstructed archive digest and NCT header.

CLI examples:

```powershell
# Split the archive into data shards plus 2 parity shards
cargo run -p noctyra-cli -- constellation-recovery-split .\\archive.nct .\\recovery-shards 4194304 2

# Recover from any sufficient set; the order does not matter
cargo run -p noctyra-cli -- constellation-recovery .\\recovered.nct .\\recovery-shards\\shard-0000.ncrs .\\recovery-shards\\shard-0002.ncrs .\\recovery-shards\\shard-0003.ncrs
```

To create recovery images, supply at least k+r PNG/BMP covers. All covers must have enough payload capacity for the chosen shard size plus the NCRS header:

```powershell
cargo run -p noctyra-cli -- constellation-recovery-encode .\\archive.nct .\\recovery-carriers 4194304 2 .\\cover1.png .\\cover2.png .\\cover3.png .\\cover4.png .\\cover5.png .\\cover6.png .\\cover7.png .\\cover8.png .\\cover9.png .\\cover10.png
```

Recover from the surviving carriers:

```powershell
cargo run -p noctyra-cli -- constellation-recovery-images .\\recovered.nct .\\recovery-carriers\\recovery-0001.png .\\recovery-carriers\\recovery-0003.png .\\recovery-carriers\\recovery-0004.png .\\recovery-carriers\\recovery-0005.png .\\recovery-carriers\\recovery-0006.png .\\recovery-carriers\\recovery-0007.png .\\recovery-carriers\\recovery-0008.png .\\recovery-carriers\\recovery-0009.png
```

The example above is illustrative: choose the actual number of cover files based on k+r and provide at least k distinct surviving shards for recovery. The recovery CLI checks the threshold before reconstruction.

BLAKE3 checksums and Reed-Solomon parity provide corruption detection and erasure recovery, not sender authentication. An attacker who can replace enough shards may cause denial of service; final archive authentication still depends on NCT AEAD. Redundancy does not make data undetectable or provide confidentiality.


## NCMF signed recovery manifest v1

NCMF v1 is a fixed-length, canonical binary manifest signed with Ed25519. It binds the transfer ID, original archive length, data/parity shard counts, shard size, and archive digest to the signer's public key. The signature input is domain-separated with the ASCII context `NOCTYRA-CONSTELLATION-MANIFEST-V1` followed by a NUL byte and the exact 70-byte manifest body.

| Offset | Length | Field |
|---:|---:|---|
| 0 | 4 | Magic: ASCII `NCMF` |
| 4 | 2 | Manifest version (little-endian, 1) |
| 6 | 16 | Recovery transfer identifier |
| 22 | 8 | Original archive length |
| 30 | 2 | Data shard count |
| 32 | 2 | Parity shard count |
| 34 | 4 | Shard payload size |
| 38 | 32 | Original archive BLAKE3 digest |
| 70 | 32 | Ed25519 signer public key |
| 102 | 64 | Ed25519 signature |

The signature proves possession of the private key corresponding to the embedded public key. It does **not** establish a real-world identity by itself. The recipient must obtain and pin the trusted public key through an independent trusted channel; a public key supplied alongside an untrusted manifest is not sufficient.

The CLI stores raw 32-byte private and public key files. On Unix, private-key files are created with mode 0600. The CLI refuses to overwrite existing key files. Keep private keys offline, encrypted at rest, and backed up securely; do not commit them to Git or send them with the carriers. The current CLI key-file workflow is a minimal local-file implementation, not an OS keychain or hardware-backed keystore.

CLI workflow:

```powershell
# Create an Ed25519 keypair (run once; retain the private key securely)
cargo run -p noctyra-cli -- constellation-keygen .\\noctyra-signing.key .\\noctyra-signing.pub

# Create a complete recovery shard set first
cargo run -p noctyra-cli -- constellation-recovery-split .\\archive.nct .\\recovery-shards 4194304 2

# Sign the exact complete set of shards
cargo run -p noctyra-cli -- constellation-manifest-create .\\recovery-shards\\shard-0000.ncrs .\\recovery-shards\\shard-0001.ncrs .\\recovery-shards\\shard-0002.ncrs .\\recovery-shards\\shard-0003.ncrs .\\recovery-shards\\shard-0004.ncrs .\\recovery-shards\\shard-0005.ncrs .\\recovery-shards\\shard-0006.ncrs .\\recovery-shards\\shard-0007.ncrs .\\recovery-shards\\shard-0008.ncrs .\\recovery-shards\\shard-0009.ncrs .\\noctyra-signing.key .\\transfer.ncmf

# Verify the signer against a separately trusted public key and recover from any k valid shards
cargo run -p noctyra-cli -- constellation-manifest-verify-recovery .\\recovered.nct .\\transfer.ncmf .\\trusted-sender.pub .\\recovery-shards\\shard-0000.ncrs .\\recovery-shards\\shard-0002.ncrs .\\recovery-shards\\shard-0003.ncrs .\\recovery-shards\\shard-0004.ncrs .\\recovery-shards\\shard-0005.ncrs .\\recovery-shards\\shard-0006.ncrs .\\recovery-shards\\shard-0007.ncrs
```

The manifest creation command currently requires the complete set so the signer cannot accidentally sign a partial set. Verification and recovery can use any sufficient set of distinct shards, provided every shard matches the signed metadata. The reconstructed archive must still pass NCT authenticated decryption before plaintext is trusted.

## Carrier format policy
PNG is the primary lossless carrier. BMP may be supported as a secondary format. JPEG and other lossy transformations are not supported for reliable carrier preservation in the initial design.

## Security and privacy
The encrypted NCT payload remains the confidentiality boundary. Image carriers may be statistically analyzed; no undetectability guarantee is made. Do not use carrier encoding to bypass security controls or monitoring. Never include passwords or plaintext secrets in a transport manifest.
