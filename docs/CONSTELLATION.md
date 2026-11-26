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

NCMF v1 is a canonical binary manifest with a length determined by the shard count, signed with Ed25519. It binds the transfer ID, original archive length, data/parity shard counts, shard size, archive digest, and each individual shard payload digest to the signer's public key. The signature input is domain-separated with the ASCII context `NOCTYRA-CONSTELLATION-MANIFEST-V1` followed by a NUL byte and the exact manifest body (70-byte fixed header followed by 32 bytes per shard).

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
| 70 | 32 × (k+r) | BLAKE3 digests of each shard payload, ordered by shard index |
| 70 + 32×(k+r) | 32 | Ed25519 signer public key |
| 102 + 32×(k+r) | 64 | Ed25519 signature |

The signature proves possession of the private key corresponding to the embedded public key and binds the exact expected digest of every data and parity shard. It does **not** establish a real-world identity by itself. The recipient must obtain and pin the trusted public key through an independent trusted channel; a public key supplied alongside an untrusted manifest is not sufficient.

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


## Signing identity and trusted-sender registry

NCKV v1 is the encrypted local signing identity vault. It encrypts the Ed25519 seed using the project's Argon2id + XChaCha20-Poly1305 baseline. The public key and vault header are authenticated. The public key can be inspected or exported without unlocking the private key.

NCRT v1 is a key-continuity certificate signed by the old Ed25519 key. Recipients verify it against their independently pinned old public key. It does not establish a person's identity or automatically trust the successor.

NCTS v1 is a password-encrypted local trust registry containing sender public keys, operator labels, and revocation state. Trust addition requires the operator to confirm the full BLAKE3 fingerprint. Revoked keys remain recorded and cannot be returned by the trust lookup API. Registry writes use fresh salt and nonce values and are atomically replaced by the CLI. There is no global revocation feed or anti-rollback counter; restoring an old registry backup can restore an earlier trust state.

CLI examples:

```powershell
cargo run -p noctyra-cli -- vault-create .\\sender.nckv
cargo run -p noctyra-cli -- vault-inspect .\\sender.nckv
cargo run -p noctyra-cli -- vault-export-public .\\sender.nckv .\\sender.pub
cargo run -p noctyra-cli -- trust-init .\\trusted-senders.ncts
cargo run -p noctyra-cli -- trust-add .\\trusted-senders.ncts .\\sender.pub "Project sender" <expected-fingerprint>
cargo run -p noctyra-cli -- trust-list .\\trusted-senders.ncts
cargo run -p noctyra-cli -- trust-check .\\trusted-senders.ncts <fingerprint>
cargo run -p noctyra-cli -- trust-revoke .\\trusted-senders.ncts <fingerprint>
cargo run -p noctyra-cli -- vault-rotate .\\sender.nckv .\\sender-next.nckv .\\rotation.ncrt
cargo run -p noctyra-cli -- verify-rotation .\\rotation.ncrt .\\sender.pub
cargo run -p noctyra-cli -- vault-export-public .\\sender-next.nckv .\\sender-next.pub
cargo run -p noctyra-cli -- trust-rotate .\\trusted-senders.ncts <old-fingerprint> .\\rotation.ncrt .\\sender-next.pub "Project sender" <new-fingerprint>
```

For trusted-manifest recovery, use `constellation-manifest-verify-trusted-recovery` with the encrypted registry and sender fingerprint. The registry password is requested interactively and is never accepted as a command-line argument. These password-encrypted local files are not yet backed by OS keychain or hardware security.


## End-to-end send and receive workflow

The CLI now exposes `constellation-send` and `constellation-receive`. The sender encrypts the input file into a temporary NCT archive, creates systematic Reed-Solomon recovery shards, signs the complete shard manifest using an unlocked NCKV identity, embeds each shard into a supplied PNG/BMP cover, and atomically publishes a new package directory. The package contains `manifest.ncmf` and `carrier-0001.png` (or BMP) files. It does not contain the archive password or private signing key.

The recipient unlocks their local NCTS registry, resolves the sender fingerprint to a non-revoked trusted public key, verifies the manifest signature, extracts carrier payloads, checks each shard against the signed manifest, reconstructs the encrypted NCT archive when at least k valid shards are present, and decrypts into a temporary output. The destination is published only after NCT authentication succeeds. The recipient needs the archive password through a separate channel.

Example (PowerShell):

```powershell
# Sender: package a file using a 4 MiB shard size and 2 parity shards.
# Supply at least k+r suitable lossless PNG/BMP covers.
cargo run -p noctyra-cli -- constellation-send .\\report.pdf .\\report-transfer .\\sender.nckv 4194304 2 .\\cover1.png .\\cover2.png .\\cover3.png .\\cover4.png .\\cover5.png .\\cover6.png .\\cover7.png .\\cover8.png .\\cover9.png .\\cover10.png

# Transfer the package directory and manifest to the recipient.
# Share the archive password separately from the package.

# Recipient: verify against a locally trusted sender fingerprint and recover.
cargo run -p noctyra-cli -- constellation-receive .\\received-report.pdf .\\report-transfer\\manifest.ncmf .\\trusted-senders.ncts <sender-fingerprint> .\\report-transfer\\carrier-0001.png .\\report-transfer\\carrier-0002.png .\\report-transfer\\carrier-0004.png .\\report-transfer\\carrier-0005.png .\\report-transfer\\carrier-0006.png .\\report-transfer\\carrier-0007.png .\\report-transfer\\carrier-0008.png .\\report-transfer\\carrier-0009.png
```

The example paths and carrier count are illustrative: use the actual generated carrier set and provide at least k distinct valid shards. Any supplied carrier can be lost, but recovery requires at least k valid shards. A manifest and its carrier set are authenticated to the pinned sender identity; they do not encrypt the transport package themselves. The NCT archive provides confidentiality and integrity. Password sharing is deliberately out-of-band. PNG/BMP carriers are experimental steganographic containers, not guaranteed to be undetectable; image resizing, recompression, filters or lossy conversion can destroy embedded data.

## Carrier format policy
PNG is the primary lossless carrier. BMP may be supported as a secondary format. JPEG and other lossy transformations are not supported for reliable carrier preservation in the initial design.

## Security and privacy
The encrypted NCT payload remains the confidentiality boundary. Image carriers may be statistically analyzed; no undetectability guarantee is made. Do not use carrier encoding to bypass security controls or monitoring. Never include passwords or plaintext secrets in a transport manifest.


## M5 authenticated checkpoints and independent recovery credentials

### Resumable local checkpoints

The CLI provides `recovery-checkpoint-init`, `recovery-checkpoint-mark`, and `recovery-checkpoint-status`. The checkpoint is bound to the exact signed NCMF bytes and transfer identifier. Its bitmap is authenticated with a separate random 256-bit local key using keyed BLAKE3. The checkpoint key is stored separately with restrictive Unix file permissions; protect it as a secret and do not include it in a carrier package or commit it to source control.

A shard is marked only after the CLI verifies the NCMF signature using a locally trusted, non-revoked sender key, extracts the image payload, and verifies that shard's metadata and digest against the signed manifest. The checkpoint stores no carrier data. On resume, every carrier must be re-read and re-verified; checkpoint bits are progress hints, not proof that files still exist or remain valid. Replacing the manifest, changing the trust registry, losing the checkpoint key, or restoring an old checkpoint requires operator review. The checkpoint has no anti-rollback protection.

```powershell
# Initialize once for a trusted signed manifest
cargo run -p noctyra-cli -- recovery-checkpoint-init .\\manifest.ncmf .\\trusted-senders.ncts <fingerprint> .\\transfer.ncrp .\\transfer-checkpoint.key

# After receiving a carrier, verify and record its shard index
cargo run -p noctyra-cli -- recovery-checkpoint-mark .\\manifest.ncmf .\\trusted-senders.ncts <fingerprint> .\\transfer.ncrp .\\transfer-checkpoint.key .\\carrier-0001.png

# Inspect the recorded progress before continuing
cargo run -p noctyra-cli -- recovery-checkpoint-status .\\manifest.ncmf .\\trusted-senders.ncts <fingerprint> .\\transfer.ncrp .\\transfer-checkpoint.key
```

### Independent recovery-key credential

`recovery-keygen` creates a random 256-bit secret in a new local key file. `encrypt-with-recovery-key` and `decrypt-with-recovery-key` use those 32 bytes as the password input to the existing NCT authenticated-encryption pipeline. This is a separate credential mode from sender signing identities and trust registries. Anyone who obtains the key file can decrypt archives encrypted with it; keep offline backups and never send the key in the same package as the archive.

This first version is a standalone recovery-key encryption mode. It does not retrofit a second key slot into an archive already encrypted with a human password, does not wrap an existing data-encryption key, and does not provide two independent ways to unlock the same archive. A future NCT envelope revision should introduce a random data-encryption key with separately authenticated password and recovery-key wraps, plus explicit format-version migration and key-rotation tests.

```powershell
cargo run -p noctyra-cli -- recovery-keygen .\\offline-recovery.key
cargo run -p noctyra-cli -- encrypt-with-recovery-key .\\important-file.pdf .\\important-file.nct .\\offline-recovery.key
cargo run -p noctyra-cli -- decrypt-with-recovery-key .\\important-file.nct .\\restored-file.pdf .\\offline-recovery.key
```

### Streaming reconstruction status

The current Reed-Solomon implementation reconstructs a complete codeword in memory. The CLI keeps its output unpublished until the recovered encrypted archive passes final digest and NCT header checks, and plaintext decryption remains a separate authenticated operation. True bounded-memory shard reconstruction is not yet implemented: it requires a disk-backed or streaming erasure-code design, authenticated temporary shard storage, bounded scratch-space accounting, and crash cleanup tests. Do not describe the current reconstruction as streaming.

