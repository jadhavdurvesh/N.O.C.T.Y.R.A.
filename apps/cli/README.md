# NOCTYRA CLI

Initial local file encryption/decryption interface.

## Usage

From repository root:

```powershell
cargo run -p noctyra-cli -- encrypt .\input.bin .\archive.nct
cargo run -p noctyra-cli -- decrypt .\archive.nct .\recovered.bin
```

The program prompts for the password without echoing it. Encryption asks for confirmation. Single-file operations use NCT v2 streaming encryption with 1 MiB independently compressed and authenticated chunks. Decryption supports both NCT v1 and v2. Outputs are written to temporary files and published only after complete authentication, without overwriting existing destinations.

## Directory commands

```powershell
cargo run -p noctyra-cli -- encrypt-dir .\\my-folder .\\folder.nct
cargo run -p noctyra-cli -- decrypt-dir .\\folder.nct .\\restored-folder
```

Directory extraction requires a destination path that does not already exist. New directory archives use NCT v2/NMF2: file contents are streamed, including large files, while preserving nested files and empty directories. Extraction authenticates and stages the complete stream before creating the destination. Symbolic links and special filesystem objects are rejected. The legacy NMF1 directory format remains readable and is buffered.

## Staging recovery

An interrupted extraction may leave a marked private staging directory beside the destination. After confirming no NOCTYRA extraction is currently running in that parent directory, remove marked staging directories older than 24 hours with:

```powershell
cargo run -p noctyra-cli -- cleanup-staging .\\
```

The cleanup command only considers directories carrying the NOCTYRA staging prefix and exact marker file. It does not touch arbitrary folders. Do not run it while an extraction is active.

## Image carrier commands

The experimental carrier codec embeds an already-encrypted NCT archive into PNG or BMP RGB least-significant bits. Alpha is preserved. The NCAR v1 frame contains a payload length and BLAKE3 corruption-detection digest; NCT authentication must still be checked by decrypting the extracted archive.

```powershell
cargo run -p noctyra-cli -- carrier-embed .\\cover.png .\\archive.nct .\\carrier.png
cargo run -p noctyra-cli -- carrier-extract .\\carrier.png .\\extracted.nct
```

The carrier input is limited to 64 MiB, decoded RGBA allocation to 512 MiB, dimensions to 16,384 per side, and payload to 16 MiB. See [NCAR v1 format notes](../../docs/IMAGE_CARRIER.md) for the pixel mapping and frame layout. Lossy image processing can destroy the payload. The codec does not guarantee concealment or resistance to steganalysis.

## CONSTELLATION multi-image transport

Split an encrypted NCT archive into bounded NCFR fragment files:

```powershell
cargo run -p noctyra-cli -- constellation-split .\\archive.nct .\\fragments
```

Or encode the archive into multiple supplied PNG/BMP cover images. The tool estimates the smallest available capacity, selects a safe fragment size, and writes a new output directory:

```powershell
cargo run -p noctyra-cli -- constellation-encode .\\archive.nct .\\carrier-set .\\cover1.png .\\cover2.png .\\cover3.png
```

Inspect a partial set before reassembly; the command reports missing zero-based indexes and rejects duplicate or mixed-transfer fragments:

```powershell
cargo run -p noctyra-cli -- constellation-inspect .\\fragments\\fragment-0000.ncfr .\\fragments\\fragment-0002.ncfr
cargo run -p noctyra-cli -- constellation-inspect-images .\\carrier-set\\carrier-0001.png .\\carrier-set\\carrier-0003.png
```

Reassemble from raw fragment files (order does not matter):

```powershell
cargo run -p noctyra-cli -- constellation-reassemble .\\recovered.nct .\\fragments\\fragment-0002.ncfr .\\fragments\\fragment-0000.ncfr .\\fragments\\fragment-0001.ncfr
```

Or reassemble directly from carrier images:

```powershell
cargo run -p noctyra-cli -- constellation-reassemble-images .\\recovered.nct .\\carrier-set\\carrier-0001.png .\\carrier-set\\carrier-0002.png .\\carrier-set\\carrier-0003.png
```

NCFR v1 uses a random transfer ID, bounded fragment indexes/counts, per-fragment BLAKE3 checksums and a complete archive digest. These hashes detect corruption but do not authenticate the sender. NCT AEAD remains the confidentiality and authenticity boundary. Current limits: 1 GiB archive, 256 fragments, 4 MiB default fragment data, 8 MiB maximum fragment data.

## CONSTELLATION resilient recovery (NCRS)

Create a raw recovery set with a 4 MiB shard size and two parity shards:

```powershell
cargo run -p noctyra-cli -- constellation-recovery-split .\\archive.nct .\\recovery-shards 4194304 2
```

Create a recovery set embedded in PNG/BMP cover images. Supply enough cover images for all data plus parity shards, and ensure each can hold the shard plus its frame header:

```powershell
cargo run -p noctyra-cli -- constellation-recovery-encode .\\archive.nct .\\recovery-carriers 4194304 2 .\\cover1.png .\\cover2.png .\\cover3.png .\\cover4.png .\\cover5.png .\\cover6.png .\\cover7.png .\\cover8.png .\\cover9.png .\\cover10.png
```

Recover from any sufficient set of distinct shards; order does not matter:

```powershell
cargo run -p noctyra-cli -- constellation-recovery-images .\\recovered.nct .\\recovery-carriers\\recovery-0001.png .\\recovery-carriers\\recovery-0003.png .\\recovery-carriers\\recovery-0004.png .\\recovery-carriers\\recovery-0005.png .\\recovery-carriers\\recovery-0006.png .\\recovery-carriers\\recovery-0007.png .\\recovery-carriers\\recovery-0008.png .\\recovery-carriers\\recovery-0009.png
```

NCRS v1 uses systematic Reed-Solomon parity shards. With k data shards and r parity shards, any k distinct shards can recover the archive, so up to r shards may be missing or damaged. Recovery verifies shard checksums, codeword consistency, the final archive digest and the NCT header. These checks do not authenticate a sender; NCT AEAD remains the authenticity boundary.

## Authenticated CONSTELLATION recovery manifests

Generate an Ed25519 signing keypair. The private key is local secret material; the public key must be distributed and pinned independently by recipients:

```powershell
cargo run -p noctyra-cli -- constellation-keygen .\\noctyra-signing.key .\\noctyra-signing.pub
```

Create a complete recovery set, then sign its metadata:

```powershell
cargo run -p noctyra-cli -- constellation-recovery-split .\\archive.nct .\\recovery-shards 4194304 2
cargo run -p noctyra-cli -- constellation-manifest-create .\\recovery-shards\\shard-0000.ncrs .\\recovery-shards\\shard-0001.ncrs .\\recovery-shards\\shard-0002.ncrs .\\recovery-shards\\shard-0003.ncrs .\\recovery-shards\\shard-0004.ncrs .\\recovery-shards\\shard-0005.ncrs .\\recovery-shards\\shard-0006.ncrs .\\recovery-shards\\shard-0007.ncrs .\\recovery-shards\\shard-0008.ncrs .\\recovery-shards\\shard-0009.ncrs .\\noctyra-signing.key .\\transfer.ncmf
```

Verify the manifest against a trusted public key and recover using any sufficient set of valid shards:

```powershell
cargo run -p noctyra-cli -- constellation-manifest-verify-recovery .\\recovered.nct .\\transfer.ncmf .\\trusted-sender.pub .\\recovery-shards\\shard-0000.ncrs .\\recovery-shards\\shard-0002.ncrs .\\recovery-shards\\shard-0003.ncrs .\\recovery-shards\\shard-0004.ncrs .\\recovery-shards\\shard-0005.ncrs .\\recovery-shards\\shard-0006.ncrs .\\recovery-shards\\shard-0007.ncrs
```

Manifest signatures authenticate possession of a signing key, not a person's identity by themselves. Recipients must obtain the trusted public key independently. The private-key file is raw 32-byte material; never commit it to the repository or share it with the carrier set. Unix files are created with mode 0600. Use secure offline storage and backups.

## Current limitations
- Legacy NMF1 directory archives remain buffered; new directory archives use NMF2 streaming.
- No image carriers or CONSTELLATION packet splitting yet.
- No recovery-key mechanism yet.
- Not independently audited; do not rely on it as the sole protection for critical data.
