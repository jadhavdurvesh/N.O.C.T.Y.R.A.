 <p align="center">
  <img
    src="assets/NOCTYRA%20Futuristic%20Orbital%20Network.png"
    alt="NOCTYRA — Networked Obscured Cryptographic Transfer & Recovery Architecture"
    width="100%"
  />
</p>

# N.O.C.T.Y.R.A.

**Networked Obscured Cryptographic Transfer & Recovery Architecture**

NOCTYRA is a private cross-platform personal information-protection project. It combines authenticated encrypted archives with image-carrier research and a resilient multi-carrier transport format.

> Encryption protects content confidentiality and integrity. Image-carrier techniques are optional and do not guarantee that embedded data is undetectable.

## Project governance
- [Restricted proprietary software license](LICENSE)
- [Master Restricted Software & Information Agreement](docs/MASTER_RESTRICTED_AGREEMENT.md)
- [Access control policy](docs/ACCESS_CONTROL.md)
- [Security assurance framework](docs/SECURITY_ASSURANCE.md)
- [Security policy](docs/SECURITY.md)
- [Threat model](docs/THREAT_MODEL.md)

## Technical documentation
- [Architecture](docs/ARCHITECTURE.md)
- [NCT container format draft](docs/NCT_FORMAT.md)
- [CONSTELLATION protocol draft](docs/CONSTELLATION.md)
- [Image carrier format draft](docs/IMAGE_CARRIER.md)
- [Project identity](docs/PROJECT_IDENTITY.md)
- [Development roadmap](docs/ROADMAP.md)

## Desktop application — primary interface
NOCTYRA now has a multi-workspace Tauri + React desktop application in `apps/desktop`. It provides graphical workflows for file/folder encryption, image concealment and extraction, CONSTELLATION fragment splitting/reassembly, and independent recovery-key operations. Normal operations no longer require typing CLI commands.

Run it from `apps/desktop`:

```powershell
npm install
npm run tauri dev
```

The CLI remains available for scripting and advanced diagnostics. See [desktop instructions](apps/desktop/README.md) for prerequisites, limitations and security notes.

## Directory archives

NOCTYRA now has an initial encrypted directory-tree archive implementation. It preserves nested files and empty directories, rejects symbolic links and special filesystem objects, validates archive paths, and refuses to merge into an existing extraction destination.

CLI:

```powershell
cargo run -p noctyra-cli -- encrypt-dir .\\my-folder .\\folder.nct
cargo run -p noctyra-cli -- decrypt-dir .\\folder.nct .\\restored-folder
```

The desktop interface also has Encrypt folder and Recover folder operations. New directory archives use NCT v2/NMF2 and stream file contents through bounded buffers. Extraction authenticates and stages the complete archive before creating the destination. Legacy NMF1 directory archives remain supported by the compatibility path. This is experimental, has not been independently audited, and should be tested only with disposable copies.

## First usable interface — CLI
From the repository root, run:

```powershell
cargo run -p noctyra-cli -- encrypt .\\input.bin .\\archive.nct
cargo run -p noctyra-cli -- decrypt .\\archive.nct .\\recovered.bin
```

The CLI prompts for passwords without echoing them and writes new outputs through temporary sibling files with no-clobber publication. Single-file encryption now uses NCT v2 streaming records (1 MiB chunks, Zstandard compression, per-chunk XChaCha20-Poly1305 authentication and an authenticated final record). Decryption supports both v1 and v2. New directory-tree operations use the NCT v2 streaming format; legacy NMF1 directory archives remain readable. Interrupted extraction staging can be cleaned explicitly with `cargo run -p noctyra-cli -- cleanup-staging <parent-directory>` after confirming no extraction is active. Do not use it for irreplaceable data until the implementation has been independently reviewed and tested.

## Current implementation
The Rust workspace contains an Argon2id + XChaCha20-Poly1305 engine, the original NCT v1 byte envelope, and an experimental NCT v2 streaming file format. The v2 stream compresses and authenticates bounded chunks independently and requires an authenticated finalization record. The CLI and desktop single-file flows use temporary outputs so incomplete or unauthenticated streams are not published. NMF2 streaming directory serialization and staged extraction are implemented. An experimental PNG/BMP RGB-LSB carrier codec is now implemented, including capacity estimation, NCAR framing, payload integrity checks and CLI embed/extract commands. CONSTELLATION v1 now includes bounded fragment framing, out-of-order reassembly, missing/duplicate/corrupt-part reporting, and CLI workflows for raw fragments and multi-image PNG/BMP carrier sets. CONSTELLATION now supports Ed25519-signed recovery manifests, encrypted sender identity vaults, trusted-sender registries, Reed-Solomon recovery shards, end-to-end send/receive, and per-carrier diagnostics against a trusted manifest. The diagnostic command can isolate invalid and duplicate carriers and report whether the surviving signed shards meet the recovery threshold. These features remain experimental; automated CI verification is required before relying on them.

Early engineering project; not an audited security product. No government, military, or national-security certification is claimed. Do not use as the sole protection for high-value sensitive data.

Never commit passwords, recovery keys, private carrier images, real encrypted personal archives, or other secrets.


## Recovery reliability tools (experimental)

M5 adds signed-carrier diagnostics, authenticated local recovery checkpoints, an independent recovery-key credential mode, bounded-stripe Reed-Solomon reconstruction, and a carrier-capacity planner.

```powershell
# Check available carrier capacity before creating a transfer
cargo run -p noctyra-cli -- constellation-plan <archive-bytes> <shard-bytes> <parity-shards> <cover-image1> [more-covers...]

# Diagnose surviving carriers against a trusted sender manifest
cargo run -p noctyra-cli -- constellation-diagnose <manifest.ncmf> <registry.ncts> <fingerprint> <carrier1.png> [more-carriers...]

# Create and inspect a resumable checkpoint
cargo run -p noctyra-cli -- recovery-checkpoint-init <manifest.ncmf> <registry.ncts> <fingerprint> <checkpoint.ncrp> <checkpoint-key.bin>
cargo run -p noctyra-cli -- recovery-checkpoint-mark <manifest.ncmf> <registry.ncts> <fingerprint> <checkpoint.ncrp> <checkpoint-key.bin> <verified-carrier.png>
cargo run -p noctyra-cli -- recovery-checkpoint-status <manifest.ncmf> <registry.ncts> <fingerprint> <checkpoint.ncrp> <checkpoint-key.bin>

# Create a separate offline recovery credential and use it for NCT files
cargo run -p noctyra-cli -- recovery-keygen <recovery-key.bin>
cargo run -p noctyra-cli -- encrypt-with-recovery-key <input-file> <archive.nct> <recovery-key.bin>
cargo run -p noctyra-cli -- decrypt-with-recovery-key <archive.nct> <output-file> <recovery-key.bin>
```

Checkpoint files are authenticated with a separate local key. They record progress but never replace fresh carrier verification. The recovery-key mode is a separate credential choice; it does not yet add a second unlock slot to an archive already encrypted with a password. The bounded-stripe API reduces reconstruction allocations, but the current CLI still loads carrier frames into memory. See the roadmap and protocol documentation before relying on these experimental workflows.

## End-to-end transfer (experimental)

NOCTYRA can package an encrypted file into a signed multi-carrier recovery set. The sender uses an encrypted identity vault; the recipient must independently trust the sender fingerprint in their encrypted trust registry.

```powershell
cargo run -p noctyra-cli -- constellation-send <input-file> <new-package-directory> <identity.nckv> <shard-bytes> <parity-shards> <cover-image1> [more-images...]
cargo run -p noctyra-cli -- constellation-receive <output-file> <manifest.ncmf> <registry.ncts> <trusted-fingerprint> <carrier1.png> [more-carriers...]
```

Use lossless PNG/BMP images and provide enough cover images for all data and parity shards. Share the archive password separately from the carrier package. These carrier techniques are experimental and do not guarantee steganographic undetectability. See [CONSTELLATION protocol documentation](docs/CONSTELLATION.md) for the complete workflow and limitations.

