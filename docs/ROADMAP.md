# NOCTYRA Roadmap

## M0 — Repository and governance foundation
- [x] Private repository and project structure
- [x] Architecture and threat-model documents
- [x] Restricted proprietary license and agreement template
- [x] CONSTELLATION protocol design draft

## M1 — Cryptographic and container core
- [x] Argon2id password-based key derivation baseline
- [x] XChaCha20-Poly1305 authenticated encryption baseline
- [x] NCT v1 binary envelope draft implementation
- [x] Wrong-password and tamper test cases
- [ ] Run and verify workspace tests in CI
- [ ] Independent review of crypto API and memory handling
- [ ] Define password policy and KDF profile migration
- [ ] Add streaming support and key-envelope/recovery-key design

## M2 — File archive system
- [x] Initial encrypted multi-file directory tree format
- [x] Safe destination creation and no-merge extraction policy
- [x] Reject symlinks, special files, traversal paths and platform device names
- [x] Wrong-password and directory round-trip test cases
- [ ] Independent cross-platform archive review
- [x] NCT v2 streaming single-file encryption and decryption API
- [x] Independent Zstandard-compressed 1 MiB chunks
- [x] Per-chunk AEAD with sequential nonce derivation
- [x] Authenticated finalization record with total length and BLAKE3 digest
- [x] CLI and desktop temporary-output publication for single-file operations
- [x] NMF2 streaming directory serialization over NCT v2
- [x] Authenticated staging and manifest validation before extraction
- [x] Bounded-memory file extraction and path/entry/resource limits
- [x] Detect source file size and modification-time changes before and after streaming
- [x] Private sibling staging directory for authenticated directory extraction
- [x] Flush extracted files and directories where supported before publication
- [x] Marked stale-staging recovery API and explicit CLI command
- [x] NMF2 manifest fuzz target and malformed-manifest regression tests
- [ ] Filesystem snapshot / no-follow handle-based source traversal
- [ ] Atomic no-replace directory publication across Windows, Linux and macOS
- [ ] Cross-platform crash-injection and power-loss testing

## M3 — Image laboratory
- [x] Bounded PNG/BMP loading with signature checks and dimension/allocation limits
- [x] RGB-LSB carrier capacity estimation
- [x] Versioned NCAR v1 payload frame with length and BLAKE3 corruption check
- [x] Reversible RGB-LSB embed/extract codec; alpha channel remains unchanged
- [x] PNG/BMP round-trip and payload corruption tests
- [x] CLI carrier-embed and carrier-extract commands
- [x] Fuzz targets for image decoding and embedded payload extraction
- [ ] Distortion measurements and carrier quality report
- [ ] Metadata policy and explicit metadata-preservation decisions
- [ ] Independent image codec review and sustained fuzz campaigns

## M4 — CONSTELLATION
- [x] NCFR v1 bounded fragment envelope with random transfer identifier
- [x] Fragment and complete-archive BLAKE3 corruption checks
- [x] Fragment splitting with configurable 4 MiB default / 8 MiB maximum
- [x] Out-of-order reassembly with final archive digest and NCT header checks
- [x] Missing, duplicate, mixed-transfer and corrupt-fragment reporting
- [x] CLI raw fragment split and reassembly
- [x] CLI multi-image PNG/BMP encode and image reassembly
- [x] Fragment parser fuzz target and inspection fuzz target
- [x] NCMF v1 canonical Ed25519-signed recovery manifest
- [x] Trusted-public-key pinning and signature verification
- [x] Signed metadata binding to recovery shards
- [x] CLI key generation, manifest creation and authenticated recovery
- [x] Manifest parser fuzz target
- [x] NCRS v1 systematic Reed-Solomon parity shard framing
- [x] Recovery from any k of k+r valid shards
- [x] Duplicate, mixed-transfer, malformed and corrupt shard rejection
- [x] Recovery CLI for raw shards and multi-image carrier sets
- [x] Recovery shard parser fuzz target
- [x] NCKV v1 password-encrypted Ed25519 signing-key vault
- [x] NCRT v1 old-key-signed rotation certificates
- [x] NCTS v1 password-encrypted trusted-sender registry
- [x] Explicit fingerprint confirmation when adding a trusted key
- [x] Local key revocation and trust-aware manifest recovery
- [ ] OS keychain / hardware-backed signing-key storage
- [ ] Windows ACL hardening and platform secure-storage integration
- [ ] Registry anti-rollback and externally distributed revocation policy
- [ ] End-to-end recovery image integration tests and carrier capacity benchmarks
- [ ] End-to-end multi-image integration tests and carrier capacity benchmarks

## M5 — Recovery intelligence and reliability
- [x] Verify individual NCRS shards against an already trusted, signature-verified manifest
- [x] Diagnose valid, damaged, duplicate and foreign carrier images independently
- [x] Report valid unique shard count, recovery threshold and missing indexes
- [x] Keep diagnostics read-only; never alter source carriers or trust records
- [x] Preserve no-clobber temporary-output publication and NCT authentication before plaintext release
- [x] Add per-shard verification regression coverage
- [x] Add authenticated local progress checkpoints bound to exact signed-manifest bytes
- [x] Verify each carrier against the trusted manifest before marking its shard index
- [x] Add checkpoint status and missing-index reporting; revalidate all carriers on resume
- [x] Add independent 256-bit recovery-key credential generation and NCT encrypt/decrypt mode
- [ ] Add dual password/recovery-key wrapping of one random archive data-encryption key in a versioned NCT envelope
- [x] Add 64 KiB stripe-based Reed-Solomon reconstruction to a temporary seekable output without allocating a second full codeword/archive
- [ ] Stream carrier reads into authenticated scratch storage instead of loading all carrier frames into memory
- [ ] Add scratch-space quotas, truncation and crash cleanup guarantees
- [x] Add per-carrier diagnostics and a carrier-capacity/recovery-set planning report
- [ ] Add crash-injection, disk-full and interrupted-write recovery tests
- [ ] Add cross-platform filesystem publication and permission tests
- [ ] Run full workspace CI and resolve all failures
- [ ] Independent security review of recovery and trust-state handling

## M6 — Desktop
- [ ] Tauri 2 shell
- [ ] React + TypeScript interface
- [ ] Vault, encrypt, decrypt, encode, extract and recovery workflows
- [ ] Cross-platform packaging

## M7 — Release readiness
- [ ] Windows, Linux and macOS tests
- [ ] Fuzzing and dependency audit
- [ ] Independent security review
- [ ] Reproducible release process
- [ ] Private v1.0 release

No milestone is complete solely because it compiles. No security assurance level is claimed until its evidence requirements are met.
