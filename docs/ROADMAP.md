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
- [ ] Carrier fragment envelope
- [ ] Authenticated transfer manifest
- [ ] Fragment validation and reassembly
- [ ] Missing/duplicate/corrupt part reporting
- [ ] Optional erasure-code design and test vectors

## M5 — Recovery
- [ ] Recovery-key workflow
- [ ] Recovery from valid carrier sets
- [ ] Safe destination handling
- [ ] Failure and corruption reporting

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
