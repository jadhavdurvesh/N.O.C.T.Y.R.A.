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
- [ ] Streaming archive creation and extraction
- [ ] Bounded chunking and authenticated finalization
- [ ] Atomic output and overwrite protection

## M3 — Image laboratory
- [ ] PNG/BMP input validation and metadata policy
- [ ] Capacity estimation
- [ ] Reversible experimental carrier codec
- [ ] Round-trip and distortion measurements
- [ ] Malformed-image fuzzing

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
