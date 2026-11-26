# NOCTYRA Roadmap

## M0 — Repository foundation
- [x] Private repository foundation
- [x] Workspace skeleton design
- [x] Architecture, threat model, and format drafts
- [x] CONSTELLATION protocol concept

## M1 — Cryptographic core
- [ ] CSPRNG-backed salt and key generation
- [ ] Argon2id key derivation with parameter bounds
- [ ] DEK lifecycle and wrapping
- [ ] XChaCha20-Poly1305 authenticated encryption
- [ ] Wrong-password and tamper tests
- [ ] Secret-handling review

## M2 — NCT container
- [ ] Freeze byte-level format specification
- [ ] Encrypted manifest
- [ ] Bounded chunking and finalization
- [ ] Truncation, reorder, duplicate, and mutation tests

## M3 — Image laboratory
- [ ] PNG/BMP input validation
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
- [ ] React + TypeScript UI
- [ ] Vault, encode, extract, recovery workflows
- [ ] Cross-platform packaging

## M7 — Release readiness
- [ ] Windows, Linux, macOS tests
- [ ] Fuzzing and dependency audit
- [ ] Independent security review
- [ ] Reproducible release process
- [ ] Private v1.0 release

No milestone is complete solely because it compiles.
