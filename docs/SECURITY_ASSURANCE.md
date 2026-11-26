# NOCTYRA Security Assurance Framework

Status: internal engineering requirements. This framework is not a certification,
government classification, military approval, or claim of suitability for
national-security deployment.

## Assurance levels

### N0 — Experimental
- Prototype code and draft formats.
- No use for sensitive or high-value data.
- Security behavior may change.

### N1 — Engineering baseline
- Threat model and security requirements reviewed.
- Authenticated encryption and password KDF use vetted libraries.
- Input limits and error handling implemented.
- Unit and integration tests cover wrong credentials and modified data.
- Dependency lockfile and dependency inventory committed.

### N2 — Hardened candidate
- Fuzzing for archive, image, manifest, and transport parsers.
- Property tests and negative tests.
- Secret and plaintext handling reviewed.
- Reproducible build process documented.
- Release artifacts signed and their hashes published privately.
- No unresolved critical or high-severity security findings.

### N3 — Independently assessed
- Independent cryptographic design review.
- Independent source-code audit and penetration test.
- Remediation evidence for all material findings.
- Cross-platform build and recovery testing.
- Supply-chain controls and incident-response procedure verified.
- Documented residual-risk acceptance by the project owner.

### N4 — Regulated or government deployment assessment
This is not a project-issued level or self-declared certification. Any deployment
in a regulated, defense, intelligence, or national-security environment requires
the relevant organization to select applicable standards, validate the complete
system and operating environment, complete procurement and legal reviews, and
grant its own authorization. NOCTYRA must not claim such approval without
documented authorization from the competent authority.

## Mandatory engineering controls

### Cryptography
- Use vetted implementations; do not invent ciphers, KDFs, or signature schemes.
- Use an OS-backed cryptographic random generator.
- Define nonce uniqueness for every key and every chunk.
- Authenticate format metadata, archive identity, and chunk ordering.
- Bound KDF parameters before running expensive work on untrusted input.
- Do not release plaintext until the required authentication checks pass.

### Application and data handling
- Parse all external input as hostile.
- Apply size, count, dimension, nesting, and decompression limits.
- Avoid logging passwords, keys, plaintext filenames, and content.
- Do not silently overwrite or delete user files.
- Use restrictive file permissions for secrets and temporary data.
- Document the limits of zeroization and operating-system memory protection.

### Software supply chain
- Commit Cargo.lock for application builds.
- Review dependency updates and license obligations.
- Generate a software bill of materials for release candidates.
- Pin CI actions and build dependencies where practical.
- Protect release signing keys separately from developer workstations.
- Produce reproducible or verifiable release builds.

### Repository and release controls
- Require multi-factor authentication on the source-control account.
- Use least-privilege collaborator access.
- Protect the main branch and require review for security-sensitive changes.
- Require tests and static checks before merge.
- Sign release tags and verify signatures during release.
- Keep secrets, test credentials, recovery keys, and personal archives out of Git.

## Release gate
A version must not be described as production-secure until its scope is documented,
tests pass on supported platforms, security review is complete, findings are
remediated or explicitly accepted, and recovery procedures are exercised.

A successful build, private repository, or use of a strong cipher does not alone
establish system security.
