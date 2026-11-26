# N.O.C.T.Y.R.A.

**Neural Obfuscation & Cryptographic Transmission Yielding Resilient Archives**

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
- [Project identity](docs/PROJECT_IDENTITY.md)
- [Development roadmap](docs/ROADMAP.md)

## First usable interface — CLI
From the repository root, run:

```powershell
cargo run -p noctyra-cli -- encrypt .\\input.bin .\\archive.nct
cargo run -p noctyra-cli -- decrypt .\\archive.nct .\\recovered.bin
```

The CLI prompts for passwords without echoing them and refuses to overwrite an existing output file. It currently reads one file into memory and is limited to 1 GiB. Do not use it for irreplaceable data until the implementation has been independently reviewed and tested.

## Current implementation
The Rust workspace now contains an initial Argon2id + XChaCha20-Poly1305 encryption engine and an NCT v1 byte-envelope implementation with wrong-password, tamper, truncation, and trailing-data test cases. The format is still a draft and automated verification has not yet passed. File-tree archives, image carriers, CONSTELLATION reassembly, and the desktop interface remain under development.

Early engineering project; not an audited security product. No government, military, or national-security certification is claimed. Do not use as the sole protection for high-value sensitive data.

Never commit passwords, recovery keys, private carrier images, real encrypted personal archives, or other secrets.
