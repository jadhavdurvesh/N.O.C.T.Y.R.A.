# CONSTELLATION — Multi-Carrier Transport Protocol

Status: protocol design draft.

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
- Support a manifest describing expected parts and integrity commitments.
- Optionally add erasure-code redundancy in a later version.
- Reassemble the exact encrypted NCT byte stream before decryption.

## Conceptual carrier envelope
Each carrier holds a versioned record with:
- Protocol magic and version.
- Transfer identifier.
- Manifest identifier.
- Fragment index and total data-fragment count.
- Fragment role (data or recovery).
- Bounded fragment length.
- Fragment bytes.
- Integrity value bound to transfer and fragment metadata.

The transfer manifest records the archive identifier, total payload length, fragment sizing, expected fragment set, integrity commitments, and optional recovery parameters. Sensitive manifest fields should be minimized; the manifest itself must be authenticated by a key derived from or associated with the encrypted archive, not trusted merely because the image contains it.

## Reassembly rules
1. Treat every carrier and manifest as untrusted input.
2. Validate magic, version, lengths, and resource bounds before allocation.
3. Reject fragments with invalid authentication/integrity.
4. Detect duplicate indexes and conflicting transfer identifiers.
5. Report missing fragments explicitly.
6. Reconstruct only when all required data fragments are available or a formally specified erasure-recovery threshold is met.
7. Verify the complete reconstructed encrypted archive before attempting decryption.
8. Never write recovered plaintext before successful cryptographic authentication.

## Optional redundancy
A later protocol revision may use a well-reviewed Reed-Solomon erasure-coding implementation. Code parameters, shard sizing, maximum recovery count, and interoperability test vectors must be specified. Redundancy improves resilience to missing parts; it does not make data undetectable or provide confidentiality.

## Carrier format policy
PNG is the primary lossless carrier. BMP may be supported as a secondary format. JPEG and other lossy transformations are not supported for reliable carrier preservation in the initial design.

## Security and privacy
The encrypted NCT payload remains the confidentiality boundary. Image carriers may be statistically analyzed; no undetectability guarantee is made. Do not use carrier encoding to bypass security controls or monitoring. Never include passwords or plaintext secrets in a transport manifest.
