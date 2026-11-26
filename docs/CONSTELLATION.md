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
- Support a manifest describing expected parts and integrity commitments.
- Optionally add erasure-code redundancy in a later version.
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

The v1 digests are unkeyed corruption checks, not sender authentication. The transfer identifier is not a secret. The complete NCT archive must still pass its authenticated decryption before plaintext is trusted. A separately authenticated transfer manifest and sender identity are future protocol work.

The future transfer manifest may record the archive identifier, total payload length, fragment sizing, expected fragment set, integrity commitments, and optional recovery parameters. NCFR v1 currently repeats bounded transfer metadata in each fragment and has no separate authenticated manifest. Do not treat unkeyed hashes as proof of origin.

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

The CLI currently supports splitting into NCFR files, embedding fragments into multiple supplied PNG/BMP cover images, and reassembling from out-of-order NCFR files or carrier images. The v1 implementation rejects duplicate indexes, mixed transfer IDs, malformed lengths, corrupt fragment digests, missing parts, and a final archive digest mismatch. It does not yet implement parity/recovery shards.

## Optional redundancy
A later protocol revision may use a well-reviewed Reed-Solomon erasure-coding implementation. Code parameters, shard sizing, maximum recovery count, and interoperability test vectors must be specified. Redundancy improves resilience to missing parts; it does not make data undetectable or provide confidentiality.

## Carrier format policy
PNG is the primary lossless carrier. BMP may be supported as a secondary format. JPEG and other lossy transformations are not supported for reliable carrier preservation in the initial design.

## Security and privacy
The encrypted NCT payload remains the confidentiality boundary. Image carriers may be statistically analyzed; no undetectability guarantee is made. Do not use carrier encoding to bypass security controls or monitoring. Never include passwords or plaintext secrets in a transport manifest.
