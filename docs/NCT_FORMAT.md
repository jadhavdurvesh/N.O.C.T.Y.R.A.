# NCT Container Format — Draft v1 and v2

Status: experimental implementation; neither version is frozen for interoperability. Extension: `.nct`. All integers are little-endian.

## Version 1 — single-record archive

| Offset | Length | Field |
|---:|---:|---|
| 0 | 4 | Magic: ASCII `NCTY` |
| 4 | 2 | Version: `1` |
| 6 | 16 | Argon2id salt |
| 22 | 24 | XChaCha20-Poly1305 nonce |
| 46 | 8 | Ciphertext length, including 16-byte tag |
| 54 | variable | Ciphertext and authentication tag |

The v1 parser requires exact file length, rejects truncation, trailing bytes, unknown versions and oversized payloads. The associated data is `NCTY || version_u16_le || ciphertext_length_u64_le`.

## Version 2 — streaming file archive

The v2 format is designed for bounded-memory file encryption. It is distinct from v1 and is selected by the version field.

### Fixed header (43 bytes)

| Offset | Length | Field |
|---:|---:|---|
| 0 | 4 | Magic: ASCII `NCTY` |
| 4 | 2 | Version: `2` |
| 6 | 16 | Argon2id salt |
| 22 | 16 | Random nonce prefix |
| 38 | 4 | Plaintext chunk size; currently exactly 1,048,576 |
| 42 | 1 | Compression profile; `1` = independent Zstandard frames |

The entire fixed header is authenticated as associated data for every record.

### Chunk record

Each chunk record is:

| Length | Field |
|---:|---|
| 4 | Marker: ASCII `CHNK` |
| 8 | Zero-based chunk index |
| 4 | Uncompressed length (1 to 1,048,576) |
| 4 | Compressed length |
| variable | XChaCha20-Poly1305 ciphertext of one Zstandard frame, followed by its 16-byte tag |

The record associated data is `fixed_header || record_header`. The 24-byte XChaCha nonce is `random_prefix_16 || chunk_index_u64_le`. The Argon2id-derived key is computed once per archive, not once per chunk. Chunk indices must be strictly sequential. Compressed lengths and decompressed output sizes are bounded before allocation/decompression.

### Finalization record

A valid archive MUST end with exactly one finalization record:

| Length | Field |
|---:|---|
| 4 | Marker: ASCII `FINL` |
| 64 | AEAD ciphertext and tag |

The encrypted 48-byte finalization payload is:

- 8-byte chunk count
- 8-byte total uncompressed byte count
- 32-byte BLAKE3 digest of the complete uncompressed byte stream

The final record uses nonce index equal to the declared chunk count and associated data `fixed_header || FINL`. The reader verifies the final record, count, byte total, digest and physical EOF. Missing finalization, reordering, truncation, corruption and trailing bytes are rejected.

### Compression and resource bounds

- One independent Zstandard frame per chunk, compression level 3.
- Plaintext memory is bounded to one 1 MiB chunk plus compression/decompression buffers and I/O buffers.
- Compressed chunk length is bounded to 1 MiB + 1/8 MiB + 1,024 bytes.
- Exact plaintext file size is not hidden; record lengths reveal approximate chunk sizes.
- Compression is performed before encryption. No compression is attempted on ciphertext.

### Important decryption rule

The streaming API writes authenticated chunks to the supplied writer before it has read and authenticated the finalization record. Therefore callers MUST write to a temporary file in the destination filesystem, and publish it atomically only after the stream function returns success. On any error, the temporary output MUST be discarded. The CLI and desktop file workflows use temporary sibling files and no-clobber publication.

## Cryptographic profile

- KDF: Argon2id, version 1.3.
- Memory: 65,536 KiB.
- Iterations: 3.
- Parallelism: 1 lane.
- Derived key: 32 bytes.
- AEAD: XChaCha20-Poly1305.
- Salt and nonce prefix: OS-backed randomness.

KDF parameters are currently compiled into the crypto crate. A future format revision must encode a bounded profile identifier and reject unsafe parameters before running the KDF.

## Compatibility

- CLI and desktop file decryption support v1 and v2.
- New single-file encryption writes v2.
- New directory encryption writes NCT v2 with an NMF2 plaintext stream: a bounded manifest followed by file bytes in sorted path order. Directory file data is streamed; the full tree is not buffered.
- Directory extraction first authenticates the complete NCT v2 stream into an anonymous temporary file, validates all manifest paths and offsets, and only then creates the destination tree. It copies file contents in bounded chunks.
- The older NMF1 directory archive remains available through the legacy API and is still buffered; CLI and desktop readers retain v1 directory compatibility.
- No promise of stable external interoperability is made for these draft formats.

## Security status

This is engineering code, not an independently audited cryptographic product. The format requires review, cross-platform testing, fuzzing, test vectors and dependency review before being trusted with irreplaceable data. No security certification or military/government assurance is claimed.


## NMF2 directory payload (inside NCT v2 encryption)

The NCT v2 authenticated plaintext for a directory archive is a sequential NMF2 stream:

| Length | Field |
|---:|---|
| 4 | Magic: ASCII `NMF2` |
| 4 | Entry count (u32 little-endian) |
| repeated | Entry header and, for files, the file bytes |

Each entry header is:

| Length | Field |
|---:|---|
| 1 | Kind: `0` directory, `1` regular file |
| 4 | UTF-8 relative path length (u32 little-endian) |
| 8 | File byte length (u64 little-endian; zero for directories) |
| variable | Relative path bytes, using `/` separators |

For file entries, exactly `file_length` raw bytes follow the path immediately. Entries are sorted lexicographically by relative path. Empty directories are explicit entries; empty files have a zero file length.

### Directory resource and path rules

- At most 100,000 entries.
- At most 4,096 UTF-8 bytes per path and 64 MiB of path bytes total.
- Total uncompressed file bytes are limited to 1 TiB by the current implementation.
- Only regular files and directories are accepted. Symlinks and special filesystem objects are rejected.
- Paths are relative, UTF-8, traversal-free, and reject platform-reserved device names and invalid separators.
- Duplicate case-folded paths and children under a file entry are rejected.
- Extraction authenticates the complete NCT stream to an anonymous temporary file before creating the destination. Manifest validation precedes destination creation; failed extraction removes the partial destination.
- The source directory is enumerated before streaming. File type, size and modification time are checked when each file is opened and again after it is read. This detects many concurrent changes but is not a filesystem snapshot and cannot defeat every same-size/same-timestamp race.
- Extraction occurs in a private sibling staging directory. File contents and directories are synced where supported, then the payload directory is renamed into place on the same filesystem. The staging marker remains outside the published payload so an interrupted operation can leave a recognizable recovery directory.
- `cleanup_stale_staging(parent)` removes only NOCTYRA-marked staging directories older than 24 hours. Run it only when no NOCTYRA extraction is active in that parent. It does not inspect or delete ordinary user directories.
- Directory publication uses a preflight destination check followed by a same-filesystem rename. The portable standard-library implementation does not provide a universal atomic no-replace directory rename, so a hostile concurrent process racing to create an empty destination remains a platform-specific hardening item.

The NMF2 payload is protected by the NCT v2 chunk authentication and finalization record. It is not a standalone format and must not be processed without the enclosing NCT v2 authenticated stream.
