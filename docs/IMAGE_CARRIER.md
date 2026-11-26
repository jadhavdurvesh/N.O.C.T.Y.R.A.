# NOCTYRA Image Carrier Format — NCAR v1 (experimental)

Status: experimental internal format. Not frozen for interoperability.

## Scope

NCAR v1 is a reversible framing layer for embedding an opaque payload in PNG or BMP pixels. The intended payload is an already encrypted NCT archive. NCAR does not encrypt, authenticate a sender, or guarantee that the presence of hidden data cannot be detected. The NCT authenticated-encryption layer remains mandatory.

## Accepted image formats

- PNG is the primary carrier.
- BMP is supported as a secondary carrier.
- Input format is selected from the file signature, not the filename extension.
- Lossy formats (including JPEG) are rejected.
- Input compressed file limit: 64 MiB.
- Maximum width and height: 16,384 pixels each.
- Maximum decoded RGBA allocation: 512 MiB.
- Maximum NCAR payload: 16 MiB.

## Pixel mapping

- Pixels are traversed in decoded row-major RGBA byte order.
- Only R, G and B channels are used; alpha is not modified by the embedding codec.
- Each payload bit is stored in the least-significant bit of the next RGB channel.
- Bits are written least-significant-bit first within each byte.
- The encoder changes no more than one bit in each used RGB channel.
- The image is re-encoded as PNG or BMP. Pixel LSBs are preserved by the lossless carrier output path.

## NCAR v1 frame

The framed byte sequence is embedded starting at the first RGB channel:

| Offset | Length | Field |
|---:|---:|---|
| 0 | 4 | Magic: ASCII `NCAR` |
| 4 | 1 | Version: `1` |
| 5 | 8 | Payload length, unsigned little-endian |
| 13 | 32 | BLAKE3 digest of payload |
| 45 | variable | Opaque payload bytes |

The payload length must not exceed 16 MiB or the carrier's available capacity. The digest detects accidental corruption and malformed extraction; it is not keyed and is not a substitute for NCT AEAD authentication. Applications must authenticate/decrypt the extracted NCT archive before trusting its contents.

## Capacity

The raw RGB-LSB capacity is `floor(width * height * 3 / 8)` bytes. NCAR consumes 45 bytes for its header. The usable payload capacity is the remaining capacity, capped at 16 MiB.

## Operational limitations

- Recompression, resizing, filtering, palette conversion, color correction, screenshotting, or social-media processing may destroy embedded bits.
- Metadata may be changed or discarded during image decoding and re-encoding. NCAR v1 does not promise metadata preservation.
- Capacity and payload length are observable. Image statistical analysis may detect LSB modifications.
- This format is for controlled experimentation and personal encrypted payload transport, not covert communications or a security certification.

## Tests and fuzzing

The image crate tests PNG/BMP pixel round trips and input limits. The steganography crate tests payload round trips, alpha preservation in PNG, capacity rejection, and payload corruption detection. The `fuzz/` workspace includes `carrier_image` and `carrier_payload` targets. These tests are not an independent security audit.
