//! Reversible experimental RGB-LSB carrier codec.
//!
//! This codec is not encryption and does not promise undetectability. Embed
//! already-encrypted NCT archives. Re-encoding as PNG/BMP preserves pixel LSBs;
//! lossy transforms, resizing, filtering and social-media processing do not.
use blake3::Hasher;
use thiserror::Error;
use noctyra_image::{CarrierFormat, CarrierImage, ImageError};

const MAGIC: &[u8; 4] = b"NCAR";
const VERSION: u8 = 1;
const HEADER_LEN: usize = 4 + 1 + 8 + 32;
const HEADER_AND_PAYLOAD_LIMIT: usize = noctyra_validation::MAX_FRAGMENT_BYTES + HEADER_LEN;

#[derive(Debug, Error)]
pub enum CarrierCodecError {
    #[error(transparent)]
    Image(#[from] ImageError),
    #[error("payload exceeds the 16 MiB carrier fragment limit")]
    PayloadTooLarge,
    #[error("carrier has insufficient capacity: needs {required} bytes, has {available}")]
    InsufficientCapacity { required: usize, available: usize },
    #[error("no valid NOCTYRA payload was found in the carrier")]
    NoPayload,
    #[error("carrier payload is malformed or has an unsupported version")]
    Malformed,
    #[error("embedded payload integrity check failed")]
    Integrity,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Capacity {
    pub total_bytes: usize,
    pub payload_bytes: usize,
    pub header_bytes: usize,
}

pub fn estimate_capacity(carrier: &CarrierImage) -> Capacity {
    let total = carrier.rgb_lsb_capacity_bytes();
    Capacity {
        total_bytes: total,
        payload_bytes: total.saturating_sub(HEADER_LEN).min(noctyra_validation::MAX_FRAGMENT_BYTES),
        header_bytes: HEADER_LEN,
    }
}

fn read_byte(raw: &[u8], byte_index: usize) -> Result<u8, CarrierCodecError> {
    let mut value = 0u8;
    for bit in 0..8 {
        let slot = byte_index.checked_mul(8).and_then(|n| n.checked_add(bit))
            .ok_or(CarrierCodecError::Malformed)?;
        let pixel = slot / 3;
        let channel = slot % 3;
        let offset = pixel.checked_mul(4).and_then(|n| n.checked_add(channel))
            .ok_or(CarrierCodecError::Malformed)?;
        let source = *raw.get(offset).ok_or(CarrierCodecError::Malformed)?;
        value |= (source & 1) << bit;
    }
    Ok(value)
}

fn write_bytes(carrier: &mut CarrierImage, bytes: &[u8]) {
    let raw = carrier.rgba_bytes_mut();
    for (byte_index, byte) in bytes.iter().copied().enumerate() {
        for bit in 0..8 {
            let slot = byte_index * 8 + bit;
            let pixel = slot / 3;
            let channel = slot % 3;
            let offset = pixel * 4 + channel;
            raw[offset] = (raw[offset] & 0xFE) | ((byte >> bit) & 1);
        }
    }
}

/// Embed an opaque payload. Callers should pass a complete encrypted NCT archive.
pub fn embed(carrier: &mut CarrierImage, payload: &[u8]) -> Result<(), CarrierCodecError> {
    if payload.len() > noctyra_validation::MAX_FRAGMENT_BYTES { return Err(CarrierCodecError::PayloadTooLarge); }
    let total_len = HEADER_LEN.checked_add(payload.len()).ok_or(CarrierCodecError::PayloadTooLarge)?;
    let available = carrier.rgb_lsb_capacity_bytes();
    if total_len > available {
        return Err(CarrierCodecError::InsufficientCapacity { required: total_len, available });
    }
    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(MAGIC);
    header.push(VERSION);
    header.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    header.extend_from_slice(Hasher::new().update(payload).finalize().as_bytes());
    let mut framed = Vec::with_capacity(total_len);
    framed.extend_from_slice(&header);
    framed.extend_from_slice(payload);
    write_bytes(carrier, &framed);
    Ok(())
}

/// Extract and integrity-check an embedded payload. This does not decrypt NCT.
pub fn extract(carrier: &CarrierImage) -> Result<Vec<u8>, CarrierCodecError> {
    let available = carrier.rgb_lsb_capacity_bytes();
    if available < HEADER_LEN { return Err(CarrierCodecError::NoPayload); }
    let raw = carrier.rgba_bytes();
    let mut header = [0u8; HEADER_LEN];
    for (index, byte) in header.iter_mut().enumerate() { *byte = read_byte(raw, index)?; }
    if &header[..4] != MAGIC { return Err(CarrierCodecError::NoPayload); }
    if header[4] != VERSION { return Err(CarrierCodecError::Malformed); }
    let length = u64::from_le_bytes(header[5..13].try_into().map_err(|_| CarrierCodecError::Malformed)?);
    let length = usize::try_from(length).map_err(|_| CarrierCodecError::Malformed)?;
    if length > noctyra_validation::MAX_FRAGMENT_BYTES { return Err(CarrierCodecError::PayloadTooLarge); }
    let total = HEADER_LEN.checked_add(length).ok_or(CarrierCodecError::Malformed)?;
    if total > available || total > HEADER_AND_PAYLOAD_LIMIT { return Err(CarrierCodecError::Malformed); }
    let mut payload = Vec::with_capacity(length);
    for index in HEADER_LEN..total { payload.push(read_byte(raw, index)?); }
    let digest = Hasher::new().update(&payload).finalize();
    if &digest.as_bytes()[..] != &header[13..45] { return Err(CarrierCodecError::Integrity); }
    Ok(payload)
}

pub fn encode_carrier(carrier: &CarrierImage, format: CarrierFormat) -> Result<Vec<u8>, ImageError> {
    carrier.encode(format)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embed_extract_round_trip_and_preserve_alpha() {
        let mut carrier = CarrierImage::new(128, 128, CarrierFormat::Png).unwrap();
        let before_alpha: Vec<u8> = carrier.rgba_bytes().chunks_exact(4).map(|p| p[3]).collect();
        let payload = b"NCTY encrypted test archive payload";
        embed(&mut carrier, payload).unwrap();
        assert_eq!(extract(&carrier).unwrap(), payload);
        let after_alpha: Vec<u8> = carrier.rgba_bytes().chunks_exact(4).map(|p| p[3]).collect();
        assert_eq!(before_alpha, after_alpha);
    }

    #[test]
    fn rejects_insufficient_capacity_and_oversized_payload() {
        let mut small = CarrierImage::new(4, 4, CarrierFormat::Png).unwrap();
        assert!(matches!(embed(&mut small, b"payload"), Err(CarrierCodecError::InsufficientCapacity { .. })));
        assert!(matches!(embed(&mut small, &vec![0u8; noctyra_validation::MAX_FRAGMENT_BYTES + 1]), Err(CarrierCodecError::PayloadTooLarge)));
    }

    #[test]
    fn payload_survives_png_and_bmp_encoding_round_trip() {
        for format in [CarrierFormat::Png, CarrierFormat::Bmp] {
            let mut carrier = CarrierImage::new(128, 128, format).unwrap();
            let payload = b"encrypted NCT payload round-trip";
            embed(&mut carrier, payload).unwrap();
            let encoded = carrier.encode(format).unwrap();
            let decoded = CarrierImage::load(&encoded).unwrap();
            assert_eq!(extract(&decoded).unwrap(), payload);
        }
    }

    #[test]
    fn detects_payload_corruption() {
        let mut carrier = CarrierImage::new(128, 128, CarrierFormat::Png).unwrap();
        embed(&mut carrier, b"payload").unwrap();
        let slot = HEADER_LEN * 8;
        let offset = (slot / 3) * 4 + (slot % 3);
        carrier.rgba_bytes_mut()[offset] ^= 1;
        assert!(matches!(extract(&carrier), Err(CarrierCodecError::Integrity)));
    }

    #[test]
    fn no_payload_is_reported_cleanly() {
        let carrier = CarrierImage::new(64, 64, CarrierFormat::Png).unwrap();
        assert!(matches!(extract(&carrier), Err(CarrierCodecError::NoPayload)));
    }
}
