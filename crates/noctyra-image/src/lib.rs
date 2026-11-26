//! Bounded PNG/BMP carrier image loading and saving.
use std::io::{Cursor, Read};

use image::{DynamicImage, ImageFormat, ImageReader, Limits, RgbaImage};
use thiserror::Error;

pub const MAX_CARRIER_FILE_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_DECODED_IMAGE_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CarrierFormat { Png, Bmp }

impl CarrierFormat {
    pub fn image_format(self) -> ImageFormat {
        match self { Self::Png => ImageFormat::Png, Self::Bmp => ImageFormat::Bmp }
    }

    pub fn extension(self) -> &'static str {
        match self { Self::Png => "png", Self::Bmp => "bmp" }
    }

    fn from_signature(bytes: &[u8]) -> Result<Self, ImageError> {
        if bytes.starts_with(b"\x89PNG\r\n\x1a\n") { Ok(Self::Png) }
        else if bytes.starts_with(b"BM") { Ok(Self::Bmp) }
        else { Err(ImageError::UnsupportedFormat) }
    }
}

#[derive(Debug, Error)]
pub enum ImageError {
    #[error("unsupported carrier format; only PNG and BMP are accepted")]
    UnsupportedFormat,
    #[error("carrier image exceeds the configured input size limit")]
    InputTooLarge,
    #[error("carrier image dimensions exceed the configured limit")]
    DimensionsTooLarge,
    #[error("carrier image could not be decoded: {0}")]
    Decode(String),
    #[error("carrier image could not be encoded: {0}")]
    Encode(String),
    #[error("carrier image has insufficient pixel capacity")]
    InsufficientCapacity,
}

pub struct CarrierImage {
    format: CarrierFormat,
    pixels: RgbaImage,
}

impl CarrierImage {
    pub fn load(bytes: &[u8]) -> Result<Self, ImageError> {
        if bytes.len() > MAX_CARRIER_FILE_BYTES { return Err(ImageError::InputTooLarge); }
        let format = CarrierFormat::from_signature(bytes)?;
        let mut limits = Limits::default();
        limits.max_image_width = Some(noctyra_validation::MAX_IMAGE_DIMENSION);
        limits.max_image_height = Some(noctyra_validation::MAX_IMAGE_DIMENSION);
        limits.max_alloc = Some(MAX_DECODED_IMAGE_BYTES);
        let mut reader = ImageReader::with_format(Cursor::new(bytes), format.image_format());
        reader.limits(limits);
        let decoded = reader.decode().map_err(|e| ImageError::Decode(e.to_string()))?;
        let (width, height) = (decoded.width(), decoded.height());
        if width == 0 || height == 0
            || width > noctyra_validation::MAX_IMAGE_DIMENSION
            || height > noctyra_validation::MAX_IMAGE_DIMENSION {
            return Err(ImageError::DimensionsTooLarge);
        }
        Ok(Self { format, pixels: decoded.to_rgba8() })
    }

    pub fn new(width: u32, height: u32, format: CarrierFormat) -> Result<Self, ImageError> {
        if width == 0 || height == 0
            || width > noctyra_validation::MAX_IMAGE_DIMENSION
            || height > noctyra_validation::MAX_IMAGE_DIMENSION {
            return Err(ImageError::DimensionsTooLarge);
        }
        let bytes = u64::from(width).checked_mul(u64::from(height))
            .and_then(|pixels| pixels.checked_mul(4))
            .ok_or(ImageError::DimensionsTooLarge)?;
        if bytes > MAX_DECODED_IMAGE_BYTES { return Err(ImageError::DimensionsTooLarge); }
        Ok(Self { format, pixels: RgbaImage::new(width, height) })
    }

    pub fn width(&self) -> u32 { self.pixels.width() }
    pub fn height(&self) -> u32 { self.pixels.height() }
    pub fn format(&self) -> CarrierFormat { self.format }

    /// Number of bytes available to a codec using one bit in each RGB channel.
    pub fn rgb_lsb_capacity_bytes(&self) -> usize {
        (self.pixels.as_raw().len() / 4).saturating_mul(3) / 8
    }

    /// Raw RGBA pixels. Alpha bytes must not be modified by carrier codecs.
    pub fn rgba_bytes(&self) -> &[u8] { self.pixels.as_raw() }

    /// Mutable RGBA pixels. Carrier codecs should modify RGB LSBs only.
    pub fn rgba_bytes_mut(&mut self) -> &mut [u8] { self.pixels.as_mut() }

    pub fn encode(&self, format: CarrierFormat) -> Result<Vec<u8>, ImageError> {
        let image = DynamicImage::ImageRgba8(self.pixels.clone());
        let mut output = Cursor::new(Vec::new());
        image.write_to(&mut output, format.image_format())
            .map_err(|e| ImageError::Encode(e.to_string()))?;
        Ok(output.into_inner())
    }
}

/// Read at most the configured compressed-file limit from a stream.
pub fn read_bounded<R: Read>(mut reader: R) -> Result<Vec<u8>, ImageError> {
    let mut bytes = Vec::new();
    reader.by_ref().take((MAX_CARRIER_FILE_BYTES + 1) as u64)
        .read_to_end(&mut bytes).map_err(|e| ImageError::Decode(e.to_string()))?;
    if bytes.len() > MAX_CARRIER_FILE_BYTES { return Err(ImageError::InputTooLarge); }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn png_and_bmp_round_trip_preserve_pixels() {
        for format in [CarrierFormat::Png, CarrierFormat::Bmp] {
            let mut carrier = CarrierImage::new(32, 24, format).unwrap();
            carrier.rgba_bytes_mut()[0..4].copy_from_slice(&[101, 102, 103, 104]);
            let encoded = carrier.encode(format).unwrap();
            let decoded = CarrierImage::load(&encoded).unwrap();
            assert_eq!(decoded.width(), 32);
            assert_eq!(decoded.height(), 24);
            assert_eq!(&decoded.rgba_bytes()[0..4], &[101, 102, 103, 104]);
        }
    }

    #[test]
    fn rejects_unknown_and_oversized_inputs() {
        assert!(matches!(CarrierImage::load(b"not an image"), Err(ImageError::UnsupportedFormat)));
        assert!(matches!(CarrierImage::load(&vec![0u8; MAX_CARRIER_FILE_BYTES + 1]), Err(ImageError::InputTooLarge)));
    }

    #[test]
    fn capacity_is_based_on_rgb_channels_only() {
        let carrier = CarrierImage::new(8, 8, CarrierFormat::Png).unwrap();
        assert_eq!(carrier.rgb_lsb_capacity_bytes(), 24);
    }
}
