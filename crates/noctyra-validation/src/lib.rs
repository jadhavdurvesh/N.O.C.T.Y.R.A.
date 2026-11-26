//! Shared validation bounds. Apply limits before allocation or decompression.
pub const MAX_IMAGE_DIMENSION: u32 = 16_384;
pub const MAX_FRAGMENT_BYTES: usize = 16 * 1024 * 1024;
