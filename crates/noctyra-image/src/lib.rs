//! Lossless carrier image handling.
//!
//! PNG is the primary carrier. BMP is secondary. Lossy formats are deliberately
//! excluded from the initial reliable-carrier path.

/// Formats accepted by the initial carrier design.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CarrierFormat {
    Png,
    Bmp,
}
