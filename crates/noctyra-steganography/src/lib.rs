//! Reversible image-carrier research.
//!
//! Carrier encoding does not provide confidentiality or guarantee
//! undetectability. Input validation and an independent encrypted archive are
//! mandatory. A reversible codec will be added only with round-trip tests.

/// Supported carrier families in the initial design.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CarrierKind {
    Png,
    Bmp,
}
