//! NOCTYRA application orchestration crate.
//!
//! The core coordinates independent components. Cryptographic operations belong
//! in noctyra-crypto, never in the desktop frontend.

/// Current application version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Product identity.
pub const PRODUCT_NAME: &str = "NOCTYRA";
