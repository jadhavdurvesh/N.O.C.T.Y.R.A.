//! NOCTYRA application orchestration crate.
//!
//! The desktop interface must call this API rather than implementing
//! cryptography or manipulating key material in the frontend.

pub use noctyra_container::{open as open_archive, seal as seal_archive, ContainerError};
pub use noctyra_crypto::{CryptoError, EncryptedPayload};

/// Current application version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Product identity.
pub const PRODUCT_NAME: &str = "NOCTYRA";
