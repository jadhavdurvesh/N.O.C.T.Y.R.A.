//! NCT archive serialization.
//!
//! The byte-level format remains a draft. Do not serialize untrusted lengths or
//! attacker-controlled KDF parameters until bounded parsing is implemented.

/// Draft NCT format version.
pub const FORMAT_VERSION: u16 = 1;

/// NCT magic identifier for future finalized binary envelopes.
pub const MAGIC: &[u8; 4] = b"NCTY";
