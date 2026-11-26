//! CONSTELLATION multi-carrier transport.
//! Fragment manifests, authentication, validation and reassembly will live here.
//! A transport checksum is not a substitute for archive authenticated encryption.
pub const PROTOCOL_VERSION: u16 = 1;
pub const PROTOCOL_NAME: &str = "CONSTELLATION";
