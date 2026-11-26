//! NOCTYRA application orchestration crate.
//!
//! The desktop interface must call this API rather than implementing
//! cryptography or manipulating key material in the frontend.

pub use noctyra_container::{
    cleanup_stale_staging, decrypt_directory_stream, decrypt_stream, encrypt_directory_stream, encrypt_stream, extract_directory, validate_directory_manifest, open as open_archive, seal as seal_archive, seal_directory, ContainerError, STREAM_CHUNK_SIZE,
};
pub use noctyra_crypto::{CryptoError, EncryptedPayload};

/// Current application version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Product identity.
pub const PRODUCT_NAME: &str = "NOCTYRA";

pub use noctyra_image::{CarrierFormat, CarrierImage, ImageError};
pub use noctyra_steganography::{embed as embed_carrier, estimate_capacity as estimate_carrier_capacity, extract as extract_carrier, Capacity as CarrierCapacity, CarrierCodecError};

pub use noctyra_constellation::{create_recovery_shards, create_recovery_shards_with_id, create_signed_manifest_for_shards, parse_signed_manifest, verify_signed_manifest, verify_manifest_shards, inspect_recovery_shards, parse_recovery_shard, recover_archive, fragment_archive, fragment_archive_with_id, inspect_fragments, parse_fragment, reassemble_fragments, ConstellationError, Fragment as ConstellationFragment, FragmentPlan as ConstellationFragmentPlan, RecoveryReport as ConstellationRecoveryReport, RecoveryShard as ConstellationRecoveryShard, SignedManifest as ConstellationSignedManifest, ReassemblyReport as ConstellationReport, DEFAULT_FRAGMENT_DATA_BYTES, FRAGMENT_HEADER_LEN, RECOVERY_HEADER_LEN, DEFAULT_RECOVERY_DATA_SHARDS, DEFAULT_RECOVERY_PARITY_SHARDS, MAX_RECOVERY_SHARDS, MAX_FRAGMENT_DATA_BYTES, MAX_FRAGMENT_COUNT, MAX_ARCHIVE_BYTES};
