//! Recovery workflows. Never emit plaintext before archive authentication succeeds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryStatus {
    Complete,
    MissingParts,
    InvalidParts,
    AuthenticationFailed,
}
