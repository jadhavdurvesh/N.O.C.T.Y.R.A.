//! Recovery workflows and authenticated resumable-transfer state.
//!
//! Checkpoints are local progress hints, not proof that carrier files still
//! exist. Every carrier MUST be re-read and verified against its signed
//! manifest before it is used for reconstruction.
use thiserror::Error;

const CHECKPOINT_MAGIC: &[u8; 4] = b"NCRP";
const CHECKPOINT_VERSION: u16 = 1;
const CHECKPOINT_DOMAIN: &[u8] = b"NOCTYRA-RECOVERY-CHECKPOINT-V1\0";
const CHECKPOINT_HEADER_LEN: usize = 4 + 2 + 16 + 32 + 2 + 2;
const CHECKPOINT_TAG_LEN: usize = 32;
pub const MAX_CHECKPOINT_SHARDS: usize = 255;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CheckpointError {
    #[error("checkpoint is malformed or unsupported")]
    Malformed,
    #[error("checkpoint authentication failed")]
    Authentication,
    #[error("checkpoint shard index is out of range")]
    InvalidIndex,
    #[error("checkpoint shard count is outside the supported range")]
    InvalidShardCount,
}

/// Authenticated local record of which signed carrier shards have arrived.
/// It intentionally stores no carrier bytes and cannot authorize a shard.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryCheckpoint {
    transfer_id: [u8; 16],
    manifest_digest: [u8; 32],
    shard_count: u16,
    received: Vec<u8>,
}

impl RecoveryCheckpoint {
    pub fn new(transfer_id: [u8; 16], manifest_bytes: &[u8], shard_count: usize) -> Result<Self, CheckpointError> {
        if shard_count == 0 || shard_count > MAX_CHECKPOINT_SHARDS {
            return Err(CheckpointError::InvalidShardCount);
        }
        let bitmap_len = shard_count.div_ceil(8);
        Ok(Self {
            transfer_id,
            manifest_digest: *blake3::hash(manifest_bytes).as_bytes(),
            shard_count: shard_count as u16,
            received: vec![0; bitmap_len],
        })
    }

    pub fn from_verified_manifest(
        transfer_id: [u8; 16],
        manifest_bytes: &[u8],
        shard_count: usize,
    ) -> Result<Self, CheckpointError> {
        Self::new(transfer_id, manifest_bytes, shard_count)
    }

    pub fn transfer_id(&self) -> [u8; 16] { self.transfer_id }
    pub fn shard_count(&self) -> u16 { self.shard_count }
    pub fn manifest_digest(&self) -> [u8; 32] { self.manifest_digest }

    pub fn contains(&self, index: usize) -> bool {
        if index >= self.shard_count as usize { return false; }
        (self.received[index / 8] & (1 << (index % 8))) != 0
    }

    /// Mark an index only after the caller has verified that carrier against
    /// the independently trusted signed manifest.
    pub fn mark_verified(&mut self, index: usize) -> Result<(), CheckpointError> {
        if index >= self.shard_count as usize { return Err(CheckpointError::InvalidIndex); }
        self.received[index / 8] |= 1 << (index % 8);
        Ok(())
    }

    pub fn received_count(&self) -> usize {
        (0..self.shard_count as usize).filter(|index| self.contains(*index)).count()
    }

    pub fn missing_indices(&self) -> Vec<u16> {
        (0..self.shard_count as usize)
            .filter(|index| !self.contains(*index))
            .map(|index| index as u16)
            .collect()
    }

    fn body(&self) -> Vec<u8> {
        let mut body = Vec::with_capacity(CHECKPOINT_HEADER_LEN + self.received.len());
        body.extend_from_slice(CHECKPOINT_MAGIC);
        body.extend_from_slice(&CHECKPOINT_VERSION.to_le_bytes());
        body.extend_from_slice(&self.transfer_id);
        body.extend_from_slice(&self.manifest_digest);
        body.extend_from_slice(&self.shard_count.to_le_bytes());
        body.extend_from_slice(&(self.received.len() as u16).to_le_bytes());
        body.extend_from_slice(&self.received);
        body
    }

    /// Serialize with a 256-bit local checkpoint key. The key must be kept
    /// separate from the carrier package and the sender's signing identity.
    pub fn encode(&self, key: &[u8; 32]) -> Vec<u8> {
        let mut output = self.body();
        let mut authenticated = Vec::with_capacity(CHECKPOINT_DOMAIN.len() + output.len());
        authenticated.extend_from_slice(CHECKPOINT_DOMAIN);
        authenticated.extend_from_slice(&output);
        let tag = blake3::keyed_hash(key, &authenticated);
        output.extend_from_slice(tag.as_bytes());
        output
    }

    pub fn decode(bytes: &[u8], key: &[u8; 32]) -> Result<Self, CheckpointError> {
        if bytes.len() < CHECKPOINT_HEADER_LEN + CHECKPOINT_TAG_LEN
            || &bytes[..4] != CHECKPOINT_MAGIC
            || u16::from_le_bytes([bytes[4], bytes[5]]) != CHECKPOINT_VERSION {
            return Err(CheckpointError::Malformed);
        }
        let shard_count = u16::from_le_bytes([bytes[54], bytes[55]]) as usize;
        let bitmap_len = u16::from_le_bytes([bytes[56], bytes[57]]) as usize;
        if shard_count == 0 || shard_count > MAX_CHECKPOINT_SHARDS
            || bitmap_len != shard_count.div_ceil(8)
            || bytes.len() != CHECKPOINT_HEADER_LEN + bitmap_len + CHECKPOINT_TAG_LEN {
            return Err(CheckpointError::Malformed);
        }
        let body_end = CHECKPOINT_HEADER_LEN + bitmap_len;
        let mut authenticated = Vec::with_capacity(CHECKPOINT_DOMAIN.len() + body_end);
        authenticated.extend_from_slice(CHECKPOINT_DOMAIN);
        authenticated.extend_from_slice(&bytes[..body_end]);
        let expected = blake3::keyed_hash(key, &authenticated);
        if expected.as_bytes() != &bytes[body_end..] {
            return Err(CheckpointError::Authentication);
        }
        let mut transfer_id = [0u8; 16];
        transfer_id.copy_from_slice(&bytes[6..22]);
        let mut manifest_digest = [0u8; 32];
        manifest_digest.copy_from_slice(&bytes[22..54]);
        let received = bytes[CHECKPOINT_HEADER_LEN..body_end].to_vec();
        let unused_bits = bitmap_len * 8 - shard_count;
        if unused_bits > 0 {
            let valid_mask = (1u8 << (8 - unused_bits)) - 1;
            if received[bitmap_len - 1] & !valid_mask != 0 {
                return Err(CheckpointError::Malformed);
            }
        }
        Ok(Self { transfer_id, manifest_digest, shard_count: shard_count as u16, received })
    }

    /// Refuse to resume a checkpoint against a different signed transfer.
    pub fn ensure_manifest(&self, transfer_id: [u8; 16], manifest_bytes: &[u8]) -> Result<(), CheckpointError> {
        if self.transfer_id != transfer_id
            || self.manifest_digest != *blake3::hash(manifest_bytes).as_bytes() {
            return Err(CheckpointError::Authentication);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryStatus {
    Complete,
    MissingParts,
    InvalidParts,
    AuthenticationFailed,
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [0x5a; 32];

    #[test]
    fn checkpoint_round_trip_and_idempotent_marks() {
        let mut checkpoint = RecoveryCheckpoint::new([7; 16], b"signed manifest", 10).unwrap();
        checkpoint.mark_verified(2).unwrap();
        checkpoint.mark_verified(2).unwrap();
        checkpoint.mark_verified(9).unwrap();
        let encoded = checkpoint.encode(&KEY);
        let decoded = RecoveryCheckpoint::decode(&encoded, &KEY).unwrap();
        assert_eq!(decoded, checkpoint);
        assert_eq!(decoded.received_count(), 2);
        assert_eq!(decoded.missing_indices(), vec![0, 1, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn rejects_wrong_key_and_tampering() {
        let checkpoint = RecoveryCheckpoint::new([1; 16], b"manifest", 9).unwrap();
        let mut encoded = checkpoint.encode(&KEY);
        assert_eq!(RecoveryCheckpoint::decode(&encoded, &[0x33; 32]), Err(CheckpointError::Authentication));
        encoded[25] ^= 1;
        assert_eq!(RecoveryCheckpoint::decode(&encoded, &KEY), Err(CheckpointError::Authentication));
    }

    #[test]
    fn rejects_wrong_manifest_and_invalid_indexes() {
        let mut checkpoint = RecoveryCheckpoint::new([1; 16], b"manifest-a", 3).unwrap();
        assert_eq!(checkpoint.mark_verified(3), Err(CheckpointError::InvalidIndex));
        assert_eq!(checkpoint.ensure_manifest([1; 16], b"manifest-b"), Err(CheckpointError::Authentication));
        assert_eq!(checkpoint.ensure_manifest([2; 16], b"manifest-a"), Err(CheckpointError::Authentication));
    }

    #[test]
    fn rejects_nonzero_unused_bitmap_bits() {
        let checkpoint = RecoveryCheckpoint::new([1; 16], b"manifest", 9).unwrap();
        let mut encoded = checkpoint.encode(&KEY);
        let bitmap_last = CHECKPOINT_HEADER_LEN + 1;
        encoded[bitmap_last] |= 0x80;
        let body_end = CHECKPOINT_HEADER_LEN + 2;
        let mut authenticated = Vec::new();
        authenticated.extend_from_slice(CHECKPOINT_DOMAIN);
        authenticated.extend_from_slice(&encoded[..body_end]);
        let tag = blake3::keyed_hash(&KEY, &authenticated);
        encoded[body_end..].copy_from_slice(tag.as_bytes());
        assert_eq!(RecoveryCheckpoint::decode(&encoded, &KEY), Err(CheckpointError::Malformed));
    }
}
