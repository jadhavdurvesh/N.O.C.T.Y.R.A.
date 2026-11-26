//! CONSTELLATION v1 bounded multi-carrier transport framing.
//!
//! Fragment digests detect accidental corruption. They are not keyed
//! authentication; the reconstructed NCT archive must still pass NCT AEAD.
use rand_core::{OsRng, RngCore};
use thiserror::Error;
use reed_solomon_erasure::galois_8::ReedSolomon;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

pub const PROTOCOL_VERSION: u16 = 1;
pub const PROTOCOL_NAME: &str = "CONSTELLATION";
pub const FRAGMENT_MAGIC: &[u8; 4] = b"NCFR";
pub const FRAGMENT_HEADER_LEN: usize = 4 + 2 + 16 + 8 + 4 + 4 + 4 + 32 + 32;
pub const DEFAULT_FRAGMENT_DATA_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_FRAGMENT_DATA_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_FRAGMENT_COUNT: usize = 256;
pub const MAX_ARCHIVE_BYTES: usize = 1024 * 1024 * 1024;
pub const RECOVERY_MAGIC: &[u8; 4] = b"NCRS";
pub const RECOVERY_VERSION: u16 = 1;
pub const RECOVERY_HEADER_LEN: usize = 4 + 2 + 16 + 8 + 2 + 2 + 2 + 4 + 32 + 32;
pub const DEFAULT_RECOVERY_DATA_SHARDS: usize = 8;
pub const DEFAULT_RECOVERY_PARITY_SHARDS: usize = 2;
pub const MAX_RECOVERY_SHARDS: usize = 255;
pub const MANIFEST_MAGIC: &[u8; 4] = b"NCMF";
pub const MANIFEST_VERSION: u16 = 1;
pub const MANIFEST_BODY_LEN: usize = 4 + 2 + 16 + 8 + 2 + 2 + 4 + 32;
pub const MANIFEST_SIGNATURE_LEN: usize = 64;
pub const MAX_MANIFEST_LEN: usize = MANIFEST_BODY_LEN + MAX_RECOVERY_SHARDS * 32 + SIGNING_PUBLIC_KEY_LEN + MANIFEST_SIGNATURE_LEN;
pub const SIGNING_PUBLIC_KEY_LEN: usize = 32;
pub const SIGNING_SECRET_KEY_LEN: usize = 32;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConstellationError {
    #[error("input is not a supported NCT archive")]
    InvalidArchive,
    #[error("archive exceeds the CONSTELLATION size limit")]
    ArchiveTooLarge,
    #[error("fragment size is outside the supported range")]
    InvalidFragmentSize,
    #[error("too many fragments for one transfer")]
    TooManyFragments,
    #[error("fragment is truncated or malformed")]
    MalformedFragment,
    #[error("fragment integrity check failed")]
    FragmentIntegrity,
    #[error("fragments belong to different transfers")]
    TransferMismatch,
    #[error("duplicate fragment index: {0}")]
    DuplicateFragment(u32),
    #[error("one or more fragments are missing")]
    MissingFragments,
    #[error("reconstructed archive digest does not match")]
    ArchiveIntegrity,
    #[error("random transfer identifier generation failed")]
    RandomFailure,
    #[error("recovery shard parameters are invalid")]
    InvalidRecoveryParameters,
    #[error("not enough recovery shards are available")]
    InsufficientRecoveryShards,
    #[error("Reed-Solomon recovery failed")]
    RecoveryFailed,
    #[error("signed manifest is malformed or unsupported")]
    MalformedManifest,
    #[error("signed manifest signature is invalid")]
    InvalidManifestSignature,
    #[error("manifest does not match the supplied recovery shards")]
    ManifestShardMismatch,
    #[error("manifest signer is not the trusted public key")]
    UntrustedManifestSigner,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fragment {
    pub transfer_id: [u8; 16],
    pub archive_len: u64,
    pub index: u32,
    pub count: u32,
    pub archive_digest: [u8; 32],
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReassemblyReport {
    pub transfer_id: [u8; 16],
    pub expected_fragments: u32,
    pub received_fragments: u32,
    pub missing_indices: Vec<u32>,
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}

fn validate_nct_archive(archive: &[u8]) -> Result<(), ConstellationError> {
    if archive.len() < 6 || &archive[..4] != b"NCTY" {
        return Err(ConstellationError::InvalidArchive);
    }
    let version = u16::from_le_bytes([archive[4], archive[5]]);
    if !matches!(version, 1 | 2) { return Err(ConstellationError::InvalidArchive); }
    Ok(())
}

/// A bounded-memory plan for producing fragments one at a time.
pub struct FragmentPlan<'a> {
    archive: &'a [u8],
    transfer_id: [u8; 16],
    fragment_bytes: usize,
    archive_digest: [u8; 32],
    count: usize,
}

impl<'a> FragmentPlan<'a> {
    pub fn new(archive: &'a [u8], fragment_bytes: usize) -> Result<Self, ConstellationError> {
        let mut transfer_id = [0u8; 16];
        OsRng.try_fill_bytes(&mut transfer_id).map_err(|_| ConstellationError::RandomFailure)?;
        Self::with_id(archive, fragment_bytes, transfer_id)
    }

    pub fn with_id(archive: &'a [u8], fragment_bytes: usize, transfer_id: [u8; 16]) -> Result<Self, ConstellationError> {
        validate_nct_archive(archive)?;
        if archive.len() > MAX_ARCHIVE_BYTES { return Err(ConstellationError::ArchiveTooLarge); }
        if fragment_bytes == 0 || fragment_bytes > MAX_FRAGMENT_DATA_BYTES {
            return Err(ConstellationError::InvalidFragmentSize);
        }
        let count = archive.len().div_ceil(fragment_bytes);
        if count == 0 || count > MAX_FRAGMENT_COUNT { return Err(ConstellationError::TooManyFragments); }
        Ok(Self { archive, transfer_id, fragment_bytes, archive_digest: digest(archive), count })
    }

    pub fn count(&self) -> usize { self.count }
    pub fn transfer_id(&self) -> [u8; 16] { self.transfer_id }

    /// Encode one fragment. Memory use is proportional to a single fragment.
    pub fn encode(&self, index: usize) -> Result<Vec<u8>, ConstellationError> {
        if index >= self.count { return Err(ConstellationError::MalformedFragment); }
        let start = index.checked_mul(self.fragment_bytes).ok_or(ConstellationError::MalformedFragment)?;
        let end = start.saturating_add(self.fragment_bytes).min(self.archive.len());
        let data = &self.archive[start..end];
        let mut bytes = Vec::with_capacity(FRAGMENT_HEADER_LEN + data.len());
        bytes.extend_from_slice(FRAGMENT_MAGIC);
        bytes.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
        bytes.extend_from_slice(&self.transfer_id);
        bytes.extend_from_slice(&(self.archive.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&(index as u32).to_le_bytes());
        bytes.extend_from_slice(&(self.count as u32).to_le_bytes());
        bytes.extend_from_slice(&(data.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.archive_digest);
        bytes.extend_from_slice(&digest(data));
        bytes.extend_from_slice(data);
        Ok(bytes)
    }
}

/// Split a complete NCT archive into independently framed transport fragments.
/// Convenience API; large transfers should use FragmentPlan and write each part
/// as it is produced to avoid retaining all fragment copies in memory.
pub fn fragment_archive(archive: &[u8], fragment_bytes: usize) -> Result<Vec<Vec<u8>>, ConstellationError> {
    let plan = FragmentPlan::new(archive, fragment_bytes)?;
    (0..plan.count()).map(|index| plan.encode(index)).collect()
}

/// Deterministic-ID convenience API for test vectors and reproducible fixtures.
pub fn fragment_archive_with_id(
    archive: &[u8],
    fragment_bytes: usize,
    transfer_id: [u8; 16],
) -> Result<Vec<Vec<u8>>, ConstellationError> {
    let plan = FragmentPlan::with_id(archive, fragment_bytes, transfer_id)?;
    (0..plan.count()).map(|index| plan.encode(index)).collect()
}

/// Versioned recovery shard with systematic data and parity roles.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryShard {
    pub transfer_id: [u8; 16],
    pub archive_len: u64,
    pub data_shards: u16,
    pub parity_shards: u16,
    pub index: u16,
    pub shard_size: u32,
    pub archive_digest: [u8; 32],
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryReport {
    pub transfer_id: [u8; 16],
    pub data_shards: u16,
    pub parity_shards: u16,
    pub received_shards: u16,
    pub missing_indices: Vec<u16>,
    pub recoverable: bool,
}

/// Produce systematic Reed-Solomon shards. The original data shards are
/// preserved byte-for-byte except zero padding on the final shard.
pub fn create_recovery_shards(
    archive: &[u8],
    shard_size: usize,
    parity_shards: usize,
) -> Result<Vec<Vec<u8>>, ConstellationError> {
    let mut transfer_id = [0u8; 16];
    OsRng.try_fill_bytes(&mut transfer_id).map_err(|_| ConstellationError::RandomFailure)?;
    create_recovery_shards_with_id(archive, shard_size, parity_shards, transfer_id)
}

pub fn create_recovery_shards_with_id(
    archive: &[u8],
    shard_size: usize,
    parity_shards: usize,
    transfer_id: [u8; 16],
) -> Result<Vec<Vec<u8>>, ConstellationError> {
    validate_nct_archive(archive)?;
    if archive.len() > MAX_ARCHIVE_BYTES { return Err(ConstellationError::ArchiveTooLarge); }
    if shard_size == 0 || shard_size > MAX_FRAGMENT_DATA_BYTES || parity_shards == 0 {
        return Err(ConstellationError::InvalidRecoveryParameters);
    }
    let data_count = archive.len().div_ceil(shard_size);
    let total = data_count.checked_add(parity_shards).ok_or(ConstellationError::InvalidRecoveryParameters)?;
    if data_count == 0 || total > MAX_RECOVERY_SHARDS {
        return Err(ConstellationError::InvalidRecoveryParameters);
    }
    let codec = ReedSolomon::new(data_count, parity_shards).map_err(|_| ConstellationError::InvalidRecoveryParameters)?;
    let mut shards = Vec::with_capacity(total);
    for chunk in archive.chunks(shard_size) {
        let mut shard = vec![0u8; shard_size];
        shard[..chunk.len()].copy_from_slice(chunk);
        shards.push(shard);
    }
    for _ in 0..parity_shards { shards.push(vec![0u8; shard_size]); }
    codec.encode(&mut shards).map_err(|_| ConstellationError::RecoveryFailed)?;
    let archive_digest = digest(archive);
    let mut output = Vec::with_capacity(total);
    for (index, data) in shards.into_iter().enumerate() {
        let mut frame = Vec::with_capacity(RECOVERY_HEADER_LEN + shard_size);
        frame.extend_from_slice(RECOVERY_MAGIC);
        frame.extend_from_slice(&RECOVERY_VERSION.to_le_bytes());
        frame.extend_from_slice(&transfer_id);
        frame.extend_from_slice(&(archive.len() as u64).to_le_bytes());
        frame.extend_from_slice(&(data_count as u16).to_le_bytes());
        frame.extend_from_slice(&(parity_shards as u16).to_le_bytes());
        frame.extend_from_slice(&(index as u16).to_le_bytes());
        frame.extend_from_slice(&(shard_size as u32).to_le_bytes());
        frame.extend_from_slice(&archive_digest);
        frame.extend_from_slice(&digest(&data));
        frame.extend_from_slice(&data);
        output.push(frame);
    }
    Ok(output)
}

pub fn parse_recovery_shard(bytes: &[u8]) -> Result<RecoveryShard, ConstellationError> {
    if bytes.len() < RECOVERY_HEADER_LEN || &bytes[..4] != RECOVERY_MAGIC {
        return Err(ConstellationError::MalformedFragment);
    }
    let version = u16::from_le_bytes([bytes[4], bytes[5]]);
    if version != RECOVERY_VERSION { return Err(ConstellationError::MalformedFragment); }
    let mut transfer_id = [0u8; 16];
    transfer_id.copy_from_slice(&bytes[6..22]);
    let archive_len = u64::from_le_bytes(bytes[22..30].try_into().map_err(|_| ConstellationError::MalformedFragment)?);
    let data_shards = u16::from_le_bytes(bytes[30..32].try_into().map_err(|_| ConstellationError::MalformedFragment)?);
    let parity_shards = u16::from_le_bytes(bytes[32..34].try_into().map_err(|_| ConstellationError::MalformedFragment)?);
    let index = u16::from_le_bytes(bytes[34..36].try_into().map_err(|_| ConstellationError::MalformedFragment)?);
    let shard_size = u32::from_le_bytes(bytes[36..40].try_into().map_err(|_| ConstellationError::MalformedFragment)?) as usize;
    let mut archive_digest = [0u8; 32];
    archive_digest.copy_from_slice(&bytes[40..72]);
    let mut shard_digest = [0u8; 32];
    shard_digest.copy_from_slice(&bytes[72..104]);
    let total = data_shards as usize + parity_shards as usize;
    if archive_len == 0 || archive_len > MAX_ARCHIVE_BYTES as u64
        || data_shards == 0 || parity_shards == 0 || total > MAX_RECOVERY_SHARDS
        || index as usize >= total || shard_size == 0 || shard_size > MAX_FRAGMENT_DATA_BYTES
        || bytes.len() != RECOVERY_HEADER_LEN.checked_add(shard_size).ok_or(ConstellationError::MalformedFragment)?
        || (data_shards as u64 - 1).saturating_mul(shard_size as u64) >= archive_len
        || (data_shards as u64).saturating_mul(shard_size as u64) < archive_len {
        return Err(ConstellationError::MalformedFragment);
    }
    let data = bytes[RECOVERY_HEADER_LEN..].to_vec();
    if digest(&data) != shard_digest { return Err(ConstellationError::FragmentIntegrity); }
    Ok(RecoveryShard { transfer_id, archive_len, data_shards, parity_shards, index, shard_size: shard_size as u32, archive_digest, data })
}

pub fn inspect_recovery_shards<'a, I>(inputs: I) -> Result<RecoveryReport, ConstellationError>
where I: IntoIterator<Item = &'a [u8]> {
    let mut shards = Vec::new();
    for input in inputs { shards.push(parse_recovery_shard(input)?); }
    let first = shards.first().ok_or(ConstellationError::InsufficientRecoveryShards)?;
    let total = first.data_shards as usize + first.parity_shards as usize;
    let mut seen = vec![false; total];
    for shard in &shards {
        if shard.transfer_id != first.transfer_id || shard.archive_len != first.archive_len
            || shard.data_shards != first.data_shards || shard.parity_shards != first.parity_shards
            || shard.shard_size != first.shard_size || shard.archive_digest != first.archive_digest {
            return Err(ConstellationError::TransferMismatch);
        }
        let slot = &mut seen[shard.index as usize];
        if *slot { return Err(ConstellationError::DuplicateFragment(shard.index as u32)); }
        *slot = true;
    }
    let missing_indices: Vec<u16> = seen.iter().enumerate().filter_map(|(i, present)| (!present).then_some(i as u16)).collect();
    Ok(RecoveryReport {
        transfer_id: first.transfer_id,
        data_shards: first.data_shards,
        parity_shards: first.parity_shards,
        received_shards: shards.len() as u16,
        recoverable: shards.len() >= first.data_shards as usize,
        missing_indices,
    })
}

/// Reconstruct the archive when any k of n valid shards are available.
pub fn recover_archive<'a, I>(inputs: I) -> Result<Vec<u8>, ConstellationError>
where I: IntoIterator<Item = &'a [u8]> {
    let mut received = Vec::new();
    for input in inputs { received.push(parse_recovery_shard(input)?); }
    let first = received.first().ok_or(ConstellationError::InsufficientRecoveryShards)?;
    let data_count = first.data_shards as usize;
    let parity_count = first.parity_shards as usize;
    let shard_size = first.shard_size as usize;
    let total = data_count + parity_count;
    if received.len() < data_count { return Err(ConstellationError::InsufficientRecoveryShards); }
    let archive_len = usize::try_from(first.archive_len).map_err(|_| ConstellationError::ArchiveTooLarge)?;
    let transfer_id = first.transfer_id;
    let archive_digest = first.archive_digest;
    let archive_len_u64 = first.archive_len;
    let mut shards: Vec<Option<Vec<u8>>> = (0..total).map(|_| None).collect();
    for shard in received {
        if shard.transfer_id != transfer_id || shard.archive_len != archive_len_u64
            || shard.data_shards as usize != data_count || shard.parity_shards as usize != parity_count
            || shard.shard_size as usize != shard_size || shard.archive_digest != archive_digest {
            return Err(ConstellationError::TransferMismatch);
        }
        let slot = &mut shards[shard.index as usize];
        if slot.is_some() { return Err(ConstellationError::DuplicateFragment(shard.index as u32)); }
        *slot = Some(shard.data);
    }
    let codec = ReedSolomon::new(data_count, parity_count).map_err(|_| ConstellationError::InvalidRecoveryParameters)?;
    codec.reconstruct(&mut shards).map_err(|_| ConstellationError::RecoveryFailed)?;
    let complete: Vec<Vec<u8>> = shards.into_iter().map(|shard| shard.ok_or(ConstellationError::RecoveryFailed)).collect::<Result<_, _>>()?;
    if !codec.verify(&complete).map_err(|_| ConstellationError::RecoveryFailed)? {
        return Err(ConstellationError::RecoveryFailed);
    }
    let mut archive = Vec::with_capacity(archive_len);
    for shard in complete.iter().take(data_count) {
        let remaining = archive_len.saturating_sub(archive.len());
        archive.extend_from_slice(&shard[..remaining.min(shard.len())]);
    }
    if archive.len() != archive_len || digest(&archive) != archive_digest {
        return Err(ConstellationError::ArchiveIntegrity);
    }
    validate_nct_archive(&archive)?;
    Ok(archive)
}

/// Signed recovery manifest. The signature covers the fixed header and
/// every shard payload digest in index order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedManifest {
    pub transfer_id: [u8; 16],
    pub archive_len: u64,
    pub data_shards: u16,
    pub parity_shards: u16,
    pub shard_size: u32,
    pub archive_digest: [u8; 32],
    pub shard_digests: Vec<[u8; 32]>,
    pub signer_public_key: [u8; 32],
    pub signature: [u8; 64],
}

/// A manifest whose Ed25519 signature and signer pin have been verified.
/// Its inner fields cannot be constructed or mutated by external callers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedManifest(SignedManifest);

impl VerifiedManifest {
    pub fn signer_public_key(&self) -> [u8; 32] { self.0.signer_public_key }
    pub fn transfer_id(&self) -> [u8; 16] { self.0.transfer_id }
}

fn manifest_header(
    transfer_id: &[u8; 16], archive_len: u64, data_shards: u16,
    parity_shards: u16, shard_size: u32, archive_digest: &[u8; 32],
) -> Vec<u8> {
    let mut body = Vec::with_capacity(MANIFEST_BODY_LEN);
    body.extend_from_slice(MANIFEST_MAGIC);
    body.extend_from_slice(&MANIFEST_VERSION.to_le_bytes());
    body.extend_from_slice(transfer_id);
    body.extend_from_slice(&archive_len.to_le_bytes());
    body.extend_from_slice(&data_shards.to_le_bytes());
    body.extend_from_slice(&parity_shards.to_le_bytes());
    body.extend_from_slice(&shard_size.to_le_bytes());
    body.extend_from_slice(archive_digest);
    body
}

/// Sign metadata and the BLAKE3 digest of every shard in the complete set.
pub fn create_signed_manifest_for_shards<'a, I>(
    inputs: I, signing_key: &SigningKey,
) -> Result<Vec<u8>, ConstellationError>
where I: IntoIterator<Item = &'a [u8]> {
    let inputs: Vec<&[u8]> = inputs.into_iter().collect();
    let report = inspect_recovery_shards(inputs.iter().copied())?;
    if !report.missing_indices.is_empty() { return Err(ConstellationError::MissingFragments); }
    let first = parse_recovery_shard(inputs[0])?;
    let mut digests: Vec<Option<[u8; 32]>> = vec![None; first.data_shards as usize + first.parity_shards as usize];
    for input in inputs {
        let shard = parse_recovery_shard(input)?;
        digests[shard.index as usize] = Some(digest(&shard.data));
    }
    let ordered_digests: Vec<[u8; 32]> = digests.into_iter()
        .map(|value| value.ok_or(ConstellationError::MissingFragments))
        .collect::<Result<_, _>>()?;
    let mut body = manifest_header(
        &first.transfer_id, first.archive_len, first.data_shards,
        first.parity_shards, first.shard_size, &first.archive_digest,
    );
    for shard_digest in &ordered_digests { body.extend_from_slice(shard_digest); }
    let mut signed_message = b"NOCTYRA-CONSTELLATION-MANIFEST-V1\0".to_vec();
    signed_message.extend_from_slice(&body);
    let signature = signing_key.sign(&signed_message);
    let mut output = body;
    output.extend_from_slice(&signing_key.verifying_key().to_bytes());
    output.extend_from_slice(&signature.to_bytes());
    Ok(output)
}

pub fn parse_signed_manifest(bytes: &[u8]) -> Result<SignedManifest, ConstellationError> {
    if bytes.len() < MANIFEST_BODY_LEN + SIGNING_PUBLIC_KEY_LEN + MANIFEST_SIGNATURE_LEN
        || &bytes[..4] != MANIFEST_MAGIC
        || u16::from_le_bytes([bytes[4], bytes[5]]) != MANIFEST_VERSION {
        return Err(ConstellationError::MalformedManifest);
    }
    let mut transfer_id = [0u8; 16]; transfer_id.copy_from_slice(&bytes[6..22]);
    let archive_len = u64::from_le_bytes(bytes[22..30].try_into().map_err(|_| ConstellationError::MalformedManifest)?);
    let data_shards = u16::from_le_bytes(bytes[30..32].try_into().map_err(|_| ConstellationError::MalformedManifest)?);
    let parity_shards = u16::from_le_bytes(bytes[32..34].try_into().map_err(|_| ConstellationError::MalformedManifest)?);
    let shard_size = u32::from_le_bytes(bytes[34..38].try_into().map_err(|_| ConstellationError::MalformedManifest)?);
    let mut archive_digest = [0u8; 32]; archive_digest.copy_from_slice(&bytes[38..70]);
    let total = data_shards as usize + parity_shards as usize;
    if archive_len == 0 || archive_len > MAX_ARCHIVE_BYTES as u64
        || data_shards == 0 || parity_shards == 0 || total > MAX_RECOVERY_SHARDS
        || shard_size == 0 || shard_size as usize > MAX_FRAGMENT_DATA_BYTES
        || (data_shards as u64 - 1).saturating_mul(shard_size as u64) >= archive_len
        || (data_shards as u64).saturating_mul(shard_size as u64) < archive_len {
        return Err(ConstellationError::MalformedManifest);
    }
    let body_len = MANIFEST_BODY_LEN.checked_add(total.checked_mul(32).ok_or(ConstellationError::MalformedManifest)?)
        .ok_or(ConstellationError::MalformedManifest)?;
    let expected = body_len.checked_add(SIGNING_PUBLIC_KEY_LEN + MANIFEST_SIGNATURE_LEN)
        .ok_or(ConstellationError::MalformedManifest)?;
    if bytes.len() != expected { return Err(ConstellationError::MalformedManifest); }
    let mut shard_digests = Vec::with_capacity(total);
    for digest_bytes in bytes[MANIFEST_BODY_LEN..body_len].chunks_exact(32) {
        let mut value = [0u8; 32]; value.copy_from_slice(digest_bytes); shard_digests.push(value);
    }
    let mut signer_public_key = [0u8; 32]; signer_public_key.copy_from_slice(&bytes[body_len..body_len + 32]);
    let mut signature = [0u8; 64]; signature.copy_from_slice(&bytes[body_len + 32..]);
    Ok(SignedManifest { transfer_id, archive_len, data_shards, parity_shards, shard_size, archive_digest, shard_digests, signer_public_key, signature })
}

/// Verify the manifest signature and pin it to an independently trusted key.
pub fn verify_signed_manifest(bytes: &[u8], trusted_public_key: &[u8; 32]) -> Result<VerifiedManifest, ConstellationError> {
    let manifest = parse_signed_manifest(bytes)?;
    if &manifest.signer_public_key != trusted_public_key { return Err(ConstellationError::UntrustedManifestSigner); }
    let key = VerifyingKey::from_bytes(&manifest.signer_public_key).map_err(|_| ConstellationError::MalformedManifest)?;
    let signature = Signature::from_bytes(&manifest.signature);
    let body_len = MANIFEST_BODY_LEN + manifest.shard_digests.len() * 32;
    let mut signed_message = b"NOCTYRA-CONSTELLATION-MANIFEST-V1\0".to_vec();
    signed_message.extend_from_slice(&bytes[..body_len]);
    key.verify(&signed_message, &signature).map_err(|_| ConstellationError::InvalidManifestSignature)?;
    Ok(VerifiedManifest(manifest))
}

/// Ensure every supplied shard belongs to the exact signed set.
pub fn verify_manifest_shards<'a, I>(verified: &VerifiedManifest, inputs: I) -> Result<RecoveryReport, ConstellationError>
where I: IntoIterator<Item = &'a [u8]> {
    let manifest = &verified.0;
    let inputs: Vec<&[u8]> = inputs.into_iter().collect();
    let _ = inspect_recovery_shards(inputs.iter().copied())?;
    let mut seen = vec![false; manifest.data_shards as usize + manifest.parity_shards as usize];
    for input in inputs {
        let shard = parse_recovery_shard(input)?;
        if shard.transfer_id != manifest.transfer_id || shard.archive_len != manifest.archive_len
            || shard.data_shards != manifest.data_shards || shard.parity_shards != manifest.parity_shards
            || shard.shard_size != manifest.shard_size || shard.archive_digest != manifest.archive_digest
            || digest(&shard.data) != manifest.shard_digests[shard.index as usize] {
            return Err(ConstellationError::ManifestShardMismatch);
        }
        seen[shard.index as usize] = true;
    }
    Ok(RecoveryReport {
        transfer_id: manifest.transfer_id,
        data_shards: manifest.data_shards,
        parity_shards: manifest.parity_shards,
        received_shards: seen.iter().filter(|present| **present).count() as u16,
        missing_indices: seen.iter().enumerate().filter_map(|(i, present)| (!present).then_some(i as u16)).collect(),
        recoverable: seen.iter().filter(|present| **present).count() >= manifest.data_shards as usize,
    })
}

/// Parse and validate one untrusted fragment before retaining its payload.
pub fn parse_fragment(bytes: &[u8]) -> Result<Fragment, ConstellationError> {
    if bytes.len() < FRAGMENT_HEADER_LEN || &bytes[..4] != FRAGMENT_MAGIC {
        return Err(ConstellationError::MalformedFragment);
    }
    let version = u16::from_le_bytes([bytes[4], bytes[5]]);
    if version != PROTOCOL_VERSION { return Err(ConstellationError::MalformedFragment); }
    let mut transfer_id = [0u8; 16];
    transfer_id.copy_from_slice(&bytes[6..22]);
    let archive_len = u64::from_le_bytes(bytes[22..30].try_into().map_err(|_| ConstellationError::MalformedFragment)?);
    let index = u32::from_le_bytes(bytes[30..34].try_into().map_err(|_| ConstellationError::MalformedFragment)?);
    let count = u32::from_le_bytes(bytes[34..38].try_into().map_err(|_| ConstellationError::MalformedFragment)?);
    let data_len = u32::from_le_bytes(bytes[38..42].try_into().map_err(|_| ConstellationError::MalformedFragment)?) as usize;
    let mut archive_digest = [0u8; 32];
    archive_digest.copy_from_slice(&bytes[42..74]);
    let mut fragment_digest = [0u8; 32];
    fragment_digest.copy_from_slice(&bytes[74..106]);

    if archive_len == 0 || archive_len > MAX_ARCHIVE_BYTES as u64
        || count == 0 || count as usize > MAX_FRAGMENT_COUNT
        || index >= count || data_len == 0 || data_len > MAX_FRAGMENT_DATA_BYTES
        || bytes.len() != FRAGMENT_HEADER_LEN.checked_add(data_len).ok_or(ConstellationError::MalformedFragment)? {
        return Err(ConstellationError::MalformedFragment);
    }
    let minimum_count = archive_len.div_ceil(MAX_FRAGMENT_DATA_BYTES as u64);
    let maximum_count = archive_len; // one byte per fragment is the theoretical lower bound
    if u64::from(count) < minimum_count || u64::from(count) > maximum_count {
        return Err(ConstellationError::MalformedFragment);
    }
    let data = bytes[FRAGMENT_HEADER_LEN..].to_vec();
    if digest(&data) != fragment_digest { return Err(ConstellationError::FragmentIntegrity); }
    Ok(Fragment { transfer_id, archive_len, index, count, archive_digest, data })
}

/// Describe missing fragment indexes without attempting partial reconstruction.
pub fn inspect_fragments<'a, I>(inputs: I) -> Result<ReassemblyReport, ConstellationError>
where I: IntoIterator<Item = &'a [u8]> {
    let mut fragments = Vec::new();
    for input in inputs { fragments.push(parse_fragment(input)?); }
    let first = fragments.first().ok_or(ConstellationError::MissingFragments)?;
    let transfer_id = first.transfer_id;
    let archive_len = first.archive_len;
    let count = first.count;
    let archive_digest = first.archive_digest;
    let mut seen = vec![false; count as usize];
    for fragment in &fragments {
        if fragment.transfer_id != transfer_id || fragment.archive_len != archive_len
            || fragment.count != count || fragment.archive_digest != archive_digest {
            return Err(ConstellationError::TransferMismatch);
        }
        let slot = &mut seen[fragment.index as usize];
        if *slot { return Err(ConstellationError::DuplicateFragment(fragment.index)); }
        *slot = true;
    }
    let missing_indices = seen.iter().enumerate().filter_map(|(i, present)| (!present).then_some(i as u32)).collect();
    Ok(ReassemblyReport {
        transfer_id: first.transfer_id,
        expected_fragments: first.count,
        received_fragments: fragments.len() as u32,
        missing_indices,
    })
}

/// Reassemble out-of-order fragments and verify the exact original NCT archive digest.
pub fn reassemble_fragments<'a, I>(inputs: I) -> Result<Vec<u8>, ConstellationError>
where I: IntoIterator<Item = &'a [u8]> {
    let mut fragments = Vec::new();
    for input in inputs { fragments.push(parse_fragment(input)?); }
    let first = fragments.first().ok_or(ConstellationError::MissingFragments)?;
    let count = first.count as usize;
    let archive_len_u64 = first.archive_len;
    let transfer_id = first.transfer_id;
    let archive_digest = first.archive_digest;
    let archive_len = usize::try_from(archive_len_u64).map_err(|_| ConstellationError::ArchiveTooLarge)?;
    if archive_len > MAX_ARCHIVE_BYTES { return Err(ConstellationError::ArchiveTooLarge); }
    let mut slots: Vec<Option<Vec<u8>>> = (0..count).map(|_| None).collect();
    for fragment in fragments {
        if fragment.transfer_id != transfer_id || fragment.archive_len != archive_len_u64
            || fragment.count != count as u32 || fragment.archive_digest != archive_digest {
            return Err(ConstellationError::TransferMismatch);
        }
        let slot = &mut slots[fragment.index as usize];
        if slot.is_some() { return Err(ConstellationError::DuplicateFragment(fragment.index)); }
        *slot = Some(fragment.data);
    }
    if slots.iter().any(Option::is_none) { return Err(ConstellationError::MissingFragments); }
    let mut archive = Vec::with_capacity(archive_len);
    for part in slots {
        archive.extend_from_slice(&part.ok_or(ConstellationError::MissingFragments)?);
        if archive.len() > archive_len { return Err(ConstellationError::MalformedFragment); }
    }
    if archive.len() != archive_len || digest(&archive) != archive_digest {
        return Err(ConstellationError::ArchiveIntegrity);
    }
    validate_nct_archive(&archive)?;
    Ok(archive)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn archive() -> Vec<u8> {
        let mut bytes = b"NCTY".to_vec();
        bytes.extend_from_slice(&2u16.to_le_bytes());
        bytes.extend((0..10_000).map(|n| (n % 251) as u8));
        bytes
    }

    #[test]
    fn fragments_reassemble_out_of_order() {
        let original = archive();
        let fragments = fragment_archive_with_id(&original, 1024, [7u8; 16]).unwrap();
        let reversed: Vec<&[u8]> = fragments.iter().rev().map(Vec::as_slice).collect();
        assert_eq!(reassemble_fragments(reversed).unwrap(), original);
    }

    #[test]
    fn missing_and_duplicate_parts_are_reported() {
        let fragments = fragment_archive_with_id(&archive(), 1024, [8u8; 16]).unwrap();
        let missing = inspect_fragments(fragments.iter().take(fragments.len() - 1).map(Vec::as_slice)).unwrap();
        assert!(!missing.missing_indices.is_empty());
        assert_eq!(missing.received_fragments as usize, fragments.len() - 1);

        let mut duplicate = fragments.clone();
        duplicate.push(fragments[0].clone());
        assert!(matches!(inspect_fragments(duplicate.iter().map(Vec::as_slice)), Err(ConstellationError::DuplicateFragment(0))));
    }

    #[test]
    fn rejects_modified_fragment_and_mixed_transfers() {
        let mut fragments = fragment_archive_with_id(&archive(), 1024, [9u8; 16]).unwrap();
        let last = fragments[0].len() - 1;
        fragments[0][last] ^= 1;
        assert_eq!(parse_fragment(&fragments[0]), Err(ConstellationError::FragmentIntegrity));

        let a = fragment_archive_with_id(&archive(), 1024, [1u8; 16]).unwrap();
        let b = fragment_archive_with_id(&archive(), 1024, [2u8; 16]).unwrap();
        let mixed = [a[0].as_slice(), b[1].as_slice()];
        assert_eq!(reassemble_fragments(mixed), Err(ConstellationError::TransferMismatch));
    }

    #[test]
    fn recovery_shards_reconstruct_with_missing_data_and_parity() {
        let original = archive();
        let shards = create_recovery_shards_with_id(&original, 1024, 3, [42u8; 16]).unwrap();
        let selected: Vec<&[u8]> = shards.iter().enumerate()
            .filter(|(i, _)| !matches!(i, 1 | 4 | 11))
            .map(|(_, shard)| shard.as_slice()).collect();
        assert_eq!(recover_archive(selected).unwrap(), original);
    }

    #[test]
    fn recovery_reports_threshold_and_rejects_corruption() {
        let shards = create_recovery_shards_with_id(&archive(), 1024, 2, [43u8; 16]).unwrap();
        let report = inspect_recovery_shards(shards.iter().take(3).map(Vec::as_slice)).unwrap();
        assert!(report.recoverable);
        let insufficient = shards.iter().take(2).map(Vec::as_slice);
        assert_eq!(recover_archive(insufficient), Err(ConstellationError::InsufficientRecoveryShards));
        let mut corrupt = shards[0].clone();
        let last = corrupt.len() - 1;
        corrupt[last] ^= 1;
        assert_eq!(parse_recovery_shard(&corrupt), Err(ConstellationError::FragmentIntegrity));
    }

    #[test]
    fn signed_manifest_pins_signer_and_authenticates_recovery_set() {
        let original = archive();
        let shards = create_recovery_shards_with_id(&original, 1024, 2, [51u8; 16]).unwrap();
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let refs: Vec<&[u8]> = shards.iter().map(Vec::as_slice).collect();
        let manifest = create_signed_manifest_for_shards(refs.iter().copied(), &signing_key).unwrap();
        let verified = verify_signed_manifest(&manifest, &signing_key.verifying_key().to_bytes()).unwrap();
        let report = verify_manifest_shards(&verified, refs.iter().copied()).unwrap();
        assert!(report.recoverable);
        assert_eq!(recover_archive(refs.iter().copied()).unwrap(), original);

        // Recompute the public frame checksum after tampering. The signed
        // manifest's per-shard digest must still detect the substitution.
        let mut forged_shard = shards[0].clone();
        let last = forged_shard.len() - 1;
        forged_shard[last] ^= 1;
        let forged_digest = digest(&forged_shard[RECOVERY_HEADER_LEN..]);
        forged_shard[72..104].copy_from_slice(&forged_digest);
        assert_eq!(
            verify_manifest_shards(&verified, [forged_shard.as_slice()]),
            Err(ConstellationError::ManifestShardMismatch)
        );

        let other_key = SigningKey::from_bytes(&[8u8; 32]);
        assert_eq!(verify_signed_manifest(&manifest, &other_key.verifying_key().to_bytes()), Err(ConstellationError::UntrustedManifestSigner));

        let mut tampered = manifest.clone();
        tampered[38] ^= 1;
        assert_eq!(verify_signed_manifest(&tampered, &signing_key.verifying_key().to_bytes()), Err(ConstellationError::InvalidManifestSignature));
    }

    #[test]
    fn rejects_non_nct_input_and_invalid_limits() {
        assert_eq!(fragment_archive_with_id(b"not an archive", 100, [0; 16]), Err(ConstellationError::InvalidArchive));
        assert_eq!(fragment_archive_with_id(&archive(), 0, [0; 16]), Err(ConstellationError::InvalidFragmentSize));
        assert_eq!(fragment_archive_with_id(&archive(), MAX_FRAGMENT_DATA_BYTES + 1, [0; 16]), Err(ConstellationError::InvalidFragmentSize));
    }
}
