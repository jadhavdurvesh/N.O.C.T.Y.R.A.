//! CONSTELLATION v1 bounded multi-carrier transport framing.
//!
//! Fragment digests detect accidental corruption. They are not keyed
//! authentication; the reconstructed NCT archive must still pass NCT AEAD.
use blake3::Hasher;
use rand_core::{OsRng, RngCore};
use thiserror::Error;

pub const PROTOCOL_VERSION: u16 = 1;
pub const PROTOCOL_NAME: &str = "CONSTELLATION";
pub const FRAGMENT_MAGIC: &[u8; 4] = b"NCFR";
pub const FRAGMENT_HEADER_LEN: usize = 4 + 2 + 16 + 8 + 4 + 4 + 4 + 32 + 32;
pub const DEFAULT_FRAGMENT_DATA_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_FRAGMENT_DATA_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_FRAGMENT_COUNT: usize = 256;
pub const MAX_ARCHIVE_BYTES: usize = 1024 * 1024 * 1024;

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

/// Split a complete NCT archive into independently framed transport fragments.
pub fn fragment_archive(archive: &[u8], fragment_bytes: usize) -> Result<Vec<Vec<u8>>, ConstellationError> {
    let mut transfer_id = [0u8; 16];
    OsRng.try_fill_bytes(&mut transfer_id).map_err(|_| ConstellationError::RandomFailure)?;
    fragment_archive_with_id(archive, fragment_bytes, transfer_id)
}

/// Deterministic-ID variant for test vectors and reproducible protocol fixtures.
pub fn fragment_archive_with_id(
    archive: &[u8],
    fragment_bytes: usize,
    transfer_id: [u8; 16],
) -> Result<Vec<Vec<u8>>, ConstellationError> {
    validate_nct_archive(archive)?;
    if archive.len() > MAX_ARCHIVE_BYTES { return Err(ConstellationError::ArchiveTooLarge); }
    if fragment_bytes == 0 || fragment_bytes > MAX_FRAGMENT_DATA_BYTES {
        return Err(ConstellationError::InvalidFragmentSize);
    }
    let count = archive.len().div_ceil(fragment_bytes);
    if count == 0 || count > MAX_FRAGMENT_COUNT { return Err(ConstellationError::TooManyFragments); }
    let archive_digest = digest(archive);
    let mut result = Vec::with_capacity(count);
    for (index, data) in archive.chunks(fragment_bytes).enumerate() {
        let mut bytes = Vec::with_capacity(FRAGMENT_HEADER_LEN + data.len());
        bytes.extend_from_slice(FRAGMENT_MAGIC);
        bytes.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
        bytes.extend_from_slice(&transfer_id);
        bytes.extend_from_slice(&(archive.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&(index as u32).to_le_bytes());
        bytes.extend_from_slice(&(count as u32).to_le_bytes());
        bytes.extend_from_slice(&(data.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&archive_digest);
        bytes.extend_from_slice(&digest(data));
        bytes.extend_from_slice(data);
        result.push(bytes);
    }
    Ok(result)
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
    let mut seen = vec![false; first.count as usize];
    for fragment in &fragments {
        if fragment.transfer_id != transfer_id || fragment.archive_len != archive_len_u64
            || fragment.count != count as u32 || fragment.archive_digest != archive_digest {
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
        if fragment.transfer_id != first.transfer_id || fragment.archive_len != first.archive_len
            || fragment.count != first.count || fragment.archive_digest != first.archive_digest {
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
    fn rejects_non_nct_input_and_invalid_limits() {
        assert_eq!(fragment_archive_with_id(b"not an archive", 100, [0; 16]), Err(ConstellationError::InvalidArchive));
        assert_eq!(fragment_archive_with_id(&archive(), 0, [0; 16]), Err(ConstellationError::InvalidFragmentSize));
        assert_eq!(fragment_archive_with_id(&archive(), MAX_FRAGMENT_DATA_BYTES + 1, [0; 16]), Err(ConstellationError::InvalidFragmentSize));
    }
}
