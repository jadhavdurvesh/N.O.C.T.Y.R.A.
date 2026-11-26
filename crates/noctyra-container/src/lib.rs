//! NCT v1 encrypted archive envelope.
//!
//! Layout: magic[4] | version[2 LE] | salt[16] | nonce[24] |
//! ciphertext_length[8 LE] | ciphertext[ciphertext_length].
//!
//! The fixed header fields (magic, version, ciphertext length) are AEAD
//! associated data. The KDF profile is currently fixed in noctyra-crypto.
//! This is an initial format implementation and must receive independent review.

use noctyra_crypto::{decrypt, encrypt, CryptoError, EncryptedPayload};

pub const FORMAT_VERSION: u16 = 1;
pub const MAGIC: &[u8; 4] = b"NCTY";
pub const HEADER_LEN: usize = 4 + 2 + 16 + 24 + 8;
pub const TAG_LEN: usize = 16;
pub const MAX_CIPHERTEXT_LEN: usize = 1024 * 1024 * 1024;

mod tree;
pub use tree::{extract_directory, seal_directory};

mod stream;
pub use stream::{decrypt_stream, encrypt_stream, STREAM_CHUNK_SIZE};

#[derive(Debug, thiserror::Error)]
pub enum ContainerError {
    #[error("archive is truncated or malformed")]
    Malformed,
    #[error("unsupported NCT version: {0}")]
    UnsupportedVersion(u16),
    #[error("archive exceeds the configured size limit")]
    TooLarge,
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error("filesystem operation failed: {0}")]
    Io(String),
    #[error("directory archive contains an unsafe or invalid path or filesystem object")]
    InvalidTree,
    #[error("directory archive contains too many entries")]
    TooManyEntries,
    #[error("destination already exists; refusing to merge or overwrite")]
    DestinationExists,
}

fn associated_data(ciphertext_len: u64) -> [u8; 14] {
    let mut aad = [0_u8; 14];
    aad[..4].copy_from_slice(MAGIC);
    aad[4..6].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
    aad[6..14].copy_from_slice(&ciphertext_len.to_le_bytes());
    aad
}

/// Encrypt an arbitrary byte payload into a versioned NCT archive.
pub fn seal(password: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, ContainerError> {
    let ciphertext_len = plaintext.len().checked_add(TAG_LEN).ok_or(ContainerError::TooLarge)?;
    if ciphertext_len > MAX_CIPHERTEXT_LEN {
        return Err(ContainerError::TooLarge);
    }
    let ciphertext_len_u64 = u64::try_from(ciphertext_len).map_err(|_| ContainerError::TooLarge)?;
    let aad = associated_data(ciphertext_len_u64);
    let encrypted = encrypt(password, plaintext, &aad)?;

    let mut output = Vec::with_capacity(HEADER_LEN + encrypted.ciphertext.len());
    output.extend_from_slice(MAGIC);
    output.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    output.extend_from_slice(&encrypted.salt);
    output.extend_from_slice(&encrypted.nonce);
    output.extend_from_slice(&ciphertext_len_u64.to_le_bytes());
    output.extend_from_slice(&encrypted.ciphertext);
    Ok(output)
}

/// Authenticate and decrypt an NCT archive. No plaintext is returned unless
/// the complete ciphertext authenticates successfully.
pub fn open(password: &[u8], archive: &[u8]) -> Result<Vec<u8>, ContainerError> {
    if archive.len() < HEADER_LEN {
        return Err(ContainerError::Malformed);
    }
    if &archive[..4] != MAGIC {
        return Err(ContainerError::Malformed);
    }

    let version = u16::from_le_bytes([archive[4], archive[5]]);
    if version != FORMAT_VERSION {
        return Err(ContainerError::UnsupportedVersion(version));
    }

    let mut salt = [0_u8; 16];
    salt.copy_from_slice(&archive[6..22]);
    let mut nonce = [0_u8; 24];
    nonce.copy_from_slice(&archive[22..46]);

    let mut length_bytes = [0_u8; 8];
    length_bytes.copy_from_slice(&archive[46..54]);
    let ciphertext_len_u64 = u64::from_le_bytes(length_bytes);
    let ciphertext_len = usize::try_from(ciphertext_len_u64).map_err(|_| ContainerError::TooLarge)?;

    if ciphertext_len > MAX_CIPHERTEXT_LEN {
        return Err(ContainerError::TooLarge);
    }
    if ciphertext_len < TAG_LEN || archive.len() != HEADER_LEN.checked_add(ciphertext_len).ok_or(ContainerError::TooLarge)? {
        return Err(ContainerError::Malformed);
    }

    let aad = associated_data(ciphertext_len_u64);
    let payload = EncryptedPayload {
        salt,
        nonce,
        ciphertext: archive[HEADER_LEN..].to_vec(),
    };
    Ok(decrypt(password, &payload, &aad)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nct_round_trip() {
        let data = b"NOCTYRA archive test\0with binary bytes";
        let archive = seal(b"long test password", data).unwrap();
        assert_eq!(&archive[..4], MAGIC);
        assert_eq!(open(b"long test password", &archive).unwrap(), data);
    }

    #[test]
    fn rejects_wrong_password_and_tampering() {
        let archive = seal(b"correct password", b"classified test payload").unwrap();
        assert!(matches!(open(b"incorrect password", &archive), Err(ContainerError::Crypto(CryptoError::Authentication))));

        let mut changed = archive;
        let last = changed.len() - 1;
        changed[last] ^= 0x80;
        assert!(matches!(open(b"correct password", &changed), Err(ContainerError::Crypto(CryptoError::Authentication))));
    }

    #[test]
    fn rejects_truncation_and_trailing_data() {
        let archive = seal(b"password", b"payload").unwrap();
        assert!(matches!(open(b"password", &archive[..archive.len() - 1]), Err(ContainerError::Malformed)));
        let mut trailing = archive;
        trailing.push(0);
        assert!(matches!(open(b"password", &trailing), Err(ContainerError::Malformed)));
    }
}
