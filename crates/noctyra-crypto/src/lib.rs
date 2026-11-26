//! Password-based authenticated encryption for NOCTYRA.
//!
//! This is the first M1 implementation. It uses Argon2id to derive a per-file
//! key from a password and fresh random salt, then XChaCha20-Poly1305 to
//! encrypt and authenticate the payload. This module is not an audited product.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const KEY_LEN: usize = 32;

// Initial desktop-oriented Argon2id profile: 64 MiB, 3 iterations, 1 lane.
// The file format must record these values and enforce strict bounds on read.
const ARGON2_MEMORY_KIB: u32 = 64 * 1024;
const ARGON2_ITERATIONS: u32 = 3;
const ARGON2_LANES: u32 = 1;

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("cryptographic random-number generation failed")]
    Random,
    #[error("invalid Argon2id configuration")]
    KdfConfiguration,
    #[error("key derivation failed")]
    KeyDerivation,
    #[error("encryption failed")]
    Encryption,
    #[error("authentication failed: password, ciphertext, or associated data is incorrect")]
    Authentication,
}

/// Version-independent encrypted payload fields for use by the container layer.
/// Serialization belongs to the container crate, not this crate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedPayload {
    pub salt: [u8; SALT_LEN],
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

fn derive_key(password: &[u8], salt: &[u8; SALT_LEN]) -> Result<Zeroizing<[u8; KEY_LEN]>, CryptoError> {
    let params = Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_ITERATIONS,
        ARGON2_LANES,
        Some(KEY_LEN),
    )
    .map_err(|_| CryptoError::KdfConfiguration)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = Zeroizing::new([0_u8; KEY_LEN]);
    argon2
        .hash_password_into(password, salt, &mut key[..])
        .map_err(|_| CryptoError::KeyDerivation)?;
    Ok(key)
}

/// Encrypt bytes with a password and optional associated data.
///
/// A fresh salt and nonce are generated for every call. The caller should bind
/// format/version metadata through associated_data once the NCT format is
/// finalized. Password bytes are used exactly as supplied; UI-level password
/// normalization must be explicitly specified rather than silently applied.
pub fn encrypt(
    password: &[u8],
    plaintext: &[u8],
    associated_data: &[u8],
) -> Result<EncryptedPayload, CryptoError> {
    let mut salt = [0_u8; SALT_LEN];
    let mut nonce = [0_u8; NONCE_LEN];
    OsRng.try_fill_bytes(&mut salt).map_err(|_| CryptoError::Random)?;
    OsRng.try_fill_bytes(&mut nonce).map_err(|_| CryptoError::Random)?;

    let key = derive_key(password, &salt)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key[..])
        .map_err(|_| CryptoError::Encryption)?;
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: associated_data,
            },
        )
        .map_err(|_| CryptoError::Encryption)?;

    Ok(EncryptedPayload { salt, nonce, ciphertext })
}

/// Authenticate and decrypt an encrypted payload.
///
/// Authentication failure intentionally does not distinguish a wrong password
/// from modified ciphertext or associated data.
pub fn decrypt(
    password: &[u8],
    payload: &EncryptedPayload,
    associated_data: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let key = derive_key(password, &payload.salt)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key[..])
        .map_err(|_| CryptoError::Authentication)?;
    cipher
        .decrypt(
            XNonce::from_slice(&payload.nonce),
            Payload {
                msg: &payload.ciphertext,
                aad: associated_data,
            },
        )
        .map_err(|_| CryptoError::Authentication)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_preserves_binary_data() {
        let plaintext = b"NOCTYRA\0binary\xffpayload";
        let aad = b"NCT draft metadata";
        let encrypted = encrypt(b"correct horse battery staple", plaintext, aad).unwrap();
        let recovered = decrypt(b"correct horse battery staple", &encrypted, aad).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn rejects_wrong_password() {
        let encrypted = encrypt(b"right password", b"secret", b"metadata").unwrap();
        let result = decrypt(b"wrong password", &encrypted, b"metadata");
        assert!(matches!(result, Err(CryptoError::Authentication)));
    }

    #[test]
    fn rejects_modified_ciphertext() {
        let mut encrypted = encrypt(b"password", b"secret payload", b"metadata").unwrap();
        encrypted.ciphertext[0] ^= 0x01;
        let result = decrypt(b"password", &encrypted, b"metadata");
        assert!(matches!(result, Err(CryptoError::Authentication)));
    }

    #[test]
    fn rejects_modified_associated_data() {
        let encrypted = encrypt(b"password", b"secret payload", b"metadata-a").unwrap();
        let result = decrypt(b"password", &encrypted, b"metadata-b");
        assert!(matches!(result, Err(CryptoError::Authentication)));
    }

    #[test]
    fn handles_empty_plaintext() {
        let encrypted = encrypt(b"password", b"", b"empty").unwrap();
        let recovered = decrypt(b"password", &encrypted, b"empty").unwrap();
        assert!(recovered.is_empty());
    }
}
