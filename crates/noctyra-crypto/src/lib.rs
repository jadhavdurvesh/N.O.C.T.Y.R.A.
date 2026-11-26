//! NOCTYRA password-based authenticated encryption engine.
//! Engineering baseline only; this is not an audited product.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{aead::{Aead, KeyInit, Payload}, XChaCha20Poly1305, XNonce};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const KEY_LEN: usize = 32;
const MEMORY_KIB: u32 = 64 * 1024;
const ITERATIONS: u32 = 3;
const LANES: u32 = 1;

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("operating-system random generator failed")] Random,
    #[error("invalid Argon2id parameters")] KdfParameters,
    #[error("key derivation failed")] KeyDerivation,
    #[error("encryption failed")] Encryption,
    #[error("authentication failed: password, ciphertext, or metadata is incorrect")] Authentication,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedPayload {
    pub salt: [u8; SALT_LEN],
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

fn derive_key(password: &[u8], salt: &[u8; SALT_LEN]) -> Result<Zeroizing<[u8; KEY_LEN]>, CryptoError> {
    let params = Params::new(MEMORY_KIB, ITERATIONS, LANES, Some(KEY_LEN))
        .map_err(|_| CryptoError::KdfParameters)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0_u8; KEY_LEN]);
    argon2.hash_password_into(password, salt, &mut key[..])
        .map_err(|_| CryptoError::KeyDerivation)?;
    Ok(key)
}

/// Encrypt bytes with a password and authenticated metadata. Fresh salt and nonce per call.
pub fn encrypt(password: &[u8], plaintext: &[u8], associated_data: &[u8]) -> Result<EncryptedPayload, CryptoError> {
    let mut salt = [0_u8; SALT_LEN];
    let mut nonce = [0_u8; NONCE_LEN];
    OsRng.try_fill_bytes(&mut salt).map_err(|_| CryptoError::Random)?;
    OsRng.try_fill_bytes(&mut nonce).map_err(|_| CryptoError::Random)?;
    let key = derive_key(password, &salt)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key[..]).map_err(|_| CryptoError::Encryption)?;
    let ciphertext = cipher.encrypt(XNonce::from_slice(&nonce), Payload { msg: plaintext, aad: associated_data })
        .map_err(|_| CryptoError::Encryption)?;
    Ok(EncryptedPayload { salt, nonce, ciphertext })
}

/// Authenticate and decrypt. Wrong password and tampering share one error.
pub fn decrypt(password: &[u8], payload: &EncryptedPayload, associated_data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let key = derive_key(password, &payload.salt)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key[..]).map_err(|_| CryptoError::Authentication)?;
    cipher.decrypt(XNonce::from_slice(&payload.nonce), Payload {
        msg: &payload.ciphertext,
        aad: associated_data,
    }).map_err(|_| CryptoError::Authentication)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_binary_payload() {
        let plaintext = b"NOCTYRA\0binary\xffpayload";
        let aad = b"NCT-header-v1";
        let encrypted = encrypt(b"correct horse battery staple", plaintext, aad).unwrap();
        assert_eq!(decrypt(b"correct horse battery staple", &encrypted, aad).unwrap(), plaintext);
    }

    #[test]
    fn rejects_wrong_password() {
        let encrypted = encrypt(b"right password", b"secret", b"metadata").unwrap();
        assert!(matches!(decrypt(b"wrong password", &encrypted, b"metadata"), Err(CryptoError::Authentication)));
    }

    #[test]
    fn rejects_ciphertext_and_metadata_tampering() {
        let mut encrypted = encrypt(b"password", b"secret payload", b"metadata").unwrap();
        encrypted.ciphertext[0] ^= 1;
        assert!(matches!(decrypt(b"password", &encrypted, b"metadata"), Err(CryptoError::Authentication)));
        let encrypted = encrypt(b"password", b"secret payload", b"metadata-a").unwrap();
        assert!(matches!(decrypt(b"password", &encrypted, b"metadata-b"), Err(CryptoError::Authentication)));
    }
}


/// A password-derived cipher for a sequence of independently authenticated chunks.
/// Construct once per archive; never derive Argon2id keys per chunk.
pub struct ChunkCipher {
    cipher: XChaCha20Poly1305,
}

impl ChunkCipher {
    pub fn from_password(password: &[u8], salt: &[u8; SALT_LEN]) -> Result<Self, CryptoError> {
        let key = derive_key(password, salt)?;
        let cipher = XChaCha20Poly1305::new_from_slice(&key[..])
            .map_err(|_| CryptoError::Encryption)?;
        Ok(Self { cipher })
    }

    pub fn seal_chunk(&self, nonce: &[u8; NONCE_LEN], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.cipher.encrypt(XNonce::from_slice(nonce), Payload { msg: plaintext, aad })
            .map_err(|_| CryptoError::Encryption)
    }

    pub fn open_chunk(&self, nonce: &[u8; NONCE_LEN], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.cipher.decrypt(XNonce::from_slice(nonce), Payload { msg: ciphertext, aad })
            .map_err(|_| CryptoError::Authentication)
    }
}
