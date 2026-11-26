//! Password-encrypted Ed25519 signing-key vaults.
//!
//! NCKV v1 stores a public key in cleartext and encrypts the 32-byte Ed25519
//! seed with NOCTYRA's Argon2id + XChaCha20-Poly1305 password encryption.
//! The public key and fixed header are authenticated as associated data.
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use noctyra_crypto::{decrypt, encrypt, EncryptedPayload};
use thiserror::Error;
use zeroize::Zeroizing;

pub const VAULT_MAGIC: &[u8; 4] = b"NCKV";
pub const VAULT_VERSION: u16 = 1;
pub const VAULT_HEADER_LEN: usize = 4 + 2 + 1 + 1 + 16 + 24 + 32;
pub const VAULT_CIPHERTEXT_LEN: usize = 32 + 16;
pub const VAULT_FILE_LEN: usize = VAULT_HEADER_LEN + VAULT_CIPHERTEXT_LEN;
const KDF_PROFILE_ARGON2ID_64M_3_1: u8 = 1;
const DOMAIN: &[u8] = b"NOCTYRA-ED25519-KEYVAULT-V1\0";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum KeyVaultError {
    #[error("key vault is truncated, malformed, or uses an unsupported version")]
    Malformed,
    #[error("key vault authentication failed: password or file contents are incorrect")]
    Authentication,
    #[error("key vault public key does not match its encrypted private key")]
    KeyMismatch,
    #[error("cryptographic random generator failed")]
    Random,
    #[error("key vault cryptographic operation failed")]
    Crypto,
}

fn aad(public_key: &[u8; 32]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(DOMAIN.len() + 4 + 2 + 1 + 1 + 32);
    aad.extend_from_slice(DOMAIN);
    aad.extend_from_slice(VAULT_MAGIC);
    aad.extend_from_slice(&VAULT_VERSION.to_le_bytes());
    aad.push(KDF_PROFILE_ARGON2ID_64M_3_1);
    aad.push(0);
    aad.extend_from_slice(public_key);
    aad
}

/// Create a new password-encrypted vault from an OS-random Ed25519 seed.
pub fn create_vault(password: &[u8]) -> Result<Vec<u8>, KeyVaultError> {
    if password.is_empty() { return Err(KeyVaultError::Authentication); }
    let mut seed = Zeroizing::new([0u8; 32]);
    rand_core_fill(&mut seed)?;
    let signing_key = SigningKey::from_bytes(&seed);
    let public_key = signing_key.verifying_key().to_bytes();
    let encrypted = encrypt(password, &seed[..], &aad(&public_key)).map_err(|_| KeyVaultError::Crypto)?;
    encode_vault(&public_key, encrypted)
}

fn rand_core_fill(seed: &mut [u8; 32]) -> Result<(), KeyVaultError> {
    use rand_core::{OsRng, RngCore};
    OsRng.try_fill_bytes(seed).map_err(|_| KeyVaultError::Random)
}

fn encode_vault(public_key: &[u8; 32], encrypted: EncryptedPayload) -> Result<Vec<u8>, KeyVaultError> {
    if encrypted.ciphertext.len() != VAULT_CIPHERTEXT_LEN { return Err(KeyVaultError::Crypto); }
    let mut output = Vec::with_capacity(VAULT_FILE_LEN);
    output.extend_from_slice(VAULT_MAGIC);
    output.extend_from_slice(&VAULT_VERSION.to_le_bytes());
    output.push(KDF_PROFILE_ARGON2ID_64M_3_1);
    output.push(0);
    output.extend_from_slice(&encrypted.salt);
    output.extend_from_slice(&encrypted.nonce);
    output.extend_from_slice(public_key);
    output.extend_from_slice(&encrypted.ciphertext);
    Ok(output)
}

/// Return the public identity and its stable BLAKE3 fingerprint without unlocking.
pub fn inspect_vault(bytes: &[u8]) -> Result<([u8; 32], String), KeyVaultError> {
    if bytes.len() != VAULT_FILE_LEN || &bytes[..4] != VAULT_MAGIC
        || u16::from_le_bytes([bytes[4], bytes[5]]) != VAULT_VERSION
        || bytes[6] != KDF_PROFILE_ARGON2ID_64M_3_1 || bytes[7] != 0 {
        return Err(KeyVaultError::Malformed);
    }
    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(&bytes[48..80]);
    let fingerprint = blake3::hash(&public_key).to_hex().to_string();
    Ok((public_key, fingerprint))
}

/// Unlock a vault. The returned Ed25519 key should be kept only for the
/// shortest possible operation and must never be logged or serialized.
pub fn unlock_vault(password: &[u8], bytes: &[u8]) -> Result<SigningKey, KeyVaultError> {
    let (public_key, _) = inspect_vault(bytes)?;
    let mut salt = [0u8; 16]; salt.copy_from_slice(&bytes[8..24]);
    let mut nonce = [0u8; 24]; nonce.copy_from_slice(&bytes[24..48]);
    let encrypted = EncryptedPayload { salt, nonce, ciphertext: bytes[VAULT_HEADER_LEN..].to_vec() };
    let seed = Zeroizing::new(decrypt(password, &encrypted, &aad(&public_key))
        .map_err(|_| KeyVaultError::Authentication)?);
    let seed: [u8; 32] = seed.as_slice().try_into().map_err(|_| KeyVaultError::Authentication)?;
    let signing_key = SigningKey::from_bytes(&seed);
    if signing_key.verifying_key().to_bytes() != public_key {
        return Err(KeyVaultError::KeyMismatch);
    }
    Ok(signing_key)
}

pub const ROTATION_MAGIC: &[u8; 4] = b"NCRT";
pub const ROTATION_VERSION: u16 = 1;
pub const ROTATION_CERTIFICATE_LEN: usize = 4 + 2 + 32 + 32 + 64;
const ROTATION_DOMAIN: &[u8] = b"NOCTYRA-KEY-ROTATION-V1\\0";

/// A continuity certificate: the currently trusted key authorizes its successor.
pub fn create_rotation_certificate(
    old_key: &SigningKey,
    new_public_key: &[u8; 32],
) -> Vec<u8> {
    let old_public_key = old_key.verifying_key().to_bytes();
    let mut body = Vec::with_capacity(70);
    body.extend_from_slice(ROTATION_MAGIC);
    body.extend_from_slice(&ROTATION_VERSION.to_le_bytes());
    body.extend_from_slice(&old_public_key);
    body.extend_from_slice(new_public_key);
    let mut message = ROTATION_DOMAIN.to_vec();
    message.extend_from_slice(&body);
    let signature = old_key.sign(&message);
    body.extend_from_slice(&signature.to_bytes());
    body
}

/// Verify continuity from an independently trusted old public key.
/// Returns the successor public key; it does not automatically trust it.
pub fn verify_rotation_certificate(
    bytes: &[u8],
    trusted_old_public_key: &[u8; 32],
) -> Result<[u8; 32], KeyVaultError> {
    if bytes.len() != ROTATION_CERTIFICATE_LEN || &bytes[..4] != ROTATION_MAGIC
        || u16::from_le_bytes([bytes[4], bytes[5]]) != ROTATION_VERSION {
        return Err(KeyVaultError::Malformed);
    }
    if &bytes[6..38] != trusted_old_public_key { return Err(KeyVaultError::KeyMismatch); }
    let old_key = ed25519_dalek::VerifyingKey::from_bytes(trusted_old_public_key)
        .map_err(|_| KeyVaultError::Malformed)?;
    let mut new_public_key = [0u8; 32];
    new_public_key.copy_from_slice(&bytes[38..70]);
    let signature = ed25519_dalek::Signature::from_slice(&bytes[70..])
        .map_err(|_| KeyVaultError::Malformed)?;
    let mut message = ROTATION_DOMAIN.to_vec();
    message.extend_from_slice(&bytes[..70]);
    old_key.verify_strict(&message, &signature)
        .map_err(|_| KeyVaultError::Authentication)?;
    Ok(new_public_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_round_trip_and_fingerprint_are_stable() {
        let vault = create_vault(b"a strong test password").unwrap();
        assert_eq!(vault.len(), VAULT_FILE_LEN);
        let (public, fingerprint) = inspect_vault(&vault).unwrap();
        let signing_key = unlock_vault(b"a strong test password", &vault).unwrap();
        assert_eq!(signing_key.verifying_key().to_bytes(), public);
        assert_eq!(fingerprint, blake3::hash(&public).to_hex().to_string());
    }

    #[test]
    fn rejects_wrong_password_and_tampering() {
        let vault = create_vault(b"correct password").unwrap();
        assert_eq!(unlock_vault(b"wrong password", &vault).unwrap_err(), KeyVaultError::Authentication);
        let mut changed = vault.clone();
        changed[79] ^= 1;
        assert_eq!(unlock_vault(b"correct password", &changed).unwrap_err(), KeyVaultError::Authentication);
        let mut changed = vault;
        changed[90] ^= 1;
        assert_eq!(unlock_vault(b"correct password", &changed).unwrap_err(), KeyVaultError::Authentication);
    }

    #[test]
    fn rotation_certificate_requires_trusted_old_key_and_valid_signature() {
        let old = SigningKey::from_bytes(&[11u8; 32]);
        let next = SigningKey::from_bytes(&[12u8; 32]);
        let old_public = old.verifying_key().to_bytes();
        let next_public = next.verifying_key().to_bytes();
        let certificate = create_rotation_certificate(&old, &next_public);
        assert_eq!(certificate.len(), ROTATION_CERTIFICATE_LEN);
        assert_eq!(verify_rotation_certificate(&certificate, &old_public).unwrap(), next_public);

        let attacker = SigningKey::from_bytes(&[13u8; 32]);
        assert_eq!(
            verify_rotation_certificate(&certificate, &attacker.verifying_key().to_bytes()),
            Err(KeyVaultError::KeyMismatch)
        );
        let mut changed = certificate;
        changed[40] ^= 1;
        assert_eq!(
            verify_rotation_certificate(&changed, &old_public),
            Err(KeyVaultError::Authentication)
        );
    }

    #[test]
    fn rejects_malformed_and_unsupported_files() {
        assert_eq!(inspect_vault(b"short").unwrap_err(), KeyVaultError::Malformed);
        let mut vault = create_vault(b"password").unwrap();
        vault[4] = 99;
        assert_eq!(inspect_vault(&vault).unwrap_err(), KeyVaultError::Malformed);
    }
}
