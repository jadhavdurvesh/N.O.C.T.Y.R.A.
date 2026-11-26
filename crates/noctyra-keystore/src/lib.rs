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
    #[error("trust registry is malformed or unsupported")]
    MalformedTrustStore,
    #[error("trusted public key is not a valid Ed25519 key")]
    InvalidTrustedPublicKey,
    #[error("trusted public key is already registered")]
    DuplicateTrustedKey,
    #[error("trusted public key was not found")]
    UnknownTrustedKey,
    #[error("trusted public key has been revoked")]
    RevokedTrustedKey,
    #[error("trust registry has reached its capacity")]
    TrustStoreFull,
    #[error("trust label must contain between 1 and 64 UTF-8 bytes")]
    InvalidTrustLabel,
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

pub const TRUST_STORE_MAGIC: &[u8; 4] = b"NCTS";
pub const TRUST_STORE_VERSION: u16 = 1;
pub const TRUST_STORE_HEADER_LEN: usize = 4 + 2 + 16 + 24 + 4;
pub const MAX_TRUSTED_KEYS: usize = 256;
pub const MAX_TRUST_LABEL_BYTES: usize = 64;
pub const MAX_TRUST_STORE_BYTES: usize = 1024 * 1024;
const TRUST_STORE_DOMAIN: &[u8] = b"NOCTYRA-TRUST-STORE-V1\\0";
const TRUST_DATA_MAGIC: &[u8; 4] = b"NCTD";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustedKey {
    pub public_key: [u8; 32],
    pub label: String,
    pub revoked: bool,
}
impl TrustedKey {
    pub fn fingerprint(&self) -> String { blake3::hash(&self.public_key).to_hex().to_string() }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TrustStore { entries: Vec<TrustedKey> }

impl TrustStore {
    pub fn entries(&self) -> &[TrustedKey] { &self.entries }
    pub fn add(&mut self, public_key: [u8; 32], label: String) -> Result<String, KeyVaultError> {
        VerifyingKey::from_bytes(&public_key).map_err(|_| KeyVaultError::InvalidTrustedPublicKey)?;
        if label.is_empty() || label.len() > MAX_TRUST_LABEL_BYTES { return Err(KeyVaultError::InvalidTrustLabel); }
        if self.entries.iter().any(|entry| entry.public_key == public_key) { return Err(KeyVaultError::DuplicateTrustedKey); }
        if self.entries.len() >= MAX_TRUSTED_KEYS { return Err(KeyVaultError::TrustStoreFull); }
        let fingerprint = blake3::hash(&public_key).to_hex().to_string();
        self.entries.push(TrustedKey { public_key, label, revoked: false });
        Ok(fingerprint)
    }
    pub fn revoke(&mut self, fingerprint: &str) -> Result<(), KeyVaultError> {
        let entry = self.entries.iter_mut().find(|entry| entry.fingerprint() == fingerprint)
            .ok_or(KeyVaultError::UnknownTrustedKey)?;
        entry.revoked = true;
        Ok(())
    }
    pub fn trusted_public_key(&self, fingerprint: &str) -> Result<[u8; 32], KeyVaultError> {
        let entry = self.entries.iter().find(|entry| entry.fingerprint() == fingerprint)
            .ok_or(KeyVaultError::UnknownTrustedKey)?;
        if entry.revoked { return Err(KeyVaultError::RevokedTrustedKey); }
        Ok(entry.public_key)
    }
}

fn trust_store_aad() -> Vec<u8> {
    let mut aad = TRUST_STORE_DOMAIN.to_vec();
    aad.extend_from_slice(TRUST_STORE_MAGIC);
    aad.extend_from_slice(&TRUST_STORE_VERSION.to_le_bytes());
    aad
}

fn encode_trust_entries(store: &TrustStore) -> Result<Zeroizing<Vec<u8>>, KeyVaultError> {
    if store.entries.len() > MAX_TRUSTED_KEYS { return Err(KeyVaultError::TrustStoreFull); }
    let mut data = Zeroizing::new(Vec::new());
    data.extend_from_slice(TRUST_DATA_MAGIC);
    data.extend_from_slice(&1u16.to_le_bytes());
    data.extend_from_slice(&(store.entries.len() as u16).to_le_bytes());
    for entry in &store.entries {
        if entry.label.is_empty() || entry.label.len() > MAX_TRUST_LABEL_BYTES { return Err(KeyVaultError::InvalidTrustLabel); }
        data.extend_from_slice(&entry.public_key);
        data.push(u8::from(entry.revoked));
        data.push(entry.label.len() as u8);
        data.extend_from_slice(entry.label.as_bytes());
    }
    if data.len() > MAX_TRUST_STORE_BYTES - TRUST_STORE_HEADER_LEN - 16 { return Err(KeyVaultError::TrustStoreFull); }
    Ok(data)
}

fn decode_trust_entries(data: &[u8]) -> Result<TrustStore, KeyVaultError> {
    if data.len() < 8 || &data[..4] != TRUST_DATA_MAGIC || u16::from_le_bytes([data[4], data[5]]) != 1 {
        return Err(KeyVaultError::MalformedTrustStore);
    }
    let count = u16::from_le_bytes([data[6], data[7]]) as usize;
    if count > MAX_TRUSTED_KEYS { return Err(KeyVaultError::MalformedTrustStore); }
    let mut cursor = 8usize;
    let mut entries: Vec<TrustedKey> = Vec::with_capacity(count);
    for _ in 0..count {
        let end_key = cursor.checked_add(32).ok_or(KeyVaultError::MalformedTrustStore)?;
        let public_key: [u8; 32] = data.get(cursor..end_key).ok_or(KeyVaultError::MalformedTrustStore)?
            .try_into().map_err(|_| KeyVaultError::MalformedTrustStore)?;
        cursor = end_key;
        let status = *data.get(cursor).ok_or(KeyVaultError::MalformedTrustStore)?;
        cursor += 1;
        if status > 1 { return Err(KeyVaultError::MalformedTrustStore); }
        let label_len = *data.get(cursor).ok_or(KeyVaultError::MalformedTrustStore)? as usize;
        cursor += 1;
        if label_len == 0 || label_len > MAX_TRUST_LABEL_BYTES { return Err(KeyVaultError::MalformedTrustStore); }
        let end_label = cursor.checked_add(label_len).ok_or(KeyVaultError::MalformedTrustStore)?;
        let label = std::str::from_utf8(data.get(cursor..end_label).ok_or(KeyVaultError::MalformedTrustStore)?)
            .map_err(|_| KeyVaultError::MalformedTrustStore)?.to_owned();
        cursor = end_label;
        VerifyingKey::from_bytes(&public_key).map_err(|_| KeyVaultError::MalformedTrustStore)?;
        if entries.iter().any(|entry| entry.public_key == public_key) { return Err(KeyVaultError::MalformedTrustStore); }
        entries.push(TrustedKey { public_key, label, revoked: status == 1 });
    }
    if cursor != data.len() { return Err(KeyVaultError::MalformedTrustStore); }
    Ok(TrustStore { entries })
}

pub fn create_trust_store(password: &[u8]) -> Result<Vec<u8>, KeyVaultError> {
    save_trust_store(password, &TrustStore::default())
}

pub fn open_trust_store(password: &[u8], bytes: &[u8]) -> Result<TrustStore, KeyVaultError> {
    if bytes.len() < TRUST_STORE_HEADER_LEN + 16 || bytes.len() > MAX_TRUST_STORE_BYTES
        || &bytes[..4] != TRUST_STORE_MAGIC
        || u16::from_le_bytes([bytes[4], bytes[5]]) != TRUST_STORE_VERSION {
        return Err(KeyVaultError::MalformedTrustStore);
    }
    let ciphertext_len = u32::from_le_bytes(bytes[46..50].try_into().map_err(|_| KeyVaultError::MalformedTrustStore)?) as usize;
    if ciphertext_len != bytes.len() - TRUST_STORE_HEADER_LEN || ciphertext_len < 16 {
        return Err(KeyVaultError::MalformedTrustStore);
    }
    let mut salt = [0u8; 16]; salt.copy_from_slice(&bytes[6..22]);
    let mut nonce = [0u8; 24]; nonce.copy_from_slice(&bytes[22..46]);
    let encrypted = EncryptedPayload { salt, nonce, ciphertext: bytes[TRUST_STORE_HEADER_LEN..].to_vec() };
    let plaintext = Zeroizing::new(decrypt(password, &encrypted, &trust_store_aad()).map_err(|_| KeyVaultError::Authentication)?);
    decode_trust_entries(&plaintext)
}

pub fn save_trust_store(password: &[u8], store: &TrustStore) -> Result<Vec<u8>, KeyVaultError> {
    if password.is_empty() { return Err(KeyVaultError::Authentication); }
    let plaintext = encode_trust_entries(store)?;
    let encrypted = encrypt(password, &plaintext, &trust_store_aad()).map_err(|_| KeyVaultError::Crypto)?;
    let ciphertext_len = u32::try_from(encrypted.ciphertext.len()).map_err(|_| KeyVaultError::TrustStoreFull)?;
    let mut output = Vec::with_capacity(TRUST_STORE_HEADER_LEN + encrypted.ciphertext.len());
    output.extend_from_slice(TRUST_STORE_MAGIC);
    output.extend_from_slice(&TRUST_STORE_VERSION.to_le_bytes());
    output.extend_from_slice(&encrypted.salt);
    output.extend_from_slice(&encrypted.nonce);
    output.extend_from_slice(&ciphertext_len.to_le_bytes());
    output.extend_from_slice(&encrypted.ciphertext);
    Ok(output)
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
    fn encrypted_trust_store_round_trip_and_revocation() {
        let key = SigningKey::from_bytes(&[21u8; 32]).verifying_key().to_bytes();
        let mut store = TrustStore::default();
        let fingerprint = store.add(key, "test sender".to_owned()).unwrap();
        let bytes = save_trust_store(b"registry password", &store).unwrap();
        let loaded = open_trust_store(b"registry password", &bytes).unwrap();
        assert_eq!(loaded.trusted_public_key(&fingerprint).unwrap(), key);
        assert_eq!(open_trust_store(b"wrong password", &bytes).unwrap_err(), KeyVaultError::Authentication);
        let mut revoked = loaded;
        revoked.revoke(&fingerprint).unwrap();
        assert_eq!(revoked.trusted_public_key(&fingerprint).unwrap_err(), KeyVaultError::RevokedTrustedKey);
        let saved = save_trust_store(b"registry password", &revoked).unwrap();
        let reloaded = open_trust_store(b"registry password", &saved).unwrap();
        assert_eq!(reloaded.entries()[0].revoked, true);
        assert_eq!(reloaded.trusted_public_key(&fingerprint).unwrap_err(), KeyVaultError::RevokedTrustedKey);
    }

    #[test]
    fn rejects_duplicate_trust_entries_and_tampering() {
        let key = SigningKey::from_bytes(&[22u8; 32]).verifying_key().to_bytes();
        let mut store = TrustStore::default();
        store.add(key, "sender".to_owned()).unwrap();
        assert_eq!(store.add(key, "duplicate".to_owned()).unwrap_err(), KeyVaultError::DuplicateTrustedKey);
        let bytes = save_trust_store(b"registry password", &store).unwrap();
        let mut changed = bytes;
        let last = changed.len() - 1;
        changed[last] ^= 1;
        assert_eq!(open_trust_store(b"registry password", &changed).unwrap_err(), KeyVaultError::Authentication);
    }

    #[test]
    fn rejects_malformed_and_unsupported_files() {
        assert_eq!(inspect_vault(b"short").unwrap_err(), KeyVaultError::Malformed);
        let mut vault = create_vault(b"password").unwrap();
        vault[4] = 99;
        assert_eq!(inspect_vault(&vault).unwrap_err(), KeyVaultError::Malformed);
    }
}
