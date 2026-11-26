//! NCT v2 streaming file format.
//!
//! Each independently compressed chunk is authenticated before decompression.
//! A final authenticated record commits the chunk count, total plaintext size,
//! and BLAKE3 digest, detecting truncation, reordering and incomplete writes.
//! Decryption streams plaintext to the supplied writer before the final record
//! is verified. Callers MUST write to a temporary file and publish it only after
//! this function returns Ok; discard the temporary output on every error.

use std::io::{Read, Write};
use rand_core::{OsRng, RngCore};
use zeroize::{Zeroize, Zeroizing};
use noctyra_crypto::ChunkCipher;
use crate::ContainerError;

const MAGIC: &[u8; 4] = b"NCTY";
const VERSION: u16 = 2;
const SALT_LEN: usize = 16;
const PREFIX_LEN: usize = 16;
const HEADER_LEN: usize = 4 + 2 + SALT_LEN + PREFIX_LEN + 4 + 1;
const RECORD_HEADER_LEN: usize = 8 + 4 + 4;
const TAG_LEN: usize = 16;
const FINAL_PLAINTEXT_LEN: usize = 8 + 8 + 32;
const FINAL_CIPHERTEXT_LEN: usize = FINAL_PLAINTEXT_LEN + TAG_LEN;
const COMPRESSION_ZSTD: u8 = 1;

/// Fixed maximum plaintext held for each chunk (1 MiB).
pub const STREAM_CHUNK_SIZE: usize = 1024 * 1024;

fn io_error(error: std::io::Error) -> ContainerError { ContainerError::Io(error.to_string()) }

fn nonce_for(prefix: &[u8; PREFIX_LEN], index: u64) -> [u8; 24] {
    let mut nonce = [0u8; 24];
    nonce[..PREFIX_LEN].copy_from_slice(prefix);
    nonce[PREFIX_LEN..].copy_from_slice(&index.to_le_bytes());
    nonce
}

fn read_exact<R: Read>(reader: &mut R, buffer: &mut [u8]) -> Result<(), ContainerError> {
    reader.read_exact(buffer).map_err(|_| ContainerError::Malformed)
}

fn read_chunk<R: Read>(reader: &mut R, buffer: &mut [u8]) -> Result<usize, ContainerError> {
    let mut filled = 0;
    while filled < buffer.len() {
        match reader.read(&mut buffer[filled..]).map_err(io_error)? {
            0 => break,
            count => filled += count,
        }
    }
    Ok(filled)
}

fn make_header(salt: &[u8; SALT_LEN], prefix: &[u8; PREFIX_LEN]) -> Vec<u8> {
    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(MAGIC);
    header.extend_from_slice(&VERSION.to_le_bytes());
    header.extend_from_slice(salt);
    header.extend_from_slice(prefix);
    header.extend_from_slice(&(STREAM_CHUNK_SIZE as u32).to_le_bytes());
    header.push(COMPRESSION_ZSTD);
    header
}

/// Encrypt a reader into an NCT v2 streaming archive using bounded 1 MiB chunks.
pub fn encrypt_stream<R: Read, W: Write>(password: &[u8], mut reader: R, mut writer: W) -> Result<(), ContainerError> {
    let mut salt = [0u8; SALT_LEN];
    let mut prefix = [0u8; PREFIX_LEN];
    OsRng.try_fill_bytes(&mut salt).map_err(|_| ContainerError::Random)?;
    OsRng.try_fill_bytes(&mut prefix).map_err(|_| ContainerError::Random)?;

    let cipher = ChunkCipher::from_password(password, &salt)?;
    let header = make_header(&salt, &prefix);
    writer.write_all(&header).map_err(io_error)?;

    let mut plaintext = Zeroizing::new(vec![0u8; STREAM_CHUNK_SIZE]);
    let mut index = 0u64;
    let mut total_plain = 0u64;
    let mut digest = blake3::Hasher::new();

    loop {
        let length = read_chunk(&mut reader, &mut plaintext)?;
        if length == 0 { break; }
        if index == u64::MAX { return Err(ContainerError::TooLarge); }

        let chunk = &plaintext[..length];
        digest.update(chunk);
        let compressed = Zeroizing::new(zstd::bulk::compress(chunk, 3)
            .map_err(|error| ContainerError::Compression(error.to_string()))?);
        if compressed.len() > STREAM_CHUNK_SIZE + STREAM_CHUNK_SIZE / 8 + 1024 {
            return Err(ContainerError::TooLarge);
        }

        let mut record = Vec::with_capacity(RECORD_HEADER_LEN);
        record.extend_from_slice(&index.to_le_bytes());
        record.extend_from_slice(&(length as u32).to_le_bytes());
        record.extend_from_slice(&(compressed.len() as u32).to_le_bytes());

        let mut aad = Vec::with_capacity(header.len() + 4 + record.len());
        aad.extend_from_slice(&header);
        aad.extend_from_slice(b"CHNK");
        aad.extend_from_slice(&record);
        let nonce = nonce_for(&prefix, index);
        let encrypted = cipher.seal_chunk(&nonce, &aad, &compressed)?;

        writer.write_all(b"CHNK").map_err(io_error)?;
        writer.write_all(&record).map_err(io_error)?;
        writer.write_all(&encrypted).map_err(io_error)?;

        total_plain = total_plain.checked_add(length as u64).ok_or(ContainerError::TooLarge)?;
        index = index.checked_add(1).ok_or(ContainerError::TooLarge)?;
        plaintext[..length].zeroize();
    }

    let mut final_plain = Zeroizing::new([0u8; FINAL_PLAINTEXT_LEN]);
    final_plain[..8].copy_from_slice(&index.to_le_bytes());
    final_plain[8..16].copy_from_slice(&total_plain.to_le_bytes());
    final_plain[16..].copy_from_slice(digest.finalize().as_bytes());

    let mut final_aad = Vec::with_capacity(header.len() + 4);
    final_aad.extend_from_slice(&header);
    final_aad.extend_from_slice(b"FINL");
    let nonce = nonce_for(&prefix, index);
    let final_ciphertext = cipher.seal_chunk(&nonce, &final_aad, &final_plain[..])?;
    writer.write_all(b"FINL").map_err(io_error)?;
    writer.write_all(&final_ciphertext).map_err(io_error)?;
    writer.flush().map_err(io_error)?;
    Ok(())
}

/// Decrypt an NCT v2 archive. Always use a temporary destination and discard it
/// on error: plaintext may be written before the authenticated final record.
pub fn decrypt_stream<R: Read, W: Write>(password: &[u8], mut reader: R, mut writer: W) -> Result<(), ContainerError> {
    let mut header = [0u8; HEADER_LEN];
    read_exact(&mut reader, &mut header)?;
    if &header[..4] != MAGIC { return Err(ContainerError::Malformed); }
    let version = u16::from_le_bytes([header[4], header[5]]);
    if version != VERSION { return Err(ContainerError::UnsupportedVersion(version)); }

    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&header[6..22]);
    let mut prefix = [0u8; PREFIX_LEN];
    prefix.copy_from_slice(&header[22..38]);
    let chunk_size = u32::from_le_bytes(header[38..42].try_into().map_err(|_| ContainerError::Malformed)?) as usize;
    if chunk_size != STREAM_CHUNK_SIZE || header[42] != COMPRESSION_ZSTD { return Err(ContainerError::Malformed); }

    let cipher = ChunkCipher::from_password(password, &salt)?;
    let mut expected_index = 0u64;
    let mut total_plain = 0u64;
    let mut digest = blake3::Hasher::new();

    loop {
        let mut marker = [0u8; 4];
        read_exact(&mut reader, &mut marker)?;
        if &marker == b"CHNK" {
            let mut record = [0u8; RECORD_HEADER_LEN];
            read_exact(&mut reader, &mut record)?;
            let index = u64::from_le_bytes(record[..8].try_into().map_err(|_| ContainerError::Malformed)?);
            let plain_len = u32::from_le_bytes(record[8..12].try_into().map_err(|_| ContainerError::Malformed)?) as usize;
            let compressed_len = u32::from_le_bytes(record[12..16].try_into().map_err(|_| ContainerError::Malformed)?) as usize;

            if index != expected_index || plain_len == 0 || plain_len > STREAM_CHUNK_SIZE
                || compressed_len == 0 || compressed_len > STREAM_CHUNK_SIZE + STREAM_CHUNK_SIZE / 8 + 1024 {
                return Err(ContainerError::Malformed);
            }
            let ciphertext_len = compressed_len.checked_add(TAG_LEN).ok_or(ContainerError::TooLarge)?;
            let mut ciphertext = Zeroizing::new(vec![0u8; ciphertext_len]);
            read_exact(&mut reader, &mut ciphertext)?;

            let mut aad = Vec::with_capacity(header.len() + 4 + record.len());
            aad.extend_from_slice(&header);
            aad.extend_from_slice(b"CHNK");
            aad.extend_from_slice(&record);
            let nonce = nonce_for(&prefix, index);
            let compressed = Zeroizing::new(cipher.open_chunk(&nonce, &aad, &ciphertext)?);
            if compressed.len() != compressed_len { return Err(ContainerError::Malformed); }

            let plaintext = Zeroizing::new(zstd::bulk::decompress(&compressed, plain_len)
                .map_err(|_| ContainerError::Compression("invalid or oversized compressed chunk".into()))?);
            if plaintext.len() != plain_len { return Err(ContainerError::Malformed); }
            digest.update(&plaintext);
            writer.write_all(&plaintext).map_err(io_error)?;
            total_plain = total_plain.checked_add(plain_len as u64).ok_or(ContainerError::TooLarge)?;
            expected_index = expected_index.checked_add(1).ok_or(ContainerError::TooLarge)?;
        } else if &marker == b"FINL" {
            let mut ciphertext = [0u8; FINAL_CIPHERTEXT_LEN];
            read_exact(&mut reader, &mut ciphertext)?;
            let mut aad = Vec::with_capacity(header.len() + 4);
            aad.extend_from_slice(&header);
            aad.extend_from_slice(b"FINL");
            let nonce = nonce_for(&prefix, expected_index);
            let final_plain = Zeroizing::new(cipher.open_chunk(&nonce, &aad, &ciphertext)?);

            let declared_count = u64::from_le_bytes(final_plain[..8].try_into().map_err(|_| ContainerError::Malformed)?);
            let declared_total = u64::from_le_bytes(final_plain[8..16].try_into().map_err(|_| ContainerError::Malformed)?);
            if declared_count != expected_index || declared_total != total_plain
                || final_plain[16..] != digest.finalize().as_bytes()[..] {
                return Err(ContainerError::Integrity);
            }
            let mut trailing = [0u8; 1];
            if reader.read(&mut trailing).map_err(io_error)? != 0 { return Err(ContainerError::Malformed); }
            writer.flush().map_err(io_error)?;
            return Ok(());
        } else {
            return Err(ContainerError::Malformed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn streaming_round_trip_empty_and_multi_chunk() {
        for input in [Vec::new(), vec![b'a'; STREAM_CHUNK_SIZE * 2 + 173]] {
            let mut archive = Vec::new();
            encrypt_stream(b"stream test password", Cursor::new(&input), &mut archive).unwrap();
            let mut recovered = Vec::new();
            decrypt_stream(b"stream test password", Cursor::new(&archive), &mut recovered).unwrap();
            assert_eq!(recovered, input);
        }
    }

    #[test]
    fn rejects_wrong_password() {
        let mut archive = Vec::new();
        encrypt_stream(b"correct", Cursor::new(b"payload"), &mut archive).unwrap();
        let mut recovered = Vec::new();
        assert!(matches!(decrypt_stream(b"incorrect", Cursor::new(&archive), &mut recovered), Err(ContainerError::Crypto(_))));
    }

    #[test]
    fn rejects_truncation_and_trailing_bytes() {
        let mut archive = Vec::new();
        encrypt_stream(b"password", Cursor::new(b"payload"), &mut archive).unwrap();
        let mut recovered = Vec::new();
        assert!(decrypt_stream(b"password", Cursor::new(&archive[..archive.len()-1]), &mut recovered).is_err());
        archive.push(0);
        let mut recovered = Vec::new();
        assert!(matches!(decrypt_stream(b"password", Cursor::new(&archive), &mut recovered), Err(ContainerError::Malformed)));
    }

    #[test]
    fn rejects_chunk_tampering() {
        let mut archive = Vec::new();
        encrypt_stream(b"password", Cursor::new(b"payload"), &mut archive).unwrap();
        let marker = HEADER_LEN + 4 + RECORD_HEADER_LEN;
        archive[marker] ^= 1;
        let mut recovered = Vec::new();
        assert!(matches!(decrypt_stream(b"password", Cursor::new(&archive), &mut recovered), Err(ContainerError::Crypto(_))));
    }
}
