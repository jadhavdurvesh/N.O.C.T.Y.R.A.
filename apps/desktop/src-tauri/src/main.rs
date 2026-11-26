use std::{
    fs::{self, File},
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
};
use zeroize::Zeroizing;

const MAX_INPUT_BYTES: u64 = 1024 * 1024 * 1024;

fn read_bounded(path: &str) -> Result<Vec<u8>, String> {
    let metadata = fs::metadata(path).map_err(|e| format!("Cannot inspect input: {e}"))?;
    if !metadata.is_file() { return Err("Input must be a regular file.".into()); }
    if metadata.len() > MAX_INPUT_BYTES { return Err("Input exceeds the current 1 GiB limit.".into()); }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path).map_err(|e| format!("Cannot open input: {e}"))?
        .take(MAX_INPUT_BYTES + 1).read_to_end(&mut bytes)
        .map_err(|e| format!("Cannot read input: {e}"))?;
    if bytes.len() as u64 > MAX_INPUT_BYTES { return Err("Input grew beyond the configured limit while being read.".into()); }
    Ok(bytes)
}

fn temporary_output(path: &str) -> Result<tempfile::NamedTempFile, String> {
    let output = Path::new(path);
    let parent = output.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    tempfile::NamedTempFile::new_in(parent).map_err(|e| format!("Cannot create temporary output: {e}"))
}

fn publish(temp: tempfile::NamedTempFile, path: &str) -> Result<(), String> {
    temp.as_file().sync_all().map_err(|e| format!("Cannot flush temporary output: {e}"))?;
    temp.persist_noclobber(Path::new(path)).map_err(|e| format!("Cannot publish output without overwriting: {}", e.error))?;
    Ok(())
}

fn validate_stream_input(path: &str) -> Result<File, String> {
    let metadata = fs::symlink_metadata(path).map_err(|e| format!("Cannot inspect input: {e}"))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err("Input must be a regular file, not a symbolic link.".into());
    }
    File::open(path).map_err(|e| format!("Cannot open input: {e}"))
}

#[tauri::command]
fn encrypt_file(input_path: String, output_path: String, password: String) -> Result<(), String> {
    let password = Zeroizing::new(password);
    if password.is_empty() { return Err("Password cannot be empty.".into()); }
    let input = validate_stream_input(&input_path)?;
    let mut temp = temporary_output(&output_path)?;
    noctyra_core::encrypt_stream(password.as_bytes(), input, temp.as_file_mut())
        .map_err(|e| format!("Streaming encryption failed: {e}"))?;
    publish(temp, &output_path)
}

#[tauri::command]
fn decrypt_file(input_path: String, output_path: String, password: String) -> Result<(), String> {
    let password = Zeroizing::new(password);
    if password.is_empty() { return Err("Password cannot be empty.".into()); }
    let mut input = validate_stream_input(&input_path)?;
    let mut prefix = [0u8; 6];
    input.read_exact(&mut prefix).map_err(|_| "Archive header is truncated.".to_string())?;
    input.seek(SeekFrom::Start(0)).map_err(|e| format!("Cannot seek archive: {e}"))?;
    let version = u16::from_le_bytes([prefix[4], prefix[5]]);
    let mut temp = temporary_output(&output_path)?;

    match version {
        2 => noctyra_core::decrypt_stream(password.as_bytes(), input, temp.as_file_mut())
            .map_err(|e| format!("Streaming archive rejected: {e}"))?,
        1 => {
            let archive = Zeroizing::new(read_bounded(&input_path)?);
            let plaintext = Zeroizing::new(noctyra_core::open_archive(password.as_bytes(), &archive)
                .map_err(|e| format!("Archive rejected: {e}"))?);
            temp.as_file_mut().write_all(&plaintext).map_err(|e| format!("Cannot write recovered file: {e}"))?;
        }
        other => return Err(format!("Unsupported NCT archive version: {other}")),
    }
    publish(temp, &output_path)
}

#[tauri::command]
fn encrypt_directory(input_path: String, output_path: String, password: String) -> Result<(), String> {
    let password = Zeroizing::new(password);
    if password.is_empty() { return Err("Password cannot be empty.".into()); }
    if Path::new(&output_path).exists() { return Err("Output already exists; refusing to overwrite.".into()); }
    let mut temp = temporary_output(&output_path)?;
    noctyra_core::encrypt_directory_stream(password.as_bytes(), &input_path, temp.as_file_mut())
        .map_err(|e| format!("Streaming directory archive failed: {e}"))?;
    publish(temp, &output_path)
}

#[tauri::command]
fn decrypt_directory(input_path: String, output_path: String, password: String) -> Result<(), String> {
    let password = Zeroizing::new(password);
    if password.is_empty() { return Err("Password cannot be empty.".into()); }
    let mut input = validate_stream_input(&input_path)?;
    let mut prefix = [0u8; 6];
    input.read_exact(&mut prefix).map_err(|_| "Archive header is truncated.".to_string())?;
    input.seek(SeekFrom::Start(0)).map_err(|e| format!("Cannot seek archive: {e}"))?;
    match u16::from_le_bytes([prefix[4], prefix[5]]) {
        2 => noctyra_core::decrypt_directory_stream(password.as_bytes(), input, &output_path)
            .map_err(|e| format!("Streaming directory recovery failed: {e}")),
        1 => {
            let archive = Zeroizing::new(read_bounded(&input_path)?);
            noctyra_core::extract_directory(password.as_bytes(), &archive, &output_path)
                .map_err(|e| format!("Legacy directory recovery failed: {e}"))
        }
        other => Err(format!("Unsupported NCT directory archive version: {other}")),
    }
}


#[tauri::command]
fn cleanup_staging(parent_path: String) -> Result<usize, String> {
    noctyra_core::cleanup_stale_staging(&parent_path)
        .map_err(|e| format!("Staging recovery cleanup failed: {e}"))
}


fn read_carrier(path: &str) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path).map_err(|e| format!("Cannot inspect carrier: {e}"))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err("Carrier must be a regular file, not a symbolic link.".into());
    }
    if metadata.len() > 64 * 1024 * 1024 {
        return Err("Carrier image exceeds the 64 MiB input limit.".into());
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path).map_err(|e| format!("Cannot open carrier: {e}"))?
        .take(64 * 1024 * 1024 + 1).read_to_end(&mut bytes)
        .map_err(|e| format!("Cannot read carrier: {e}"))?;
    if bytes.len() > 64 * 1024 * 1024 { return Err("Carrier image grew beyond the input limit.".into()); }
    Ok(bytes)
}

#[tauri::command]
fn conceal_archive(archive_path: String, carrier_path: String, output_path: String) -> Result<usize, String> {
    let archive = Zeroizing::new(read_bounded(&archive_path)?);
    if archive.len() < 6 || &archive[..4] != b"NCTY" || !matches!(u16::from_le_bytes([archive[4], archive[5]]), 1 | 2) {
        return Err("Select a valid encrypted NCT archive first.".into());
    }
    let carrier_bytes = Zeroizing::new(read_carrier(&carrier_path)?);
    let mut carrier = noctyra_core::CarrierImage::load(&carrier_bytes)
        .map_err(|e| format!("Cannot decode carrier image: {e}"))?;
    let capacity = noctyra_core::estimate_carrier_capacity(&carrier);
    let required = archive.len().saturating_add(45);
    if required > capacity.total_bytes {
        return Err(format!("Image capacity is insufficient: archive needs {required} bytes, available capacity is {} bytes. Use a larger PNG/BMP image or split the archive into transfer parts.", capacity.total_bytes));
    }
    noctyra_core::embed_carrier(&mut carrier, &archive)
        .map_err(|e| format!("Cannot embed encrypted archive: {e}"))?;
    let encoded = Zeroizing::new(carrier.encode(carrier.format())
        .map_err(|e| format!("Cannot encode carrier image: {e}"))?);
    let mut temp = temporary_output(&output_path)?;
    temp.as_file_mut().write_all(&encoded).map_err(|e| format!("Cannot write concealed image: {e}"))?;
    publish(temp, &output_path)?;
    Ok(archive.len())
}

#[tauri::command]
fn reveal_archive(carrier_path: String, output_path: String) -> Result<usize, String> {
    let carrier_bytes = Zeroizing::new(read_carrier(&carrier_path)?);
    let carrier = noctyra_core::CarrierImage::load(&carrier_bytes)
        .map_err(|e| format!("Cannot decode carrier image: {e}"))?;
    let archive = Zeroizing::new(noctyra_core::extract_carrier(&carrier)
        .map_err(|e| format!("No valid NOCTYRA payload found: {e}"))?);
    if archive.len() < 6 || &archive[..4] != b"NCTY" || !matches!(u16::from_le_bytes([archive[4], archive[5]]), 1 | 2) {
        return Err("Embedded payload is not a supported encrypted NCT archive.".into());
    }
    let mut temp = temporary_output(&output_path)?;
    temp.as_file_mut().write_all(&archive).map_err(|e| format!("Cannot write extracted archive: {e}"))?;
    publish(temp, &output_path)?;
    Ok(archive.len())
}

#[tauri::command]
fn constellation_split(archive_path: String, output_directory: String, fragment_bytes: usize) -> Result<Vec<String>, String> {
    if !(1024..=noctyra_core::MAX_FRAGMENT_DATA_BYTES).contains(&fragment_bytes) {
        return Err("Choose a part size between 1 KiB and 8 MiB.".into());
    }
    let archive = Zeroizing::new(read_bounded(&archive_path)?);
    if archive.len() < 6 || &archive[..4] != b"NCTY" || !matches!(u16::from_le_bytes([archive[4], archive[5]]), 1 | 2) {
        return Err("Select a valid encrypted NCT archive first.".into());
    }
    let destination = Path::new(&output_directory);
    if destination.exists() { return Err("The selected transfer folder already exists. Choose a new folder name.".into()); }
    let fragments = noctyra_core::fragment_archive(&archive, fragment_bytes)
        .map_err(|e| format!("Cannot split archive: {e}"))?;
    fs::create_dir_all(destination).map_err(|e| format!("Cannot create transfer folder: {e}"))?;
    let mut created = Vec::new();
    for (index, frame) in fragments.iter().enumerate() {
        let path = destination.join(format!("NOCTYRA-PART-{:04}.ncfr", index + 1));
        let write_result = (|| -> Result<(), String> {
            let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(&path)
                .map_err(|e| format!("Cannot create transfer part: {e}"))?;
            file.write_all(frame).map_err(|e| format!("Cannot write transfer part: {e}"))?;
            file.sync_all().map_err(|e| format!("Cannot flush transfer part: {e}"))?;
            Ok(())
        })();
        if let Err(error) = write_result {
            let _ = fs::remove_dir_all(destination);
            return Err(error);
        }
        created.push(path.to_string_lossy().into_owned());
    }
    Ok(created)
}

#[tauri::command]
fn constellation_join(fragment_paths: Vec<String>, output_path: String) -> Result<usize, String> {
    if fragment_paths.is_empty() { return Err("Select all parts belonging to one transfer.".into()); }
    if fragment_paths.len() > noctyra_core::MAX_FRAGMENT_COUNT { return Err("Too many transfer parts were selected.".into()); }
    let mut frames = Vec::with_capacity(fragment_paths.len());
    for path in &fragment_paths {
        let metadata = fs::symlink_metadata(path).map_err(|e| format!("Cannot inspect transfer part: {e}"))?;
        if !metadata.is_file() || metadata.file_type().is_symlink() { return Err("Transfer parts must be regular files.".into()); }
        let limit = (noctyra_core::MAX_FRAGMENT_DATA_BYTES + noctyra_core::FRAGMENT_HEADER_LEN) as u64;
        if metadata.len() > limit { return Err("A transfer part exceeds the configured size limit.".into()); }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        File::open(path).map_err(|e| format!("Cannot open transfer part: {e}"))?
            .take(limit + 1).read_to_end(&mut bytes).map_err(|e| format!("Cannot read transfer part: {e}"))?;
        if bytes.len() as u64 > limit { return Err("A transfer part grew beyond the configured size limit.".into()); }
        frames.push(bytes);
    }
    let references: Vec<&[u8]> = frames.iter().map(Vec::as_slice).collect();
    let archive = Zeroizing::new(noctyra_core::reassemble_fragments(references)
        .map_err(|e| format!("Transfer parts could not be reassembled: {e}"))?);
    let mut temp = temporary_output(&output_path)?;
    temp.as_file_mut().write_all(&archive).map_err(|e| format!("Cannot write reassembled archive: {e}"))?;
    publish(temp, &output_path)?;
    Ok(archive.len())
}


fn read_recovery_key(path: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    let metadata = fs::symlink_metadata(path).map_err(|e| format!("Cannot inspect recovery key: {e}"))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() != 32 {
        return Err("Recovery key must be a regular 32-byte file.".into());
    }
    let mut key = Zeroizing::new(Vec::with_capacity(32));
    File::open(path).map_err(|e| format!("Cannot open recovery key: {e}"))?
        .take(33).read_to_end(&mut key).map_err(|e| format!("Cannot read recovery key: {e}"))?;
    if key.len() != 32 { return Err("Recovery key must contain exactly 32 bytes.".into()); }
    Ok(key)
}

#[tauri::command]
fn generate_recovery_key(output_path: String) -> Result<(), String> {
    use rand_core::RngCore;
    let mut key = Zeroizing::new([0u8; 32]);
    rand_core::OsRng.try_fill_bytes(&mut key[..])
        .map_err(|_| "Operating-system random generator failed.".to_string())?;
    let mut temp = temporary_output(&output_path)?;
    temp.as_file_mut().write_all(&key[..]).map_err(|e| format!("Cannot write recovery key: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        temp.as_file().set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("Cannot restrict recovery-key permissions: {e}"))?;
    }
    temp.as_file().sync_all().map_err(|e| format!("Cannot flush recovery key: {e}"))?;
    temp.persist_noclobber(Path::new(&output_path))
        .map_err(|e| format!("Cannot publish recovery key without overwriting: {}", e.error))?;
    Ok(())
}

#[tauri::command]
fn encrypt_file_with_recovery_key(input_path: String, output_path: String, key_path: String) -> Result<(), String> {
    let key = read_recovery_key(&key_path)?;
    let input = validate_stream_input(&input_path)?;
    let mut temp = temporary_output(&output_path)?;
    noctyra_core::encrypt_stream(&key, input, temp.as_file_mut())
        .map_err(|e| format!("Recovery-key encryption failed: {e}"))?;
    publish(temp, &output_path)
}

#[tauri::command]
fn decrypt_file_with_recovery_key(input_path: String, output_path: String, key_path: String) -> Result<(), String> {
    let key = read_recovery_key(&key_path)?;
    let mut input = validate_stream_input(&input_path)?;
    let mut prefix = [0u8; 6];
    input.read_exact(&mut prefix).map_err(|_| "Archive header is truncated.".to_string())?;
    input.seek(SeekFrom::Start(0)).map_err(|e| format!("Cannot seek archive: {e}"))?;
    let mut temp = temporary_output(&output_path)?;
    match u16::from_le_bytes([prefix[4], prefix[5]]) {
        2 => noctyra_core::decrypt_stream(&key, input, temp.as_file_mut())
            .map_err(|e| format!("Recovery-key authentication failed: {e}"))?,
        1 => {
            let archive = Zeroizing::new(read_bounded(&input_path)?);
            let plaintext = Zeroizing::new(noctyra_core::open_archive(&key, &archive)
                .map_err(|e| format!("Recovery-key authentication failed: {e}"))?);
            temp.as_file_mut().write_all(&plaintext)
                .map_err(|e| format!("Cannot write recovered file: {e}"))?;
        }
        other => return Err(format!("Unsupported NCT archive version: {other}")),
    }
    publish(temp, &output_path)
}


fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![encrypt_file, decrypt_file, encrypt_directory, decrypt_directory, cleanup_staging, conceal_archive, reveal_archive, constellation_split, constellation_join, generate_recovery_key, encrypt_file_with_recovery_key, decrypt_file_with_recovery_key])
        .run(tauri::generate_context!())
        .expect("NOCTYRA desktop runtime failed");
}
