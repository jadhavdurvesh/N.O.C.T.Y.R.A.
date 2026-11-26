use std::{
    fs::{self, File, OpenOptions},
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

fn write_new(path: &str, bytes: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(Path::new(path))
        .map_err(|e| format!("Cannot create output (existing files are never overwritten): {e}"))?;
    if let Err(error) = file.write_all(bytes).and_then(|_| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(format!("Cannot safely finish output: {error}"));
    }
    Ok(())
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

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![encrypt_file, decrypt_file, encrypt_directory, decrypt_directory])
        .run(tauri::generate_context!())
        .expect("NOCTYRA desktop runtime failed");
}
