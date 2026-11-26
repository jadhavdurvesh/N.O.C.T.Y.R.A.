use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::Path,
};
use zeroize::Zeroizing;

const MAX_INPUT_BYTES: u64 = 1024 * 1024 * 1024;

fn read_bounded(path: &str) -> Result<Vec<u8>, String> {
    let metadata = fs::metadata(path).map_err(|e| format!("Cannot inspect input: {e}"))?;
    if !metadata.is_file() {
        return Err("Input must be a regular file.".into());
    }
    if metadata.len() > MAX_INPUT_BYTES {
        return Err("Input exceeds the current 1 GiB limit.".into());
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)
        .map_err(|e| format!("Cannot open input: {e}"))?
        .take(MAX_INPUT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("Cannot read input: {e}"))?;
    if bytes.len() as u64 > MAX_INPUT_BYTES {
        return Err("Input grew beyond the configured limit while being read.".into());
    }
    Ok(bytes)
}

fn write_new(path: &str, bytes: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(Path::new(path))
        .map_err(|e| format!("Cannot create output (existing files are never overwritten): {e}"))?;
    if let Err(error) = file.write_all(bytes).and_then(|_| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(format!("Cannot safely finish output: {error}"));
    }
    Ok(())
}

#[tauri::command]
fn encrypt_file(input_path: String, output_path: String, password: String) -> Result<(), String> {
    let password = Zeroizing::new(password);
    if password.is_empty() {
        return Err("Password cannot be empty.".into());
    }
    let input = read_bounded(&input_path)?;
    let archive = noctyra_core::seal_archive(password.as_bytes(), &input)
        .map_err(|e| format!("Encryption failed: {e}"))?;
    write_new(&output_path, &archive)
}

#[tauri::command]
fn decrypt_file(input_path: String, output_path: String, password: String) -> Result<(), String> {
    let password = Zeroizing::new(password);
    if password.is_empty() { return Err("Password cannot be empty.".into()); }
    let archive = read_bounded(&input_path)?;
    let plaintext = noctyra_core::open_archive(password.as_bytes(), &archive)
        .map_err(|e| format!("Archive rejected: {e}"))?;
    write_new(&output_path, &plaintext)
}

#[tauri::command]
fn encrypt_directory(input_path: String, output_path: String, password: String) -> Result<(), String> {
    let password = Zeroizing::new(password);
    if password.is_empty() { return Err("Password cannot be empty.".into()); }
    if Path::new(&output_path).exists() { return Err("Output already exists; refusing to overwrite.".into()); }
    let archive = noctyra_core::seal_directory(password.as_bytes(), &input_path)
        .map_err(|e| format!("Directory archive failed: {e}"))?;
    write_new(&output_path, &archive)
}

#[tauri::command]
fn decrypt_directory(input_path: String, output_path: String, password: String) -> Result<(), String> {
    let password = Zeroizing::new(password);
    if password.is_empty() { return Err("Password cannot be empty.".into()); }
    let archive = read_bounded(&input_path)?;
    noctyra_core::extract_directory(password.as_bytes(), &archive, &output_path)
        .map_err(|e| format!("Directory recovery failed: {e}"))
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![encrypt_file, decrypt_file, encrypt_directory, decrypt_directory])
        .run(tauri::generate_context!())
        .expect("NOCTYRA desktop runtime failed");
}
