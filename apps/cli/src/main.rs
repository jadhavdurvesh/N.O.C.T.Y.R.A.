use std::{
    env,
    error::Error,
    fs::{self, File},
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
};
use zeroize::Zeroizing;

const MAX_INPUT_BYTES: u64 = 1024 * 1024 * 1024;

fn main() {
    if let Err(error) = run() {
        eprintln!("NOCTYRA ERROR: {error}");
        std::process::exit(1);
    }
}

fn password(confirm: bool) -> Result<Zeroizing<String>, Box<dyn Error>> {
    let value = Zeroizing::new(rpassword::prompt_password("NOCTYRA password: ")?);
    if value.is_empty() { return Err("password must not be empty".into()); }
    if confirm {
        let again = Zeroizing::new(rpassword::prompt_password("Confirm password: ")?);
        if value.as_bytes() != again.as_bytes() { return Err("password confirmation did not match".into()); }
    }
    Ok(value)
}

fn check_regular_file(path: &Path) -> Result<(), Box<dyn Error>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err("input must be a regular file, not a symbolic link".into());
    }
    Ok(())
}

fn read_limited(path: &Path, limit: u64, label: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    check_regular_file(path)?;
    let metadata = fs::metadata(path)?;
    if metadata.len() > limit { return Err(format!("{label} exceeds the configured size limit").into()); }
    let capacity = usize::try_from(metadata.len())?;
    let mut bytes = Vec::with_capacity(capacity);
    File::open(path)?.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit { return Err(format!("{label} grew beyond the configured size limit while being read").into()); }
    Ok(bytes)
}

fn read_bounded(path: &Path) -> Result<Vec<u8>, Box<dyn Error>> {
    read_limited(path, MAX_INPUT_BYTES, "input")
}

fn read_carrier_file(path: &Path) -> Result<Vec<u8>, Box<dyn Error>> {
    check_regular_file(path)?;
    let metadata = fs::metadata(path)?;
    let limit = 64 * 1024 * 1024u64;
    if metadata.len() > limit { return Err("carrier image exceeds the 64 MiB input limit".into()); }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)?.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit { return Err("carrier image grew beyond the 64 MiB input limit while being read".into()); }
    Ok(bytes)
}

fn temporary_output(path: &Path) -> Result<tempfile::NamedTempFile, Box<dyn Error>> {
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    Ok(tempfile::NamedTempFile::new_in(parent)?)
}

fn publish(temp: tempfile::NamedTempFile, path: &Path) -> Result<(), Box<dyn Error>> {
    temp.as_file().sync_all()?;
    temp.persist_noclobber(path).map_err(|e| e.error)?;
    Ok(())
}

fn encrypt_file(input: &Path, output: &Path, password: &[u8]) -> Result<(), Box<dyn Error>> {
    check_regular_file(input)?;
    let source = File::open(input)?;
    let mut temp = temporary_output(output)?;
    noctyra_core::encrypt_stream(password, source, temp.as_file_mut())?;
    publish(temp, output)
}

fn decrypt_file(input: &Path, output: &Path, password: &[u8]) -> Result<(), Box<dyn Error>> {
    check_regular_file(input)?;
    let mut source = File::open(input)?;
    let mut prefix = [0u8; 6];
    source.read_exact(&mut prefix)?;
    source.seek(SeekFrom::Start(0))?;
    let version = u16::from_le_bytes([prefix[4], prefix[5]]);
    let mut temp = temporary_output(output)?;

    match version {
        2 => noctyra_core::decrypt_stream(password, source, temp.as_file_mut())?,
        1 => {
            // Backward compatibility for the original single-record NCT v1 format.
            let archive = Zeroizing::new(read_bounded(input)?);
            let plaintext = Zeroizing::new(noctyra_core::open_archive(password, &archive)?);
            temp.as_file_mut().write_all(&plaintext)?;
        }
        other => return Err(format!("unsupported NCT archive version: {other}").into()),
    }
    publish(temp, output)
}

fn run() -> Result<(), Box<dyn Error>> {
    let mut args = env::args_os().skip(1);
    let command = args.next().ok_or("missing command")?;
    let command = command.to_string_lossy().into_owned();
    let paths: Vec<_> = args.collect();

    if command == "cleanup-staging" {
        if paths.len() != 1 { return Err("usage: noctyra cleanup-staging <parent-directory>".into()); }
        let removed = noctyra_core::cleanup_stale_staging(Path::new(&paths[0]))?;
        println!("Removed {removed} stale NOCTYRA staging director(y/ies).");
        return Ok(());
    }

    if command == "carrier-embed" {
        if paths.len() != 3 { return Err("usage: noctyra carrier-embed <carrier-image> <encrypted-archive.nct> <output-image>".into()); }
        let image_bytes = Zeroizing::new(read_carrier_file(Path::new(&paths[0]))?);
        let archive_bytes = Zeroizing::new(read_limited(Path::new(&paths[1]), 16 * 1024 * 1024, "encrypted archive payload")?);
        if archive_bytes.len() < 6 || &archive_bytes[..4] != b"NCTY" {
            return Err("carrier payload must be a valid NOCTYRA NCT archive".into());
        }
        let archive_version = u16::from_le_bytes([archive_bytes[4], archive_bytes[5]]);
        if !matches!(archive_version, 1 | 2) { return Err("unsupported NCT archive version for carrier embedding".into()); }
        let mut carrier = noctyra_core::CarrierImage::load(&image_bytes)?;
        noctyra_core::embed_carrier(&mut carrier, &archive_bytes)?;
        let encoded = Zeroizing::new(carrier.encode(carrier.format())?);
        let output = Path::new(&paths[2]);
        let mut temp = temporary_output(output)?;
        temp.as_file_mut().write_all(&encoded)?;
        publish(temp, output)?;
        println!("Encrypted archive embedded in carrier image: {}", output.display());
        return Ok(());
    }

    if command == "carrier-extract" {
        if paths.len() != 2 { return Err("usage: noctyra carrier-extract <carrier-image> <output-archive.nct>".into()); }
        let image_bytes = Zeroizing::new(read_carrier_file(Path::new(&paths[0]))?);
        let carrier = noctyra_core::CarrierImage::load(&image_bytes)?;
        let payload = Zeroizing::new(noctyra_core::extract_carrier(&carrier)?);
        let output = Path::new(&paths[1]);
        let mut temp = temporary_output(output)?;
        temp.as_file_mut().write_all(&payload)?;
        publish(temp, output)?;
        println!("Carrier payload extracted (still encrypted): {}", output.display());
        return Ok(());
    }

    if paths.len() != 2 { return Err("expected exactly an input path and an output path".into()); }
    let input = Path::new(&paths[0]);
    let output = Path::new(&paths[1]);

    match command.as_str() {
        "encrypt" => {
            let secret = password(true)?;
            encrypt_file(input, output, secret.as_bytes())?;
        }
        "decrypt" => {
            let secret = password(false)?;
            decrypt_file(input, output, secret.as_bytes())?;
        }
        "encrypt-dir" => {
            let secret = password(true)?;
            let mut temp = temporary_output(output)?;
            noctyra_core::encrypt_directory_stream(secret.as_bytes(), input, temp.as_file_mut())?;
            publish(temp, output)?;
        }
        "decrypt-dir" => {
            if output.exists() { return Err(format!("refusing to merge with or overwrite existing destination: {}", output.display()).into()); }
            let secret = password(false)?;
            check_regular_file(input)?;
            let mut archive = File::open(input)?;
            let mut prefix = [0u8; 6];
            archive.read_exact(&mut prefix)?;
            archive.seek(SeekFrom::Start(0))?;
            match u16::from_le_bytes([prefix[4], prefix[5]]) {
                2 => noctyra_core::decrypt_directory_stream(secret.as_bytes(), archive, output)?,
                1 => {
                    let legacy = Zeroizing::new(read_bounded(input)?);
                    noctyra_core::extract_directory(secret.as_bytes(), &legacy, output)?;
                }
                other => return Err(format!("unsupported NCT directory archive version: {other}").into()),
            }
        }
        _ => return Err("usage: noctyra encrypt <file> <archive.nct> | decrypt <archive.nct> <file> | encrypt-dir <directory> <archive.nct> | decrypt-dir <archive.nct> <new-directory> | cleanup-staging <parent-directory> | carrier-embed <carrier-image> <encrypted-archive.nct> <output-image> | carrier-extract <carrier-image> <output-archive.nct>".into()),
    }

    println!("Operation completed: {}", output.display());
    Ok(())
}
