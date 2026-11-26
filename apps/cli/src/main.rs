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

fn read_bounded(path: &Path) -> Result<Vec<u8>, Box<dyn Error>> {
    check_regular_file(path)?;
    let metadata = fs::metadata(path)?;
    if metadata.len() > MAX_INPUT_BYTES { return Err("input exceeds the current 1 GiB limit".into()); }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)?.take(MAX_INPUT_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_INPUT_BYTES { return Err("input grew beyond the configured 1 GiB limit while being read".into()); }
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
    let input = args.next().ok_or("missing input path")?;
    let output = args.next().ok_or("missing output path")?;
    if args.next().is_some() { return Err("too many arguments".into()); }

    let command = command.to_string_lossy();
    let input = Path::new(&input);
    let output = Path::new(&output);

    match command.as_ref() {
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
        _ => return Err("usage: noctyra encrypt <file> <archive.nct> | decrypt <archive.nct> <file> | encrypt-dir <directory> <archive.nct> | decrypt-dir <archive.nct> <new-directory>".into()),
    }

    println!("Operation completed: {}", output.display());
    Ok(())
}
