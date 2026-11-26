use std::{
    env,
    error::Error,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
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
    if value.is_empty() {
        return Err("password must not be empty".into());
    }
    if confirm {
        let again = Zeroizing::new(rpassword::prompt_password("Confirm password: ")?);
        if value.as_bytes() != again.as_bytes() {
            return Err("password confirmation did not match".into());
        }
    }
    Ok(value)
}

fn read_bounded(path: &Path) -> Result<Vec<u8>, Box<dyn Error>> {
    let metadata = fs::metadata(path)?;
    if !metadata.is_file() {
        return Err("input must be a regular file".into());
    }
    if metadata.len() > MAX_INPUT_BYTES {
        return Err("input exceeds the current 1 GiB limit".into());
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)?.take(MAX_INPUT_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_INPUT_BYTES {
        return Err("input grew beyond the configured 1 GiB limit while being read".into());
    }
    Ok(bytes)
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    if let Err(error) = file.write_all(bytes).and_then(|_| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(error.into());
    }
    Ok(())
}

fn run() -> Result<(), Box<dyn Error>> {
    let mut args = env::args_os().skip(1);
    let command = args.next().ok_or("missing command")?;
    let input = args.next().ok_or("missing input path")?;
    let output = args.next().ok_or("missing output path")?;
    if args.next().is_some() {
        return Err("too many arguments".into());
    }

    let command = command.to_string_lossy();
    let input = Path::new(&input);
    let output = Path::new(&output);

    match command.as_ref() {
        "encrypt" => {
            let secret = password(true)?;
            let bytes = Zeroizing::new(read_bounded(input)?);
            let archive = noctyra_core::seal_archive(secret.as_bytes(), &bytes)?;
            write_new(output, &archive)?;
        }
        "decrypt" => {
            let secret = password(false)?;
            let archive = read_bounded(input)?;
            let bytes = Zeroizing::new(noctyra_core::open_archive(secret.as_bytes(), &archive)?);
            write_new(output, &bytes)?;
        }
        "encrypt-dir" => {
            if output.exists() {
                return Err(format!("refusing to overwrite existing output: {}", output.display()).into());
            }
            let secret = password(true)?;
            let archive = noctyra_core::seal_directory(secret.as_bytes(), input)?;
            write_new(output, &archive)?;
        }
        "decrypt-dir" => {
            if output.exists() {
                return Err(format!("refusing to merge with or overwrite existing destination: {}", output.display()).into());
            }
            let secret = password(false)?;
            let archive = read_bounded(input)?;
            noctyra_core::extract_directory(secret.as_bytes(), &archive, output)?;
        }
        _ => {
            return Err("usage: noctyra encrypt <file> <archive.nct> | decrypt <archive.nct> <file> | encrypt-dir <directory> <archive.nct> | decrypt-dir <archive.nct> <new-directory>".into());
        }
    }

    println!("Operation completed: {}", output.display());
    Ok(())
}
