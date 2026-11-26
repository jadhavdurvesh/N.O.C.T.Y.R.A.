use std::{
    env,
    error::Error,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
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

    if output.exists() {
        return Err(format!("refusing to overwrite existing output: {}", output.display()).into());
    }

    let metadata = fs::metadata(input)?;
    if !metadata.is_file() {
        return Err("input must be a regular file".into());
    }
    if metadata.len() > MAX_INPUT_BYTES {
        return Err("input exceeds the current 1 GiB limit".into());
    }

    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(input)?.take(MAX_INPUT_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_INPUT_BYTES {
        return Err("input grew beyond the configured 1 GiB limit while being read".into());
    }

    let result = match command.as_ref() {
        "encrypt" => {
            let password = Zeroizing::new(rpassword::prompt_password("NOCTYRA password: ")?);
            if password.is_empty() {
                return Err("password must not be empty".into());
            }
            let confirmation = Zeroizing::new(rpassword::prompt_password("Confirm password: ")?);
            if password.as_bytes() != confirmation.as_bytes() {
                return Err("password confirmation did not match".into());
            }
            noctyra_core::seal_archive(password.as_bytes(), &bytes)?
        }
        "decrypt" => {
            let password = Zeroizing::new(rpassword::prompt_password("NOCTYRA password: ")?);
            if password.is_empty() {
                return Err("password must not be empty".into());
            }
            noctyra_core::open_archive(password.as_bytes(), &bytes)?
        }
        _ => return Err("usage: noctyra encrypt <input> <output.nct> | decrypt <input.nct> <output>".into()),
    };

    // create_new provides a race-safe no-overwrite guarantee.
    let mut file = OpenOptions::new().write(true).create_new(true).open(output)?;
    if let Err(error) = file.write_all(&result).and_then(|_| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(output);
        return Err(error.into());
    }

    println!("Operation completed: {}", output.display());
    Ok(())
}
