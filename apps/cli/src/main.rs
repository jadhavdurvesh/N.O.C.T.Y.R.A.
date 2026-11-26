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

    if command == "constellation-split" {
        if paths.len() != 2 && paths.len() != 3 {
            return Err("usage: noctyra constellation-split <archive.nct> <new-output-directory> [fragment-bytes]".into());
        }
        let archive = Zeroizing::new(read_bounded(Path::new(&paths[0]))?);
        let fragment_size = if paths.len() == 3 {
            paths[2].to_string_lossy().parse::<usize>()?
        } else { noctyra_core::DEFAULT_FRAGMENT_DATA_BYTES };
        let plan = noctyra_core::ConstellationFragmentPlan::new(&archive, fragment_size)?;
        let destination = Path::new(&paths[1]);
        if destination.exists() { return Err("output directory already exists; refusing to overwrite".into()); }
        let parent = destination.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
        let staging = tempfile::Builder::new().prefix(".noctyra-constellation-").tempdir_in(parent)?;
        for index in 0..plan.count() {
            let fragment = Zeroizing::new(plan.encode(index)?);
            let path = staging.path().join(format!("fragment-{index:04}.ncfr"));
            let mut file = File::options().write(true).create_new(true).open(path)?;
            file.write_all(&fragment)?;
            file.sync_all()?;
        }
        let staging_path = staging.keep();
        if let Err(error) = fs::rename(&staging_path, destination) {
            let _ = fs::remove_dir_all(&staging_path);
            return Err(error.into());
        }
        println!("CONSTELLATION split complete: {} fragments written to {}", plan.count(), destination.display());
        return Ok(());
    }

    if command == "constellation-encode" {
        if paths.len() < 3 || paths.len() > noctyra_core::MAX_FRAGMENT_COUNT + 2 {
            return Err("usage: noctyra constellation-encode <archive.nct> <new-output-directory> <cover-image1> [cover-image2 ...]".into());
        }
        let archive = Zeroizing::new(read_bounded(Path::new(&paths[0]))?);
        let destination = Path::new(&paths[1]);
        if destination.exists() { return Err("output directory already exists; refusing to overwrite".into()); }
        let cover_paths = &paths[2..];
        let mut smallest_capacity = usize::MAX;
        for path in cover_paths {
            let image_bytes = Zeroizing::new(read_carrier_file(Path::new(path))?);
            let carrier = noctyra_core::CarrierImage::load(&image_bytes)?;
            let capacity = noctyra_core::estimate_carrier_capacity(&carrier).payload_bytes
                .saturating_sub(noctyra_core::FRAGMENT_HEADER_LEN);
            smallest_capacity = smallest_capacity.min(capacity);
        }
        let fragment_size = smallest_capacity.min(noctyra_core::MAX_FRAGMENT_DATA_BYTES);
        if fragment_size == 0 { return Err("one or more cover images cannot hold a CONSTELLATION fragment header and payload".into()); }
        let plan = noctyra_core::ConstellationFragmentPlan::new(&archive, fragment_size)?;
        if plan.count() > cover_paths.len() {
            return Err(format!("not enough cover images: {} fragments required, {} supplied", plan.count(), cover_paths.len()).into());
        }
        let parent = destination.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
        let staging = tempfile::Builder::new().prefix(".noctyra-constellation-").tempdir_in(parent)?;
        for index in 0..plan.count() {
            let fragment = Zeroizing::new(plan.encode(index)?);
            let image_bytes = Zeroizing::new(read_carrier_file(Path::new(&cover_paths[index]))?);
            let mut carrier = noctyra_core::CarrierImage::load(&image_bytes)?;
            noctyra_core::embed_carrier(&mut carrier, &fragment)?;
            let format = carrier.format();
            let encoded = Zeroizing::new(carrier.encode(format)?);
            let output = staging.path().join(format!("carrier-{:04}.{}", index + 1, format.extension()));
            let mut file = File::options().write(true).create_new(true).open(output)?;
            file.write_all(&encoded)?;
            file.sync_all()?;
        }
        let staging_path = staging.keep();
        if let Err(error) = fs::rename(&staging_path, destination) {
            let _ = fs::remove_dir_all(&staging_path);
            return Err(error.into());
        }
        println!("CONSTELLATION encoded {} image carriers in {}", plan.count(), destination.display());
        return Ok(());
    }

    if command == "constellation-reassemble-images" {
        if paths.len() < 2 || paths.len() > noctyra_core::MAX_FRAGMENT_COUNT + 1 {
            return Err("usage: noctyra constellation-reassemble-images <output-archive.nct> <carrier-image1> [carrier-image2 ...]".into());
        }
        let mut fragments = Vec::with_capacity(paths.len() - 1);
        for path in &paths[1..] {
            let image_bytes = Zeroizing::new(read_carrier_file(Path::new(path))?);
            let carrier = noctyra_core::CarrierImage::load(&image_bytes)?;
            fragments.push(Zeroizing::new(noctyra_core::extract_carrier(&carrier)?));
        }
        let refs: Vec<&[u8]> = fragments.iter().map(|fragment| fragment.as_slice()).collect();
        let archive = Zeroizing::new(noctyra_core::reassemble_fragments(refs)?);
        let output = Path::new(&paths[0]);
        let mut temp = temporary_output(output)?;
        temp.as_file_mut().write_all(&archive)?;
        publish(temp, output)?;
        println!("CONSTELLATION image reassembly complete: {}", output.display());
        return Ok(());
    }

    if command == "constellation-inspect" || command == "constellation-inspect-images" {
        if paths.is_empty() || paths.len() > noctyra_core::MAX_FRAGMENT_COUNT {
            return Err("usage: noctyra constellation-inspect <fragment.ncfr> [more-fragments...] (or constellation-inspect-images <carrier.png> [more-carriers...])".into());
        }
        let mut fragments = Vec::with_capacity(paths.len());
        for path in &paths {
            if command == "constellation-inspect-images" {
                let image_bytes = Zeroizing::new(read_carrier_file(Path::new(path))?);
                let carrier = noctyra_core::CarrierImage::load(&image_bytes)?;
                fragments.push(Zeroizing::new(noctyra_core::extract_carrier(&carrier)?));
            } else {
                fragments.push(Zeroizing::new(read_limited(
                    Path::new(path),
                    (noctyra_core::MAX_FRAGMENT_DATA_BYTES + noctyra_core::FRAGMENT_HEADER_LEN) as u64,
                    "CONSTELLATION fragment"
                )?));
            }
        }
        let refs: Vec<&[u8]> = fragments.iter().map(|fragment| fragment.as_slice()).collect();
        let report = noctyra_core::inspect_fragments(refs)?;
        println!("Transfer ID: {}", report.transfer_id.iter().map(|byte| format!("{byte:02x}")).collect::<String>());
        println!("Fragments received: {} / {}", report.received_fragments, report.expected_fragments);
        if report.missing_indices.is_empty() {
            println!("All fragment indexes are present.");
        } else {
            println!("Missing fragment indexes (zero-based): {:?}", report.missing_indices);
        }
        return Ok(());
    }

    if command == "constellation-reassemble" {
        if paths.len() < 2 || paths.len() > noctyra_core::MAX_FRAGMENT_COUNT + 1 {
            return Err("usage: noctyra constellation-reassemble <output-archive.nct> <fragment-1.ncfr> [fragment-2.ncfr ...]".into());
        }
        let mut fragments = Vec::with_capacity(paths.len() - 1);
        for path in &paths[1..] {
            fragments.push(Zeroizing::new(read_limited(
                Path::new(path),
                (noctyra_core::MAX_FRAGMENT_DATA_BYTES + noctyra_core::FRAGMENT_HEADER_LEN) as u64,
                "CONSTELLATION fragment"
            )?));
        }
        let refs: Vec<&[u8]> = fragments.iter().map(|fragment| fragment.as_slice()).collect();
        let archive = Zeroizing::new(noctyra_core::reassemble_fragments(refs)?);
        let output = Path::new(&paths[0]);
        let mut temp = temporary_output(output)?;
        temp.as_file_mut().write_all(&archive)?;
        publish(temp, output)?;
        println!("CONSTELLATION reassembly complete: {}", output.display());
        return Ok(());
    }

    if command == "carrier-embed" {
        if paths.len() != 3 { return Err("usage: noctyra carrier-embed <carrier-image> <encrypted-archive.nct> <output-image>".into()); }
        let image_bytes = Zeroizing::new(read_carrier_file(Path::new(&paths[0]))?);
        let archive_bytes = Zeroizing::new(read_limited(Path::new(&paths[1]), 16 * 1024 * 1024, "encrypted archive payload")?);
        if archive_bytes.len() < 6 || &archive_bytes[..4] != b"NCTY" {
            return Err("carrier payload must begin with a NOCTYRA NCT archive header".into());
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
        if payload.len() < 6 || &payload[..4] != b"NCTY" {
            return Err("extracted carrier data does not contain an NCT archive header".into());
        }
        let archive_version = u16::from_le_bytes([payload[4], payload[5]]);
        if !matches!(archive_version, 1 | 2) {
            return Err("extracted carrier contains an unsupported NCT version".into());
        }
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
        _ => return Err("usage: noctyra encrypt <file> <archive.nct> | decrypt <archive.nct> <file> | encrypt-dir <directory> <archive.nct> | decrypt-dir <archive.nct> <new-directory> | cleanup-staging <parent-directory> | carrier-embed <carrier-image> <encrypted-archive.nct> <output-image> | carrier-extract <carrier-image> <output-archive.nct> | constellation-split <archive.nct> <new-output-directory> [fragment-bytes] | constellation-inspect <fragment-1.ncfr> [more-fragments...] | constellation-inspect-images <carrier-image1> [more-carriers...] | constellation-reassemble <output-archive.nct> <fragment-1.ncfr> [fragment-2.ncfr ...] | constellation-encode <archive.nct> <new-output-directory> <cover-image1> [cover-image2 ...] | constellation-reassemble-images <output-archive.nct> <carrier-image1> [carrier-image2 ...]".into()),
    }

    println!("Operation completed: {}", output.display());
    Ok(())
}
