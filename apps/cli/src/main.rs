use std::{
    env,
    error::Error,
    fs::{self, File},
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
};
use zeroize::Zeroizing;
use ed25519_dalek::SigningKey;
use rand_core::{OsRng, RngCore};

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

fn write_new_key_file(path: &Path, bytes: &[u8], private: bool) -> Result<(), Box<dyn Error>> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn replace_private_file(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let mut temp = tempfile::NamedTempFile::new_in(parent)?;
    temp.as_file_mut().write_all(bytes)?;
    temp.as_file().sync_all()?;
    temp.persist(path).map_err(|error| error.error)?;
    Ok(())
}

fn run() -> Result<(), Box<dyn Error>> {
    let mut args = env::args_os().skip(1);
    let command = args.next().ok_or("missing command")?;
    let command = command.to_string_lossy().into_owned();
    let paths: Vec<_> = args.collect();

    if command == "trust-init" {
        if paths.len() != 1 { return Err("usage: noctyra trust-init <trusted-senders.ncts>".into()); }
        let output = Path::new(&paths[0]);
        if output.exists() { return Err("refusing to overwrite an existing trust registry".into()); }
        let secret = password(true)?;
        let bytes = Zeroizing::new(noctyra_core::create_trust_store(secret.as_bytes())?);
        write_new_key_file(output, &bytes, true)?;
        println!("Encrypted trusted-sender registry created: {}", output.display());
        return Ok(());
    }

    if command == "trust-add" {
        if paths.len() != 4 { return Err("usage: noctyra trust-add <registry.ncts> <public-key.bin> <label> <expected-fingerprint>".into()); }
        let registry_path = Path::new(&paths[0]);
        let public_bytes = Zeroizing::new(read_limited(Path::new(&paths[1]), 32, "Ed25519 public key")?);
        let public_key: [u8; 32] = public_bytes.as_slice().try_into().map_err(|_| "Ed25519 public key must be exactly 32 bytes")?;
        let expected = paths[3].to_string_lossy();
        let actual = blake3::hash(&public_key).to_hex().to_string();
        if actual != expected { return Err(format!("fingerprint confirmation mismatch; computed fingerprint: {actual}").into()); }
        let registry_bytes = Zeroizing::new(read_limited(registry_path, noctyra_core::MAX_TRUST_STORE_BYTES as u64, "trust registry")?);
        let secret = password(false)?;
        let mut store = noctyra_core::open_trust_store(secret.as_bytes(), &registry_bytes)?;
        let label = paths[2].to_string_lossy().into_owned();
        store.add(public_key, label)?;
        let updated = Zeroizing::new(noctyra_core::save_trust_store(secret.as_bytes(), &store)?);
        replace_private_file(registry_path, &updated)?;
        println!("Public key explicitly added to the encrypted trust registry.");
        println!("Fingerprint: {actual}");
        return Ok(());
    }

    if command == "trust-rotate" {
        if paths.len() != 6 { return Err("usage: noctyra trust-rotate <registry.ncts> <old-fingerprint> <rotation.ncrt> <new-public-key.bin> <label> <expected-new-fingerprint>".into()); }
        let registry_path = Path::new(&paths[0]);
        let registry_bytes = Zeroizing::new(read_limited(registry_path, noctyra_core::MAX_TRUST_STORE_BYTES as u64, "trust registry")?);
        let secret = password(false)?;
        let mut store = noctyra_core::open_trust_store(secret.as_bytes(), &registry_bytes)?;
        let old_fingerprint = paths[1].to_string_lossy();
        let old_public = store.trusted_public_key(&old_fingerprint)?;
        let certificate = Zeroizing::new(read_limited(Path::new(&paths[2]), noctyra_core::ROTATION_CERTIFICATE_LEN as u64, "rotation certificate")?);
        let successor = noctyra_core::verify_rotation_certificate(&certificate, &old_public)?;
        let supplied_bytes = Zeroizing::new(read_limited(Path::new(&paths[3]), 32, "successor public key")?);
        let supplied: [u8; 32] = supplied_bytes.as_slice().try_into().map_err(|_| "successor public key must be exactly 32 bytes")?;
        if supplied != successor { return Err("successor public key does not match the signed rotation certificate".into()); }
        let fingerprint = blake3::hash(&successor).to_hex().to_string();
        if fingerprint != paths[5].to_string_lossy().as_ref() { return Err(format!("successor fingerprint confirmation mismatch; computed fingerprint: {fingerprint}").into()); }
        let label = paths[4].to_string_lossy().into_owned();
        store.add(successor, label)?;
        store.revoke(&old_fingerprint)?;
        let updated = Zeroizing::new(noctyra_core::save_trust_store(secret.as_bytes(), &store)?);
        replace_private_file(registry_path, &updated)?;
        println!("Trust rotation committed: successor added and predecessor revoked.");
        println!("New trusted fingerprint: {fingerprint}");
        return Ok(());
    }

    if command == "constellation-manifest-verify-trusted-recovery" {
        if paths.len() < 5 { return Err("usage: noctyra constellation-manifest-verify-trusted-recovery <output.nct> <manifest.ncmf> <registry.ncts> <trusted-fingerprint> <shard1.ncrs> [more-shards...]".into()); }
        let manifest_bytes = Zeroizing::new(read_limited(Path::new(&paths[1]), noctyra_core::MAX_MANIFEST_LEN as u64, "signed manifest")?);
        let registry_bytes = Zeroizing::new(read_limited(Path::new(&paths[2]), noctyra_core::MAX_TRUST_STORE_BYTES as u64, "trust registry")?);
        let secret = password(false)?;
        let store = noctyra_core::open_trust_store(secret.as_bytes(), &registry_bytes)?;
        let fingerprint = paths[3].to_string_lossy();
        let trusted_key = store.trusted_public_key(&fingerprint)?;
        let manifest = noctyra_core::verify_signed_manifest(&manifest_bytes, &trusted_key)?;
        let mut shards = Vec::with_capacity(paths.len() - 4);
        for path in &paths[4..] {
            shards.push(Zeroizing::new(read_limited(Path::new(path), (noctyra_core::MAX_FRAGMENT_DATA_BYTES + noctyra_core::RECOVERY_HEADER_LEN) as u64, "recovery shard")?));
        }
        let refs: Vec<&[u8]> = shards.iter().map(|shard| shard.as_slice()).collect();
        let report = noctyra_core::verify_manifest_shards(&manifest, refs.iter().copied())?;
        if !report.recoverable { return Err(format!("signed set is authentic but incomplete: received {}, need at least {}", report.received_shards, report.data_shards).into()); }
        let archive = Zeroizing::new(noctyra_core::recover_archive(refs)?);
        let output = Path::new(&paths[0]);
        let mut temp = temporary_output(output)?;
        temp.as_file_mut().write_all(&archive)?;
        publish(temp, output)?;
        println!("Trusted-sender verification and authenticated recovery succeeded: {}", output.display());
        return Ok(());
    }

    if command == "trust-list" || command == "trust-revoke" || command == "trust-check" {
        let expected = if command == "trust-list" { 1 } else { 2 };
        if paths.len() != expected {
            return Err("usage: noctyra trust-list <registry.ncts> | trust-revoke <registry.ncts> <fingerprint> | trust-check <registry.ncts> <fingerprint>".into());
        }
        let registry_path = Path::new(&paths[0]);
        let registry_bytes = Zeroizing::new(read_limited(registry_path, noctyra_core::MAX_TRUST_STORE_BYTES as u64, "trust registry")?);
        let secret = password(false)?;
        let mut store = noctyra_core::open_trust_store(secret.as_bytes(), &registry_bytes)?;
        if command == "trust-list" {
            if store.entries().is_empty() { println!("Trust registry is empty."); }
            for entry in store.entries() {
                println!("{} | {} | {}", entry.fingerprint(), if entry.revoked { "REVOKED" } else { "TRUSTED" }, entry.label);
            }
            return Ok(());
        }
        let fingerprint = paths[1].to_string_lossy();
        if command == "trust-revoke" {
            store.revoke(&fingerprint)?;
            let updated = Zeroizing::new(noctyra_core::save_trust_store(secret.as_bytes(), &store)?);
            replace_private_file(registry_path, &updated)?;
            println!("Key revoked in the encrypted local trust registry: {fingerprint}");
            return Ok(());
        }
        let public_key = store.trusted_public_key(&fingerprint)?;
        println!("Key is trusted and not revoked.");
        println!("Public key: {}", public_key.iter().map(|b| format!("{b:02x}")).collect::<String>());
        return Ok(());
    }

    if command == "vault-create" {
        if paths.len() != 1 { return Err("usage: noctyra vault-create <identity.nckv>".into()); }
        let output = Path::new(&paths[0]);
        if output.exists() { return Err("refusing to overwrite an existing key vault".into()); }
        let secret = password(true)?;
        let vault = Zeroizing::new(noctyra_core::create_vault(secret.as_bytes())?);
        write_new_key_file(output, &vault, true)?;
        let (public_key, fingerprint) = noctyra_core::inspect_vault(&vault)?;
        println!("Encrypted Ed25519 identity vault created.");
        println!("Public-key fingerprint: {fingerprint}");
        println!("Public key: {}", public_key.iter().map(|b| format!("{b:02x}")).collect::<String>());
        return Ok(());
    }

    if command == "vault-inspect" || command == "vault-export-public" {
        let expected = if command == "vault-inspect" { 1 } else { 2 };
        if paths.len() != expected {
            return Err("usage: noctyra vault-inspect <identity.nckv> | vault-export-public <identity.nckv> <public-key.bin>".into());
        }
        let bytes = Zeroizing::new(read_limited(Path::new(&paths[0]), noctyra_core::VAULT_FILE_LEN as u64, "key vault")?);
        let (public_key, fingerprint) = noctyra_core::inspect_vault(&bytes)?;
        println!("Identity fingerprint: {fingerprint}");
        println!("Public key: {}", public_key.iter().map(|b| format!("{b:02x}")).collect::<String>());
        if command == "vault-export-public" {
            let output = Path::new(&paths[1]);
            write_new_key_file(output, &public_key, false)?;
            println!("Public key exported: {}", output.display());
        }
        return Ok(());
    }

    if command == "vault-rotate" {
        if paths.len() != 3 { return Err("usage: noctyra vault-rotate <old-identity.nckv> <new-identity.nckv> <rotation.ncrt>".into()); }
        let old_path = Path::new(&paths[0]);
        let new_path = Path::new(&paths[1]);
        let certificate_path = Path::new(&paths[2]);
        if new_path.exists() || certificate_path.exists() || old_path == new_path || new_path == certificate_path || old_path == certificate_path {
            return Err("rotation outputs must be distinct, new paths that do not already exist".into());
        }
        let old_bytes = Zeroizing::new(read_limited(old_path, noctyra_core::VAULT_FILE_LEN as u64, "old key vault")?);
        let old_password = password(false)?;
        let old_signing_key = noctyra_core::unlock_vault(old_password.as_bytes(), &old_bytes)?;
        let new_password = password(true)?;
        let new_bytes = Zeroizing::new(noctyra_core::create_vault(new_password.as_bytes())?);
        let (new_public_key, new_fingerprint) = noctyra_core::inspect_vault(&new_bytes)?;
        let certificate = Zeroizing::new(noctyra_core::create_rotation_certificate(&old_signing_key, &new_public_key));
        write_new_key_file(new_path, &new_bytes, true)?;
        if let Err(error) = write_new_key_file(certificate_path, &certificate, false) {
            return Err(format!("new vault was created at {}, but rotation certificate could not be written: {error}", new_path.display()).into());
        }
        println!("New encrypted identity vault created: {}", new_path.display());
        println!("Rotation certificate created: {}", certificate_path.display());
        println!("New identity fingerprint: {new_fingerprint}");
        println!("Distribute the certificate and new public key; recipients must verify the certificate using their independently pinned old key before accepting the successor.");
        return Ok(());
    }

    if command == "verify-rotation" {
        if paths.len() != 2 { return Err("usage: noctyra verify-rotation <rotation.ncrt> <trusted-old-public-key.bin>".into()); }
        let certificate = Zeroizing::new(read_limited(Path::new(&paths[0]), noctyra_core::ROTATION_CERTIFICATE_LEN as u64, "rotation certificate")?);
        let old_public = Zeroizing::new(read_limited(Path::new(&paths[1]), 32, "trusted old public key")?);
        let trusted: [u8; 32] = old_public.as_slice().try_into().map_err(|_| "trusted old public key must be exactly 32 bytes")?;
        let next = noctyra_core::verify_rotation_certificate(&certificate, &trusted)?;
        let fingerprint = blake3::hash(&next).to_hex().to_string();
        println!("Rotation certificate valid: trusted old key authorized this successor.");
        println!("Successor fingerprint: {fingerprint}");
        println!("Successor public key: {}", next.iter().map(|b| format!("{b:02x}")).collect::<String>());
        println!("This verifies continuity only. Review and explicitly pin the successor; it is not automatically trusted.");
        return Ok(());
    }

    if command == "constellation-keygen" {
        if paths.len() != 2 { return Err("usage: noctyra constellation-keygen <private-key-file> <public-key-file>".into()); }
        let private_path = Path::new(&paths[0]);
        let public_path = Path::new(&paths[1]);
        if private_path == public_path { return Err("private and public key paths must be different".into()); }
        if private_path.exists() || public_path.exists() { return Err("refusing to overwrite an existing key file".into()); }
        let mut secret = Zeroizing::new([0u8; 32]);
        OsRng.try_fill_bytes(&mut *secret).map_err(|_| "operating-system random generator failed")?;
        let signing_key = SigningKey::from_bytes(&secret);
        let public_key = signing_key.verifying_key().to_bytes();
        write_new_key_file(private_path, &secret[..], true)?;
        if let Err(error) = write_new_key_file(public_path, &public_key, false) {
            return Err(format!("public key could not be written; private key was created at {}: {error}", private_path.display()).into());
        }
        println!("Ed25519 keypair created. Keep the private key offline and share the public key through an independently trusted channel.");
        return Ok(());
    }

    if command == "constellation-send" {
        if paths.len() < 7 || paths.len() > noctyra_core::MAX_RECOVERY_SHARDS + 5 {
            return Err("usage: noctyra constellation-send <plaintext-file> <new-package-directory> <identity.nckv> <shard-bytes> <parity-shards> <cover-image1> [more-images...]".into());
        }
        let input = Path::new(&paths[0]);
        check_regular_file(input)?;
        let destination = Path::new(&paths[1]);
        if destination.exists() { return Err("package directory already exists; refusing to overwrite".into()); }
        let shard_size = paths[3].to_string_lossy().parse::<usize>()?;
        let parity_count = paths[4].to_string_lossy().parse::<usize>()?;
        let cover_paths = &paths[5..];

        println!("Unlock the sender identity vault.");
        let vault_password = password(false)?;
        let vault_bytes = Zeroizing::new(read_limited(Path::new(&paths[2]), noctyra_core::VAULT_FILE_LEN as u64, "identity vault")?);
        let signing_key = noctyra_core::unlock_vault(vault_password.as_bytes(), &vault_bytes)?;
        let signer_public = signing_key.verifying_key().to_bytes();

        println!("Choose the password that the recipient will need to decrypt the file.");
        let archive_password = password(true)?;
        let mut archive_file = tempfile::tempfile()?;
        noctyra_core::encrypt_stream(archive_password.as_bytes(), File::open(input)?, &mut archive_file)?;
        archive_file.seek(SeekFrom::Start(0))?;
        let mut archive = Zeroizing::new(Vec::new());
        archive_file.take(MAX_INPUT_BYTES + 1).read_to_end(&mut archive)?;
        if archive.len() as u64 > MAX_INPUT_BYTES { return Err("encrypted archive exceeds the configured transfer limit".into()); }

        let mut smallest_capacity = usize::MAX;
        for path in cover_paths {
            let image_bytes = Zeroizing::new(read_carrier_file(Path::new(path))?);
            let carrier = noctyra_core::CarrierImage::load(&image_bytes)?;
            let capacity = noctyra_core::estimate_carrier_capacity(&carrier).payload_bytes
                .saturating_sub(noctyra_core::RECOVERY_HEADER_LEN);
            smallest_capacity = smallest_capacity.min(capacity);
        }
        if shard_size == 0 || shard_size > smallest_capacity {
            return Err(format!("shard size must fit every supplied cover image; maximum available is {smallest_capacity} bytes").into());
        }

        let shards = noctyra_core::create_recovery_shards(&archive, shard_size, parity_count)?;
        if shards.len() > cover_paths.len() {
            return Err(format!("not enough cover images: {} shards required, {} supplied", shards.len(), cover_paths.len()).into());
        }
        let shard_refs: Vec<&[u8]> = shards.iter().map(Vec::as_slice).collect();
        let manifest = Zeroizing::new(noctyra_core::create_signed_manifest_for_shards(shard_refs, &signing_key)?);
        let fingerprint = blake3::hash(&signer_public).to_hex().to_string();

        let parent = destination.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
        let staging = tempfile::Builder::new().prefix(".noctyra-send-").tempdir_in(parent)?;
        let manifest_path = staging.path().join("manifest.ncmf");
        let mut manifest_file = File::options().write(true).create_new(true).open(&manifest_path)?;
        manifest_file.write_all(&manifest)?;
        manifest_file.sync_all()?;

        for (index, shard) in shards.iter().enumerate() {
            let image_bytes = Zeroizing::new(read_carrier_file(Path::new(&cover_paths[index]))?);
            let mut carrier = noctyra_core::CarrierImage::load(&image_bytes)?;
            noctyra_core::embed_carrier(&mut carrier, shard)?;
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
        println!("CONSTELLATION package created: {}", destination.display());
        println!("Signed manifest: manifest.ncmf");
        println!("Carrier count: {}", shards.len());
        println!("Signer fingerprint: {fingerprint}");
        println!("Share the package directory with the recipient through your chosen channel. Share the archive password separately.");
        return Ok(());
    }

    if command == "constellation-receive" {
        if paths.len() < 5 {
            return Err("usage: noctyra constellation-receive <output-plaintext-file> <manifest.ncmf> <registry.ncts> <trusted-fingerprint> <carrier1.png> [more-carriers...]".into());
        }
        let manifest_bytes = Zeroizing::new(read_limited(Path::new(&paths[1]), noctyra_core::MAX_MANIFEST_LEN as u64, "signed manifest")?);
        let registry_bytes = Zeroizing::new(read_limited(Path::new(&paths[2]), noctyra_core::MAX_TRUST_STORE_BYTES as u64, "trust registry")?);
        println!("Unlock the local trusted-sender registry.");
        let registry_password = password(false)?;
        let store = noctyra_core::open_trust_store(registry_password.as_bytes(), &registry_bytes)?;
        let fingerprint = paths[3].to_string_lossy();
        let trusted_key = store.trusted_public_key(&fingerprint)?;
        let verified_manifest = noctyra_core::verify_signed_manifest(&manifest_bytes, &trusted_key)?;

        let mut shards = Vec::with_capacity(paths.len() - 4);
        for path in &paths[4..] {
            let image_bytes = Zeroizing::new(read_carrier_file(Path::new(path))?);
            let carrier = noctyra_core::CarrierImage::load(&image_bytes)?;
            shards.push(Zeroizing::new(noctyra_core::extract_carrier(&carrier)?));
        }
        let shard_refs: Vec<&[u8]> = shards.iter().map(|shard| shard.as_slice()).collect();
        let report = noctyra_core::verify_manifest_shards(&verified_manifest, shard_refs.iter().copied())?;
        if !report.recoverable {
            return Err(format!("signed transfer is authentic but incomplete: received {}, need at least {} valid carriers", report.received_shards, report.data_shards).into());
        }
        let archive = Zeroizing::new(noctyra_core::recover_archive(shard_refs.iter().copied())?);

        println!("Enter the file-encryption password supplied separately by the sender.");
        let archive_password = password(false)?;
        let mut temp = temporary_output(Path::new(&paths[0]))?;
        if archive.len() < 6 || &archive[..4] != b"NCTY" {
            return Err("recovered data is not a supported NCT archive".into());
        }
        let version = u16::from_le_bytes([archive[4], archive[5]]);
        match version {
            2 => noctyra_core::decrypt_stream(archive_password.as_bytes(), std::io::Cursor::new(archive.as_slice()), temp.as_file_mut())?,
            1 => {
                let plaintext = Zeroizing::new(noctyra_core::open_archive(archive_password.as_bytes(), &archive)?);
                temp.as_file_mut().write_all(&plaintext)?;
            }
            other => return Err(format!("unsupported recovered NCT archive version: {other}").into()),
        }
        publish(temp, Path::new(&paths[0]))?;
        println!("Trusted sender verified, recovery completed and archive authenticated.");
        println!("Decrypted file published: {}", paths[0].to_string_lossy());
        return Ok(());
    }

    if command == "constellation-diagnose" {
        if paths.len() < 5 {
            return Err("usage: noctyra constellation-diagnose <manifest.ncmf> <registry.ncts> <trusted-fingerprint> <carrier1.png> [more-carriers...]".into());
        }
        let manifest_bytes = Zeroizing::new(read_limited(Path::new(&paths[0]), noctyra_core::MAX_MANIFEST_LEN as u64, "signed manifest")?);
        let registry_bytes = Zeroizing::new(read_limited(Path::new(&paths[1]), noctyra_core::MAX_TRUST_STORE_BYTES as u64, "trust registry")?);
        println!("Unlock the local trusted-sender registry.");
        let registry_password = password(false)?;
        let store = noctyra_core::open_trust_store(registry_password.as_bytes(), &registry_bytes)?;
        let trusted_key = store.trusted_public_key(&paths[2].to_string_lossy())?;
        let verified = noctyra_core::verify_signed_manifest(&manifest_bytes, &trusted_key)?;

        let total = verified.data_shards() as usize + verified.parity_shards() as usize;
        let mut seen = vec![false; total];
        let mut valid = Vec::new();
        let mut invalid = 0usize;
        for path in &paths[3..] {
            let display = Path::new(path).display();
            let candidate = (|| -> Result<(u16, Vec<u8>), Box<dyn Error>> {
                let image_bytes = Zeroizing::new(read_carrier_file(Path::new(path))?);
                let carrier = noctyra_core::CarrierImage::load(&image_bytes)?;
                let shard = Zeroizing::new(noctyra_core::extract_carrier(&carrier)?);
                let index = noctyra_core::verify_manifest_shard(&verified, &shard)?;
                Ok((index, shard.to_vec()))
            })();
            match candidate {
                Ok((index, shard)) if !seen[index as usize] => {
                    seen[index as usize] = true;
                    valid.push(Zeroizing::new(shard));
                    println!("VALID   shard {index:03}: {display}");
                }
                Ok((index, _)) => {
                    invalid += 1;
                    println!("DUPLICATE shard {index:03}: {display}");
                }
                Err(error) => {
                    invalid += 1;
                    println!("REJECTED: {display} ({error})");
                }
            }
        }
        let received = valid.len();
        let required = verified.data_shards() as usize;
        let missing: Vec<usize> = seen.iter().enumerate().filter_map(|(i, present)| (!present).then_some(i)).collect();
        println!("\nTransfer: {}", blake3::Hash::from_bytes(verified.transfer_id()));
        println!("Valid unique shards: {received}/{total}");
        println!("Rejected or duplicate inputs: {invalid}");
        println!("Recovery threshold: {required}");
        if missing.is_empty() {
            println!("Missing indexes: none");
        } else {
            println!("Missing indexes: {}", missing.iter().map(usize::to_string).collect::<Vec<_>>().join(", "));
        }
        if received >= required {
            println!("STATUS: RECOVERABLE — run constellation-receive with the valid carriers only.");
        } else {
            println!("STATUS: INCOMPLETE — need {} additional valid shard(s).", required - received);
        }
        return Ok(());
    }

    if command == "constellation-manifest-create" {
        if paths.len() < 3 { return Err("usage: noctyra constellation-manifest-create <shard1.ncrs> [more-shards...] <private-key-file> <manifest.ncmf>".into()); }
        let private_path = Path::new(&paths[paths.len() - 2]);
        let output = Path::new(&paths[paths.len() - 1]);
        let key_bytes = Zeroizing::new(read_limited(private_path, 32, "Ed25519 private key")?);
        let secret = Zeroizing::new(<[u8; 32]>::try_from(key_bytes.as_slice()).map_err(|_| "Ed25519 private key must be exactly 32 raw bytes")?);
        let signing_key = SigningKey::from_bytes(&secret);
        let mut shards = Vec::with_capacity(paths.len() - 2);
        for path in &paths[..paths.len() - 2] {
            shards.push(Zeroizing::new(read_limited(Path::new(path), (noctyra_core::MAX_FRAGMENT_DATA_BYTES + noctyra_core::RECOVERY_HEADER_LEN) as u64, "recovery shard")?));
        }
        let refs: Vec<&[u8]> = shards.iter().map(|shard| shard.as_slice()).collect();
        let manifest = Zeroizing::new(noctyra_core::create_signed_manifest_for_shards(refs, &signing_key)?);
        let mut temp = temporary_output(output)?;
        temp.as_file_mut().write_all(&manifest)?;
        publish(temp, output)?;
        println!("Signed CONSTELLATION manifest created: {}", output.display());
        return Ok(());
    }

    if command == "constellation-manifest-verify-recovery" {
        if paths.len() < 4 { return Err("usage: noctyra constellation-manifest-verify-recovery <output-archive.nct> <manifest.ncmf> <trusted-public-key-file> <shard1.ncrs> [more-shards...]".into()); }
        let manifest_bytes = Zeroizing::new(read_limited(Path::new(&paths[1]), noctyra_core::MAX_MANIFEST_LEN as u64, "signed manifest")?);
        let public_bytes = Zeroizing::new(read_limited(Path::new(&paths[2]), 32, "trusted Ed25519 public key")?);
        let trusted_key: [u8; 32] = public_bytes.as_slice().try_into().map_err(|_| "trusted Ed25519 public key must be exactly 32 raw bytes")?;
        let manifest = noctyra_core::verify_signed_manifest(&manifest_bytes, &trusted_key)?;
        let mut shards = Vec::with_capacity(paths.len() - 3);
        for path in &paths[3..] {
            shards.push(Zeroizing::new(read_limited(Path::new(path), (noctyra_core::MAX_FRAGMENT_DATA_BYTES + noctyra_core::RECOVERY_HEADER_LEN) as u64, "recovery shard")?));
        }
        let refs: Vec<&[u8]> = shards.iter().map(|shard| shard.as_slice()).collect();
        let report = noctyra_core::verify_manifest_shards(&manifest, refs.iter().copied())?;
        if !report.recoverable {
            return Err(format!("signed set is authentic but incomplete: received {}, need at least {}", report.received_shards, report.data_shards).into());
        }
        let archive = Zeroizing::new(noctyra_core::recover_archive(refs)?);
        let output = Path::new(&paths[0]);
        let mut temp = temporary_output(output)?;
        temp.as_file_mut().write_all(&archive)?;
        publish(temp, output)?;
        println!("Authenticated recovery succeeded. Signer key is pinned to the supplied trusted public key; recovered archive: {}", output.display());
        return Ok(());
    }

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

    if command == "constellation-recovery-encode" {
        if paths.len() < 5 || paths.len() > noctyra_core::MAX_RECOVERY_SHARDS + 4 {
            return Err("usage: noctyra constellation-recovery-encode <archive.nct> <new-output-directory> <shard-bytes> <parity-shards> <cover-image1> [more-images...]".into());
        }
        let archive = Zeroizing::new(read_bounded(Path::new(&paths[0]))?);
        let destination = Path::new(&paths[1]);
        if destination.exists() { return Err("output directory already exists; refusing to overwrite".into()); }
        let shard_size = paths[2].to_string_lossy().parse::<usize>()?;
        let parity_count = paths[3].to_string_lossy().parse::<usize>()?;
        let cover_paths = &paths[4..];
        let mut smallest_capacity = usize::MAX;
        for path in cover_paths {
            let image_bytes = Zeroizing::new(read_carrier_file(Path::new(path))?);
            let carrier = noctyra_core::CarrierImage::load(&image_bytes)?;
            let capacity = noctyra_core::estimate_carrier_capacity(&carrier).payload_bytes
                .saturating_sub(noctyra_core::RECOVERY_HEADER_LEN);
            smallest_capacity = smallest_capacity.min(capacity);
        }
        if shard_size == 0 || shard_size > smallest_capacity {
            return Err(format!("shard size must fit every supplied cover image; maximum available is {smallest_capacity} bytes").into());
        }
        let shards = noctyra_core::create_recovery_shards(&archive, shard_size, parity_count)?;
        if shards.len() > cover_paths.len() {
            return Err(format!("not enough cover images: {} shards required, {} supplied", shards.len(), cover_paths.len()).into());
        }
        let parent = destination.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
        let staging = tempfile::Builder::new().prefix(".noctyra-recovery-").tempdir_in(parent)?;
        for (index, shard) in shards.iter().enumerate() {
            let image_bytes = Zeroizing::new(read_carrier_file(Path::new(&cover_paths[index]))?);
            let mut carrier = noctyra_core::CarrierImage::load(&image_bytes)?;
            noctyra_core::embed_carrier(&mut carrier, shard)?;
            let format = carrier.format();
            let encoded = Zeroizing::new(carrier.encode(format)?);
            let output = staging.path().join(format!("recovery-{:04}.{}", index + 1, format.extension()));
            let mut file = File::options().write(true).create_new(true).open(output)?;
            file.write_all(&encoded)?;
            file.sync_all()?;
        }
        let staging_path = staging.keep();
        if let Err(error) = fs::rename(&staging_path, destination) {
            let _ = fs::remove_dir_all(&staging_path);
            return Err(error.into());
        }
        println!("CONSTELLATION recovery set created: {} shards ({} data + {} parity)", shards.len(), shards.len() - parity_count, parity_count);
        return Ok(());
    }

    if command == "constellation-recovery-split" {
        if paths.len() != 4 {
            return Err("usage: noctyra constellation-recovery-split <archive.nct> <new-output-directory> <shard-bytes> <parity-shards>".into());
        }
        let archive = Zeroizing::new(read_bounded(Path::new(&paths[0]))?);
        let destination = Path::new(&paths[1]);
        if destination.exists() { return Err("output directory already exists; refusing to overwrite".into()); }
        let shard_size = paths[2].to_string_lossy().parse::<usize>()?;
        let parity_count = paths[3].to_string_lossy().parse::<usize>()?;
        let shards = noctyra_core::create_recovery_shards(&archive, shard_size, parity_count)?;
        let parent = destination.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
        let staging = tempfile::Builder::new().prefix(".noctyra-recovery-").tempdir_in(parent)?;
        for (index, shard) in shards.iter().enumerate() {
            let path = staging.path().join(format!("shard-{index:04}.ncrs"));
            let mut file = File::options().write(true).create_new(true).open(path)?;
            file.write_all(shard)?;
            file.sync_all()?;
        }
        let staging_path = staging.keep();
        if let Err(error) = fs::rename(&staging_path, destination) {
            let _ = fs::remove_dir_all(&staging_path);
            return Err(error.into());
        }
        println!("CONSTELLATION recovery set written: {} shards ({} data + {} parity)", shards.len(), shards.len() - parity_count, parity_count);
        return Ok(());
    }

    if command == "constellation-recovery" || command == "constellation-recovery-images" {
        if paths.len() < 2 || paths.len() > noctyra_core::MAX_RECOVERY_SHARDS + 1 {
            return Err("usage: noctyra constellation-recovery <output-archive.nct> <shard1.ncrs> [more-shards...] (or constellation-recovery-images <output-archive.nct> <carrier1.png> [more-carriers...])".into());
        }
        let mut shards = Vec::with_capacity(paths.len() - 1);
        for path in &paths[1..] {
            if command == "constellation-recovery-images" {
                let image_bytes = Zeroizing::new(read_carrier_file(Path::new(path))?);
                let carrier = noctyra_core::CarrierImage::load(&image_bytes)?;
                shards.push(Zeroizing::new(noctyra_core::extract_carrier(&carrier)?));
            } else {
                shards.push(Zeroizing::new(read_limited(
                    Path::new(path),
                    (noctyra_core::MAX_FRAGMENT_DATA_BYTES + noctyra_core::RECOVERY_HEADER_LEN) as u64,
                    "CONSTELLATION recovery shard"
                )?));
            }
        }
        let refs: Vec<&[u8]> = shards.iter().map(|shard| shard.as_slice()).collect();
        let report = noctyra_core::inspect_recovery_shards(refs.iter().copied())?;
        if !report.recoverable {
            return Err(format!("not enough shards: received {}, need at least {}", report.received_shards, report.data_shards).into());
        }
        let archive = Zeroizing::new(noctyra_core::recover_archive(refs)?);
        let output = Path::new(&paths[0]);
        let mut temp = temporary_output(output)?;
        temp.as_file_mut().write_all(&archive)?;
        publish(temp, output)?;
        println!("CONSTELLATION recovery succeeded from {} of {} shards", report.received_shards, report.data_shards as usize + report.parity_shards as usize);
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
        _ => return Err("usage: noctyra encrypt <file> <archive.nct> | decrypt <archive.nct> <file> | encrypt-dir <directory> <archive.nct> | decrypt-dir <archive.nct> <new-directory> | cleanup-staging <parent-directory> | carrier-embed <carrier-image> <encrypted-archive.nct> <output-image> | carrier-extract <carrier-image> <output-archive.nct> | constellation-split <archive.nct> <new-output-directory> [fragment-bytes] | constellation-inspect <fragment-1.ncfr> [more-fragments...] | constellation-inspect-images <carrier-image1> [more-carriers...] | constellation-reassemble <output-archive.nct> <fragment-1.ncfr> [fragment-2.ncfr ...] | constellation-encode <archive.nct> <new-output-directory> <cover-image1> [cover-image2 ...] | constellation-reassemble-images <output-archive.nct> <carrier-image1> [carrier-image2 ...] | constellation-recovery-encode <archive.nct> <new-output-directory> <shard-bytes> <parity-shards> <cover-image1> [more-images...] | constellation-recovery-split <archive.nct> <new-output-directory> <shard-bytes> <parity-shards> | constellation-recovery <output-archive.nct> <shard1.ncrs> [more-shards...] | constellation-recovery-images <output-archive.nct> <carrier1.png> [more-carriers...] | constellation-send <plaintext-file> <new-package-directory> <identity.nckv> <shard-bytes> <parity-shards> <cover-image1> [more-images...] | constellation-receive <output-plaintext-file> <manifest.ncmf> <registry.ncts> <trusted-fingerprint> <carrier1.png> [more-carriers...] | vault-create <identity.nckv> | vault-inspect <identity.nckv> | vault-export-public <identity.nckv> <public-key.bin> | vault-rotate <old.nckv> <new.nckv> <rotation.ncrt> | verify-rotation <rotation.ncrt> <trusted-old-public-key.bin> | trust-init <registry.ncts> | trust-add <registry.ncts> <public-key.bin> <label> <expected-fingerprint> | trust-rotate <registry.ncts> <old-fingerprint> <rotation.ncrt> <new-public-key.bin> <label> <expected-new-fingerprint> | trust-list <registry.ncts> | trust-revoke <registry.ncts> <fingerprint> | trust-check <registry.ncts> <fingerprint> | constellation-keygen <private-key-file> <public-key-file> | constellation-manifest-create <shard1.ncrs> [more-shards...] <private-key-file> <manifest.ncmf> | constellation-manifest-verify-recovery <output.nct> <manifest.ncmf> <trusted-public-key-file> <shard1.ncrs> [more-shards...] | constellation-manifest-verify-trusted-recovery <output.nct> <manifest.ncmf> <registry.ncts> <trusted-fingerprint> <shard1.ncrs> [more-shards...]".into()),
    }

    println!("Operation completed: {}", output.display());
    Ok(())
}


#[cfg(test)]
mod end_to_end_tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn encrypted_signed_trusted_recovery_round_trip() {
        let plaintext = b"NOCTYRA end-to-end integration test payload".repeat(100);

        // Sender encrypts the plaintext before any carrier or recovery encoding.
        let mut encrypted_archive = tempfile::tempfile().unwrap();
        noctyra_core::encrypt_stream(
            b"separate archive password",
            Cursor::new(plaintext.clone()),
            &mut encrypted_archive,
        ).unwrap();
        encrypted_archive.seek(SeekFrom::Start(0)).unwrap();
        let mut archive = Vec::new();
        encrypted_archive.read_to_end(&mut archive).unwrap();

        // Sender unlocks an encrypted signing identity and signs the complete shard set.
        let vault = noctyra_core::create_vault(b"vault password").unwrap();
        let signing_key = noctyra_core::unlock_vault(b"vault password", &vault).unwrap();
        let public_key = signing_key.verifying_key().to_bytes();
        let shards = noctyra_core::create_recovery_shards(&archive, 512, 2).unwrap();
        let shard_refs: Vec<&[u8]> = shards.iter().map(Vec::as_slice).collect();
        let manifest = noctyra_core::create_signed_manifest_for_shards(
            shard_refs.iter().copied(),
            &signing_key,
        ).unwrap();

        // Recipient trusts the sender only after explicitly provisioning its public key.
        let mut trust = noctyra_core::TrustStore::default();
        let fingerprint = trust.add(public_key, "integration sender".to_owned()).unwrap();
        let registry = noctyra_core::save_trust_store(b"registry password", &trust).unwrap();
        let reopened = noctyra_core::open_trust_store(b"registry password", &registry).unwrap();
        let pinned_key = reopened.trusted_public_key(&fingerprint).unwrap();
        let verified = noctyra_core::verify_signed_manifest(&manifest, &pinned_key).unwrap();

        // Lose two shards; verify signed digests and reconstruct from the remaining carriers.
        let surviving: Vec<&[u8]> = shards.iter().enumerate()
            .filter(|(index, _)| !matches!(index, 0 | 2))
            .map(|(_, shard)| shard.as_slice())
            .collect();
        let report = noctyra_core::verify_manifest_shards(&verified, surviving.iter().copied()).unwrap();
        assert!(report.recoverable);
        let recovered_archive = noctyra_core::recover_archive(surviving.iter().copied()).unwrap();
        assert_eq!(recovered_archive, archive);

        // Only publish plaintext after the NCT AEAD authentication completes.
        let mut recovered_plaintext = tempfile::tempfile().unwrap();
        noctyra_core::decrypt_stream(
            b"separate archive password",
            Cursor::new(recovered_archive),
            &mut recovered_plaintext,
        ).unwrap();
        recovered_plaintext.seek(SeekFrom::Start(0)).unwrap();
        let mut actual = Vec::new();
        recovered_plaintext.read_to_end(&mut actual).unwrap();
        assert_eq!(actual, plaintext);
    }
}

