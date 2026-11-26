//! Bounded-memory directory archive serialization over the NCT v2 stream.
//!
//! The plaintext stream is NMF2: magic, entry count, then sorted entry records.
//! File bytes immediately follow each file record. File contents are never
//! accumulated in memory. Extraction first authenticates the complete NCT
//! stream into an anonymous temporary file, validates the complete manifest,
//! and only then creates the destination tree.

use std::{
    collections::{HashMap, HashSet},
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Component, Path, PathBuf},
    time::{Duration, SystemTime},
};

use zeroize::{Zeroize, Zeroizing};

use crate::{decrypt_stream, encrypt_stream, ContainerError, STREAM_CHUNK_SIZE};

const TREE_MAGIC: &[u8; 4] = b"NMF2";
const MAX_ENTRIES: usize = 100_000;
const MAX_PATH_BYTES: usize = 4_096;
const MAX_TOTAL_PATH_BYTES: usize = 64 * 1024 * 1024;
const MAX_DIRECTORY_BYTES: u64 = 1 << 40; // 1 TiB safety ceiling.
const STAGING_PREFIX: &str = ".noctyra-staging-";
const STAGING_MARKER: &str = ".noctyra-staging-marker";
const STAGING_MARKER_CONTENT: &[u8] = b"NOCTYRA-STAGING-DIRECTORY-V1\\n";
const MIN_STALE_AGE: Duration = Duration::from_secs(24 * 60 * 60);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EntryKind { Directory = 0, File = 1 }

#[derive(Clone, Debug)]
struct SourceEntry {
    path: String,
    kind: EntryKind,
    size: u64,
    source: PathBuf,
    modified: SystemTime,
}

fn io_error(error: io::Error) -> ContainerError {
    ContainerError::Io(error.to_string())
}

fn relative_name(root: &Path, path: &Path) -> Result<String, ContainerError> {
    let relative = path.strip_prefix(root).map_err(|_| ContainerError::InvalidTree)?;
    let mut pieces = Vec::new();
    for component in relative.components() {
        match component {
            Component::Normal(part) => {
                let text = part.to_str().ok_or(ContainerError::InvalidTree)?;
                if text.is_empty() || text == "." || text == ".."
                    || text.chars().any(|ch| matches!(ch, '/' | '\\' | ':' | '\0'))
                    || text.ends_with(' ') || text.ends_with('.') {
                    return Err(ContainerError::InvalidTree);
                }
                pieces.push(text);
            }
            _ => return Err(ContainerError::InvalidTree),
        }
    }
    if pieces.is_empty() { return Err(ContainerError::InvalidTree); }
    let name = pieces.join("/");
    if name.len() > MAX_PATH_BYTES { return Err(ContainerError::TooLarge); }
    Ok(name)
}

fn collect_entries(root: &Path, current: &Path, entries: &mut Vec<SourceEntry>, total: &mut u64, path_bytes: &mut usize) -> Result<(), ContainerError> {
    let mut children = fs::read_dir(current).map_err(io_error)?
        .map(|item| item.map_err(io_error))
        .collect::<Result<Vec<_>, _>>()?;
    children.sort_by_key(|entry| entry.file_name());

    for child in children {
        let path = child.path();
        let metadata = fs::symlink_metadata(&path).map_err(io_error)?;
        if metadata.file_type().is_symlink() { return Err(ContainerError::InvalidTree); }
        let name = relative_name(root, &path)?;
        *path_bytes = path_bytes.checked_add(name.len()).ok_or(ContainerError::TooLarge)?;
        if *path_bytes > MAX_TOTAL_PATH_BYTES { return Err(ContainerError::TooLarge); }

        if metadata.is_dir() {
            entries.push(SourceEntry { path: name, kind: EntryKind::Directory, size: 0, source: path.clone(), modified: metadata.modified().map_err(io_error)? });
            if entries.len() > MAX_ENTRIES { return Err(ContainerError::TooManyEntries); }
            collect_entries(root, &path, entries, total, path_bytes)?;
        } else if metadata.is_file() {
            *total = total.checked_add(metadata.len()).ok_or(ContainerError::TooLarge)?;
            if *total > MAX_DIRECTORY_BYTES { return Err(ContainerError::TooLarge); }
            entries.push(SourceEntry { path: name, kind: EntryKind::File, size: metadata.len(), source: path, modified: metadata.modified().map_err(io_error)? });
            if entries.len() > MAX_ENTRIES { return Err(ContainerError::TooManyEntries); }
        } else {
            return Err(ContainerError::InvalidTree);
        }
    }
    Ok(())
}

/// A Read adapter that emits the NMF2 manifest and file contents one at a time.
struct DirectoryReader {
    entries: Vec<SourceEntry>,
    index: usize,
    pending: Vec<u8>,
    pending_offset: usize,
    active_file: Option<File>,
    active_remaining: u64,
    active_expected_modified: Option<SystemTime>,
    active_expected_size: u64,
}

impl DirectoryReader {
    fn new(entries: Vec<SourceEntry>) -> Result<Self, ContainerError> {
        let count = u32::try_from(entries.len()).map_err(|_| ContainerError::TooManyEntries)?;
        let mut pending = Vec::with_capacity(8);
        pending.extend_from_slice(TREE_MAGIC);
        pending.extend_from_slice(&count.to_le_bytes());
        Ok(Self {
            entries,
            index: 0,
            pending,
            pending_offset: 0,
            active_file: None,
            active_remaining: 0,
            active_expected_modified: None,
            active_expected_size: 0,
        })
    }

    fn prepare_entry(&mut self) -> Result<bool, io::Error> {
        if self.index >= self.entries.len() { return Ok(false); }
        let entry = &self.entries[self.index];
        let path = entry.path.as_bytes();
        let mut header = Vec::with_capacity(13 + path.len());
        header.push(entry.kind as u8);
        header.extend_from_slice(&(path.len() as u32).to_le_bytes());
        header.extend_from_slice(&entry.size.to_le_bytes());
        header.extend_from_slice(path);
        self.pending = header;
        self.pending_offset = 0;

        if entry.kind == EntryKind::File {
            // Check the path and the opened handle independently. This rejects
            // ordinary symlink substitution and files changed since enumeration.
            let path_meta = fs::symlink_metadata(&entry.source)?;
            if path_meta.file_type().is_symlink() || !path_meta.is_file() {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "source changed to a non-regular file"));
            }
            let file = File::open(&entry.source)?;
            let opened_meta = file.metadata()?;
            if !opened_meta.is_file() || opened_meta.len() != entry.size
                || opened_meta.modified().ok() != Some(entry.modified) {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "source file changed after enumeration"));
            }
            self.active_remaining = entry.size;
            self.active_expected_size = entry.size;
            self.active_expected_modified = Some(entry.modified);
            self.active_file = Some(file);
        } else {
            self.active_remaining = 0;
        }
        self.index += 1;
        Ok(true)
    }
}

impl Read for DirectoryReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() { return Ok(0); }
        let mut written = 0;

        while written < output.len() {
            if self.pending_offset < self.pending.len() {
                let count = (self.pending.len() - self.pending_offset).min(output.len() - written);
                output[written..written + count]
                    .copy_from_slice(&self.pending[self.pending_offset..self.pending_offset + count]);
                self.pending_offset += count;
                written += count;
                continue;
            }

            if let Some(file) = self.active_file.as_mut() {
                if self.active_remaining == 0 {
                    let metadata = file.metadata()?;
                    if metadata.len() != self.active_expected_size
                        || metadata.modified().ok() != self.active_expected_modified {
                        return Err(io::Error::new(io::ErrorKind::InvalidData, "source file changed while being archived"));
                    }
                    self.active_file = None;
                    self.active_expected_modified = None;
                    continue;
                }
                let limit = usize::try_from(self.active_remaining.min((output.len() - written) as u64))
                    .unwrap_or(output.len() - written);
                let count = file.read(&mut output[written..written + limit])?;
                if count == 0 {
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "source file shortened during archive creation"));
                }
                self.active_remaining -= count as u64;
                written += count;
                continue;
            }

            if !self.prepare_entry()? { break; }
        }

        Ok(written)
    }
}

/// Encrypt a directory tree into an NCT v2 stream without buffering file contents.
pub fn encrypt_directory_stream<W: Write>(
    password: &[u8],
    source: impl AsRef<Path>,
    writer: W,
) -> Result<(), ContainerError> {
    let source = source.as_ref();
    let metadata = fs::symlink_metadata(source).map_err(io_error)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(ContainerError::InvalidTree);
    }
    let root = fs::canonicalize(source).map_err(io_error)?;
    let mut entries = Vec::new();
    let mut total = 0u64;
    let mut path_bytes = 0usize;
    collect_entries(&root, &root, &mut entries, &mut total, &mut path_bytes)?;
    entries.sort_by(|a, b| a.path.cmp(&b.path));

    let reader = DirectoryReader::new(entries)?;
    encrypt_stream(password, reader, writer)
}

fn validate_archive_path(path: &str) -> Result<(), ContainerError> {
    if path.is_empty() || path.len() > MAX_PATH_BYTES || path.starts_with('/')
        || path.chars().any(|ch| matches!(ch, '\\' | '\0' | ':')) {
        return Err(ContainerError::InvalidTree);
    }
    for part in path.split('/') {
        let upper = part.split('.').next().unwrap_or(part).to_ascii_uppercase();
        let reserved = matches!(upper.as_str(), "CON" | "PRN" | "AUX" | "NUL")
            || (upper.len() == 4 && (upper.starts_with("COM") || upper.starts_with("LPT"))
                && matches!(upper.as_bytes()[3], b'1'..=b'9'));
        if part.is_empty() || part == "." || part == ".."
            || part.ends_with(' ') || part.ends_with('.')
            || reserved
            || part.chars().any(|ch| ch.is_control() || matches!(ch, '\\' | '\0' | ':' | '<' | '>' | '"' | '|' | '?' | '*')) {
            return Err(ContainerError::InvalidTree);
        }
    }
    for component in Path::new(path).components() {
        if !matches!(component, Component::Normal(_)) { return Err(ContainerError::InvalidTree); }
    }
    Ok(())
}

#[derive(Debug)]
struct ExtractEntry {
    path: String,
    kind: EntryKind,
    offset: u64,
    size: u64,
}

fn read_u32<R: Read>(reader: &mut R) -> Result<u32, ContainerError> {
    let mut bytes = [0u8; 4];
    reader.read_exact(&mut bytes).map_err(|_| ContainerError::Malformed)?;
    Ok(u32::from_le_bytes(bytes))
}

fn read_u64<R: Read>(reader: &mut R) -> Result<u64, ContainerError> {
    let mut bytes = [0u8; 8];
    reader.read_exact(&mut bytes).map_err(|_| ContainerError::Malformed)?;
    Ok(u64::from_le_bytes(bytes))
}

fn validate_manifest<R: Read + Seek>(file: &mut R) -> Result<Vec<ExtractEntry>, ContainerError> {
    file.seek(SeekFrom::Start(0)).map_err(io_error)?;
    let mut magic = [0u8; 4];
    file.read_exact(&mut magic).map_err(|_| ContainerError::Malformed)?;
    if &magic != TREE_MAGIC { return Err(ContainerError::Malformed); }
    let count = read_u32(file)? as usize;
    if count > MAX_ENTRIES { return Err(ContainerError::TooManyEntries); }

    let mut entries = Vec::with_capacity(count);
    let mut names = HashSet::with_capacity(count);
    let mut kinds = HashMap::with_capacity(count);
    let mut total_bytes = 0u64;
    let mut total_path_bytes = 0usize;

    for _ in 0..count {
        let mut kind_byte = [0u8; 1];
        file.read_exact(&mut kind_byte).map_err(|_| ContainerError::Malformed)?;
        let kind = match kind_byte[0] {
            0 => EntryKind::Directory,
            1 => EntryKind::File,
            _ => return Err(ContainerError::Malformed),
        };
        let path_len = read_u32(file)? as usize;
        let size = read_u64(file)?;
        if path_len == 0 || path_len > MAX_PATH_BYTES || size > MAX_DIRECTORY_BYTES {
            return Err(ContainerError::TooLarge);
        }
        if kind == EntryKind::Directory && size != 0 { return Err(ContainerError::Malformed); }
        total_path_bytes = total_path_bytes.checked_add(path_len).ok_or(ContainerError::TooLarge)?;
        if total_path_bytes > MAX_TOTAL_PATH_BYTES { return Err(ContainerError::TooLarge); }

        let mut path_bytes = vec![0u8; path_len];
        file.read_exact(&mut path_bytes).map_err(|_| ContainerError::Malformed)?;
        let path = String::from_utf8(path_bytes).map_err(|_| ContainerError::InvalidTree)?;
        validate_archive_path(&path)?;
        let folded = path.to_lowercase();
        if !names.insert(folded.clone()) { return Err(ContainerError::InvalidTree); }
        kinds.insert(folded, kind);

        total_bytes = total_bytes.checked_add(size).ok_or(ContainerError::TooLarge)?;
        if total_bytes > MAX_DIRECTORY_BYTES { return Err(ContainerError::TooLarge); }
        let offset = file.stream_position().map_err(io_error)?;
        let next = offset.checked_add(size).ok_or(ContainerError::TooLarge)?;
        file.seek(SeekFrom::Start(next)).map_err(io_error)?;
        entries.push(ExtractEntry { path, kind, offset, size });
    }

    let end = file.stream_position().map_err(io_error)?;
    let actual = file.seek(SeekFrom::End(0)).map_err(io_error)?;
    if end != actual { return Err(ContainerError::Malformed); }

    for entry in &entries {
        let parts: Vec<&str> = entry.path.split('/').collect();
        let mut parent = String::new();
        for part in parts.iter().take(parts.len().saturating_sub(1)) {
            if !parent.is_empty() { parent.push('/'); }
            parent.push_str(part);
            if kinds.get(&parent.to_lowercase()).is_some_and(|kind| *kind == EntryKind::File) {
                return Err(ContainerError::InvalidTree);
            }
        }
    }
    Ok(entries)
}

/// Validate an NMF2 directory manifest from an already authenticated plaintext stream.
/// Exposed for fuzzing and diagnostics; callers must not treat this as authentication.
pub fn validate_directory_manifest<R: Read + Seek>(reader: &mut R) -> Result<(), ContainerError> {
    validate_manifest(reader).map(|_| ())
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), ContainerError> {
    File::open(path).and_then(|file| file.sync_all()).map_err(io_error)
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<(), ContainerError> {
    // Rust's portable std API does not expose directory-handle flushing on
    // every supported platform. Files are still fsynced before publication.
    Ok(())
}

fn sync_tree_directories(root: &Path) -> Result<(), ContainerError> {
    let mut children = fs::read_dir(root).map_err(io_error)?
        .map(|entry| entry.map_err(io_error))
        .collect::<Result<Vec<_>, _>>()?;
    children.sort_by_key(|entry| entry.file_name());
    for child in children {
        let path = child.path();
        let metadata = fs::symlink_metadata(&path).map_err(io_error)?;
        if metadata.file_type().is_symlink() { return Err(ContainerError::InvalidTree); }
        if metadata.is_dir() { sync_tree_directories(&path)?; }
    }
    sync_directory(root)
}

/// Remove only NOCTYRA-marked staging directories older than 24 hours.
/// This is an explicit recovery action for leftovers after a process or machine crash.
/// It never scans outside the supplied parent directory.
pub fn cleanup_stale_staging(parent: impl AsRef<Path>) -> Result<usize, ContainerError> {
    let parent = parent.as_ref();
    let mut removed = 0usize;
    let entries = fs::read_dir(parent).map_err(io_error)?;
    for entry in entries {
        let entry = entry.map_err(io_error)?;
        let path = entry.path();
        let name = entry.file_name();
        if !name.to_string_lossy().starts_with(STAGING_PREFIX) { continue; }
        let metadata = fs::symlink_metadata(&path).map_err(io_error)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() { continue; }
        let marker = path.join(STAGING_MARKER);
        let marker_meta = match fs::symlink_metadata(&marker) {
            Ok(value) => value,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(io_error(error)),
        };
        if !marker_meta.is_file() || marker_meta.file_type().is_symlink() { continue; }
        let mut marker_bytes = Vec::new();
        File::open(&marker).map_err(io_error)?.read_to_end(&mut marker_bytes).map_err(io_error)?;
        if marker_bytes != STAGING_MARKER_CONTENT { continue; }
        let modified = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);
        if SystemTime::now().duration_since(modified).unwrap_or_default() < MIN_STALE_AGE { continue; }
        fs::remove_dir_all(&path).map_err(io_error)?;
        removed = removed.checked_add(1).ok_or(ContainerError::TooLarge)?;
    }
    if removed > 0 { sync_directory(parent)?; }
    Ok(removed)
}

/// Authenticate an NCT v2 directory archive, validate it, then publish a complete
/// extracted directory with a same-filesystem no-clobber rename. Plaintext remains
/// in a private staging directory until every file has been written and synced.
pub fn decrypt_directory_stream(
    password: &[u8],
    reader: impl Read,
    destination: impl AsRef<Path>,
) -> Result<(), ContainerError> {
    let mut authenticated_plaintext = tempfile::tempfile().map_err(io_error)?;
    decrypt_stream(password, reader, &mut authenticated_plaintext)?;
    let entries = validate_manifest(&mut authenticated_plaintext)?;

    let destination = destination.as_ref();
    if destination.exists() { return Err(ContainerError::DestinationExists); }
    let parent = destination.parent().filter(|path| !path.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let file_name = destination.file_name().ok_or(ContainerError::InvalidTree)?;
    if file_name.is_empty() { return Err(ContainerError::InvalidTree); }

    let staging = tempfile::Builder::new().prefix(STAGING_PREFIX).tempdir_in(parent).map_err(io_error)?;
    let marker_path = staging.path().join(STAGING_MARKER);
    let payload_path = staging.path().join("payload");
    fs::create_dir(&payload_path).map_err(io_error)?;
    let mut marker = OpenOptions::new().write(true).create_new(true).open(&marker_path).map_err(io_error)?;
    marker.write_all(STAGING_MARKER_CONTENT).map_err(io_error)?;
    marker.sync_all().map_err(io_error)?;

    let extraction = (|| -> Result<(), ContainerError> {
        let mut buffer = Zeroizing::new(vec![0u8; STREAM_CHUNK_SIZE]);
        for entry in entries {
            let mut output = payload_path.clone();
            for part in entry.path.split('/') { output.push(part); }
            match entry.kind {
                EntryKind::Directory => fs::create_dir_all(&output).map_err(io_error)?,
                EntryKind::File => {
                    if let Some(parent) = output.parent() { fs::create_dir_all(parent).map_err(io_error)?; }
                    let mut target = OpenOptions::new().write(true).create_new(true).open(&output).map_err(io_error)?;
                    authenticated_plaintext.seek(SeekFrom::Start(entry.offset)).map_err(io_error)?;
                    let mut remaining = entry.size;
                    while remaining > 0 {
                        let count = usize::try_from(remaining.min(buffer.len() as u64)).unwrap_or(buffer.len());
                        authenticated_plaintext.read_exact(&mut buffer[..count]).map_err(|_| ContainerError::Malformed)?;
                        target.write_all(&buffer[..count]).map_err(io_error)?;
                        buffer[..count].zeroize();
                        remaining -= count as u64;
                    }
                    target.sync_all().map_err(io_error)?;
                }
            }
        }
        sync_tree_directories(&payload_path)?;
        Ok(())
    })();

    if let Err(error) = extraction { return Err(error); }
    drop(marker);
    sync_directory(&payload_path)?;

    // The marker stays in the private sibling staging directory while the payload
    // is renamed. A crash before publication leaves a marked directory for the
    // explicit stale-staging cleanup; a crash after publication leaves only an
    // empty marked staging shell, never a marker inside the user's recovered tree.
    let staging_path = staging.keep();
    let staged_payload = staging_path.join("payload");
    if let Err(error) = fs::rename(&staged_payload, destination) {
        let _ = fs::remove_dir_all(&staging_path);
        return Err(io_error(error));
    }
    let _ = fs::remove_dir_all(&staging_path);
    sync_directory(parent)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn directory_stream_round_trip_large_nested_and_empty_files() {
        let source_parent = tempfile::tempdir().unwrap();
        let source = source_parent.path().join("source");
        fs::create_dir_all(source.join("nested/deeper")).unwrap();
        fs::create_dir(source.join("empty-dir")).unwrap();
        fs::write(source.join("empty-file"), []).unwrap();
        let large = (0..(STREAM_CHUNK_SIZE * 2 + 333)).map(|i| (i % 251) as u8).collect::<Vec<_>>();
        fs::write(source.join("nested/deeper/large.bin"), &large).unwrap();

        let mut archive = Vec::new();
        encrypt_directory_stream(b"directory streaming password", &source, &mut archive).unwrap();
        let output_parent = tempfile::tempdir().unwrap();
        let output = output_parent.path().join("restored");
        decrypt_directory_stream(b"directory streaming password", Cursor::new(archive), &output).unwrap();

        assert_eq!(fs::read(output.join("nested/deeper/large.bin")).unwrap(), large);
        assert_eq!(fs::read(output.join("empty-file")).unwrap(), []);
        assert!(output.join("empty-dir").is_dir());
    }

    #[test]
    fn directory_stream_wrong_password_does_not_create_destination() {
        let source_parent = tempfile::tempdir().unwrap();
        let source = source_parent.path().join("source");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("file"), b"secret").unwrap();
        let mut archive = Vec::new();
        encrypt_directory_stream(b"correct", &source, &mut archive).unwrap();

        let output_parent = tempfile::tempdir().unwrap();
        let output = output_parent.path().join("restored");
        assert!(matches!(
            decrypt_directory_stream(b"wrong", Cursor::new(archive), &output),
            Err(ContainerError::Crypto(_))
        ));
        assert!(!output.exists());
    }

    fn manifest_entry(kind: u8, path: &str, size: u64) -> Vec<u8> {
        let mut bytes = vec![kind];
        bytes.extend_from_slice(&(path.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&size.to_le_bytes());
        bytes.extend_from_slice(path.as_bytes());
        bytes
    }

    #[test]
    fn manifest_accepts_empty_tree_and_rejects_traversal() {
        let mut empty = b"NMF2".to_vec();
        empty.extend_from_slice(&0u32.to_le_bytes());
        assert!(validate_directory_manifest(&mut Cursor::new(empty)).is_ok());

        let mut traversal = b"NMF2".to_vec();
        traversal.extend_from_slice(&1u32.to_le_bytes());
        traversal.extend_from_slice(&manifest_entry(1, "../escape", 0));
        assert!(validate_directory_manifest(&mut Cursor::new(traversal)).is_err());
    }

    #[test]
    fn manifest_rejects_case_collisions_and_file_parent_conflicts() {
        let mut collisions = b"NMF2".to_vec();
        collisions.extend_from_slice(&2u32.to_le_bytes());
        collisions.extend_from_slice(&manifest_entry(1, "Data.bin", 0));
        collisions.extend_from_slice(&manifest_entry(1, "data.BIN", 0));
        assert!(validate_directory_manifest(&mut Cursor::new(collisions)).is_err());

        let mut conflict = b"NMF2".to_vec();
        conflict.extend_from_slice(&2u32.to_le_bytes());
        conflict.extend_from_slice(&manifest_entry(1, "parent", 0));
        conflict.extend_from_slice(&manifest_entry(0, "parent/child", 0));
        assert!(validate_directory_manifest(&mut Cursor::new(conflict)).is_err());
    }

    #[test]
    fn manifest_rejects_excessive_entry_count_and_trailing_bytes() {
        let mut excessive = b"NMF2".to_vec();
        excessive.extend_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(validate_directory_manifest(&mut Cursor::new(excessive)), Err(ContainerError::TooManyEntries)));

        let mut trailing = b"NMF2".to_vec();
        trailing.extend_from_slice(&0u32.to_le_bytes());
        trailing.push(0);
        assert!(validate_directory_manifest(&mut Cursor::new(trailing)).is_err());
    }

    #[test]
    fn directory_stream_rejects_truncation_and_trailing_bytes() {
        let source_parent = tempfile::tempdir().unwrap();
        let source = source_parent.path().join("source");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("file"), b"payload").unwrap();
        let mut archive = Vec::new();
        encrypt_directory_stream(b"password", &source, &mut archive).unwrap();

        let output_parent = tempfile::tempdir().unwrap();
        let output = output_parent.path().join("restored");
        let truncated = archive[..archive.len() - 1].to_vec();
        assert!(decrypt_directory_stream(b"password", Cursor::new(truncated), &output).is_err());
        assert!(!output.exists());
        archive.push(0);
        assert!(decrypt_directory_stream(b"password", Cursor::new(archive), &output).is_err());
        assert!(!output.exists());
    }
}
