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
};

use zeroize::{Zeroize, Zeroizing};

use crate::{decrypt_stream, encrypt_stream, ContainerError, STREAM_CHUNK_SIZE};

const TREE_MAGIC: &[u8; 4] = b"NMF2";
const MAX_ENTRIES: usize = 100_000;
const MAX_PATH_BYTES: usize = 4_096;
const MAX_TOTAL_PATH_BYTES: usize = 64 * 1024 * 1024;
const MAX_DIRECTORY_BYTES: u64 = 1 << 40; // 1 TiB safety ceiling.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EntryKind { Directory = 0, File = 1 }

#[derive(Clone, Debug)]
struct SourceEntry {
    path: String,
    kind: EntryKind,
    size: u64,
    source: PathBuf,
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
            entries.push(SourceEntry { path: name, kind: EntryKind::Directory, size: 0, source: path.clone() });
            if entries.len() > MAX_ENTRIES { return Err(ContainerError::TooManyEntries); }
            collect_entries(root, &path, entries, total, path_bytes)?;
        } else if metadata.is_file() {
            *total = total.checked_add(metadata.len()).ok_or(ContainerError::TooLarge)?;
            if *total > MAX_DIRECTORY_BYTES { return Err(ContainerError::TooLarge); }
            entries.push(SourceEntry { path: name, kind: EntryKind::File, size: metadata.len(), source: path });
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
            if !opened_meta.is_file() || opened_meta.len() != entry.size {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "source file changed after enumeration"));
            }
            self.active_remaining = entry.size;
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
                    self.active_file = None;
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

fn validate_manifest(file: &mut File) -> Result<Vec<ExtractEntry>, ContainerError> {
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
    let actual = file.metadata().map_err(io_error)?.len();
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

/// Authenticate an NCT v2 directory archive, validate it, then extract it.
/// Plaintext is staged in an anonymous temporary file until final authentication succeeds.
pub fn decrypt_directory_stream(
    password: &[u8],
    reader: impl Read,
    destination: impl AsRef<Path>,
) -> Result<(), ContainerError> {
    let mut staging = tempfile::tempfile().map_err(io_error)?;
    decrypt_stream(password, reader, &mut staging)?;
    let entries = validate_manifest(&mut staging)?;

    let destination = destination.as_ref();
    if destination.exists() { return Err(ContainerError::DestinationExists); }
    fs::create_dir(destination).map_err(io_error)?;

    let extraction = (|| -> Result<(), ContainerError> {
        let mut buffer = Zeroizing::new(vec![0u8; STREAM_CHUNK_SIZE]);
        for entry in entries {
            let mut output = destination.to_path_buf();
            for part in entry.path.split('/') { output.push(part); }
            match entry.kind {
                EntryKind::Directory => fs::create_dir_all(&output).map_err(io_error)?,
                EntryKind::File => {
                    if let Some(parent) = output.parent() { fs::create_dir_all(parent).map_err(io_error)?; }
                    let mut target = OpenOptions::new().write(true).create_new(true).open(&output).map_err(io_error)?;
                    staging.seek(SeekFrom::Start(entry.offset)).map_err(io_error)?;
                    let mut remaining = entry.size;
                    while remaining > 0 {
                        let count = usize::try_from(remaining.min(buffer.len() as u64)).unwrap_or(buffer.len());
                        staging.read_exact(&mut buffer[..count]).map_err(|_| ContainerError::Malformed)?;
                        target.write_all(&buffer[..count]).map_err(io_error)?;
                        buffer[..count].zeroize();
                        remaining -= count as u64;
                    }
                    target.sync_all().map_err(io_error)?;
                }
            }
        }
        Ok(())
    })();

    if extraction.is_err() { let _ = fs::remove_dir_all(destination); }
    extraction
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
