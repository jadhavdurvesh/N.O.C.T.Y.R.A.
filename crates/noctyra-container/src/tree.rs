//! Encrypted multi-file directory archives.
//!
//! The complete file tree is serialized, then sealed as one authenticated NCT
//! payload. Extraction requires a destination directory that does not exist.
//! Symlinks and non-regular filesystem objects are rejected.

use std::{
    collections::{HashMap, HashSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Component, Path},
};
use zeroize::Zeroizing;

use crate::{open, seal, ContainerError};

const TREE_MAGIC: &[u8; 4] = b"NMF1";
const MAX_ENTRIES: usize = 100_000;
const MAX_PATH_BYTES: usize = 4_096;
const MAX_TREE_BYTES: usize = 1024 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EntryKind { Directory = 0, File = 1 }

struct TreeEntry { path: String, kind: EntryKind, bytes: Zeroizing<Vec<u8>> }

fn io_error(error: std::io::Error) -> ContainerError {
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

fn collect_directory(root: &Path, current: &Path, entries: &mut Vec<TreeEntry>, total: &mut usize) -> Result<(), ContainerError> {
    let mut children = fs::read_dir(current).map_err(io_error)?
        .map(|item| item.map_err(io_error))
        .collect::<Result<Vec<_>, _>>()?;
    children.sort_by_key(|entry| entry.file_name());

    for child in children {
        let path = child.path();
        let metadata = fs::symlink_metadata(&path).map_err(io_error)?;
        let name = relative_name(root, &path)?;
        if metadata.file_type().is_symlink() { return Err(ContainerError::InvalidTree); }

        if metadata.is_dir() {
            entries.push(TreeEntry { path: name, kind: EntryKind::Directory, bytes: Zeroizing::new(Vec::new()) });
            if entries.len() > MAX_ENTRIES { return Err(ContainerError::TooManyEntries); }
            collect_directory(root, &path, entries, total)?;
        } else if metadata.is_file() {
            let remaining = MAX_TREE_BYTES.saturating_sub(*total);
            if metadata.len() > remaining as u64 { return Err(ContainerError::TooLarge); }
            let mut bytes = Vec::with_capacity(metadata.len() as usize);
            File::open(&path).map_err(io_error)?.take(remaining as u64 + 1)
                .read_to_end(&mut bytes).map_err(io_error)?;
            if bytes.len() > remaining { return Err(ContainerError::TooLarge); }
            *total = total.checked_add(bytes.len()).ok_or(ContainerError::TooLarge)?;
            entries.push(TreeEntry { path: name, kind: EntryKind::File, bytes: Zeroizing::new(bytes) });
            if entries.len() > MAX_ENTRIES { return Err(ContainerError::TooManyEntries); }
        } else {
            return Err(ContainerError::InvalidTree);
        }
    }
    Ok(())
}

/// Encrypt a complete directory tree. Symlinks and special files are rejected.
pub fn seal_directory(password: &[u8], source: impl AsRef<Path>) -> Result<Vec<u8>, ContainerError> {
    let root = source.as_ref();
    let metadata = fs::symlink_metadata(root).map_err(io_error)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() { return Err(ContainerError::InvalidTree); }
    let root = fs::canonicalize(root).map_err(io_error)?;

    let mut entries = Vec::new();
    let mut total = 0usize;
    collect_directory(&root, &root, &mut entries, &mut total)?;
    entries.sort_by(|a, b| a.path.cmp(&b.path));

    let mut plain = Zeroizing::new(Vec::new());
    plain.extend_from_slice(TREE_MAGIC);
    plain.extend_from_slice(&u32::try_from(entries.len()).map_err(|_| ContainerError::TooManyEntries)?.to_le_bytes());

    for entry in entries {
        let path = entry.path.as_bytes();
        plain.push(entry.kind as u8);
        plain.extend_from_slice(&u32::try_from(path.len()).map_err(|_| ContainerError::TooLarge)?.to_le_bytes());
        plain.extend_from_slice(&u64::try_from(entry.bytes.len()).map_err(|_| ContainerError::TooLarge)?.to_le_bytes());
        plain.extend_from_slice(path);
        plain.extend_from_slice(&entry.bytes);
        if plain.len() > MAX_TREE_BYTES { return Err(ContainerError::TooLarge); }
    }
    seal(password, &plain)
}

struct Cursor<'a> { bytes: &'a [u8], offset: usize }

impl<'a> Cursor<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], ContainerError> {
        let end = self.offset.checked_add(length).ok_or(ContainerError::Malformed)?;
        let value = self.bytes.get(self.offset..end).ok_or(ContainerError::Malformed)?;
        self.offset = end;
        Ok(value)
    }
    fn u8(&mut self) -> Result<u8, ContainerError> { Ok(self.take(1)?[0]) }
    fn u32(&mut self) -> Result<u32, ContainerError> {
        let mut value = [0; 4]; value.copy_from_slice(self.take(4)?); Ok(u32::from_le_bytes(value))
    }
    fn u64(&mut self) -> Result<u64, ContainerError> {
        let mut value = [0; 8]; value.copy_from_slice(self.take(8)?); Ok(u64::from_le_bytes(value))
    }
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

/// Authenticate and extract into a destination directory that must not exist.
/// Partial output is removed if extraction fails.
pub fn extract_directory(password: &[u8], archive: &[u8], destination: impl AsRef<Path>) -> Result<(), ContainerError> {
    let destination = destination.as_ref();
    let plain = Zeroizing::new(open(password, archive)?);
    if plain.len() < 8 || &plain[..4] != TREE_MAGIC { return Err(ContainerError::Malformed); }

    let mut cursor = Cursor { bytes: &plain, offset: 4 };
    let count = cursor.u32()? as usize;
    if count > MAX_ENTRIES { return Err(ContainerError::TooManyEntries); }

    let mut entries: Vec<(String, EntryKind, usize, usize)> = Vec::with_capacity(count);
    let mut names = HashSet::with_capacity(count);
    let mut kinds = HashMap::with_capacity(count);
    let mut total_file_bytes = 0usize;

    for _ in 0..count {
        let kind = match cursor.u8()? {
            0 => EntryKind::Directory,
            1 => EntryKind::File,
            _ => return Err(ContainerError::Malformed),
        };
        let path_len = cursor.u32()? as usize;
        let file_len = usize::try_from(cursor.u64()?).map_err(|_| ContainerError::TooLarge)?;
        if path_len == 0 || path_len > MAX_PATH_BYTES || file_len > MAX_TREE_BYTES { return Err(ContainerError::TooLarge); }
        if kind == EntryKind::Directory && file_len != 0 { return Err(ContainerError::Malformed); }
        let path = std::str::from_utf8(cursor.take(path_len)?).map_err(|_| ContainerError::InvalidTree)?.to_owned();
        validate_archive_path(&path)?;
        if !names.insert(path.to_lowercase()) { return Err(ContainerError::InvalidTree); }
        if kind == EntryKind::File {
            total_file_bytes = total_file_bytes.checked_add(file_len).ok_or(ContainerError::TooLarge)?;
            if total_file_bytes > MAX_TREE_BYTES { return Err(ContainerError::TooLarge); }
        }
        let offset = cursor.offset;
        cursor.take(file_len)?;
        kinds.insert(path.to_lowercase(), kind);
        entries.push((path, kind, offset, file_len));
    }
    if cursor.offset != plain.len() { return Err(ContainerError::Malformed); }

    // Reject children whose parent is explicitly encoded as a regular file.
    for (path, _, _, _) in &entries {
        let parts: Vec<&str> = path.split('/').collect();
        let mut parent = String::new();
        for part in parts.iter().take(parts.len().saturating_sub(1)) {
            if !parent.is_empty() { parent.push('/'); }
            parent.push_str(part);
            if kinds.get(&parent.to_lowercase()).is_some_and(|kind| *kind == EntryKind::File) {
                return Err(ContainerError::InvalidTree);
            }
        }
    }

    if destination.exists() { return Err(ContainerError::DestinationExists); }
    fs::create_dir(destination).map_err(io_error)?;

    let extraction = (|| -> Result<(), ContainerError> {
        for (path, kind, offset, length) in entries {
            let mut output = destination.to_path_buf();
            for part in path.split('/') { output.push(part); }
            match kind {
                EntryKind::Directory => fs::create_dir_all(&output).map_err(io_error)?,
                EntryKind::File => {
                    if let Some(parent) = output.parent() { fs::create_dir_all(parent).map_err(io_error)?; }
                    let mut file = OpenOptions::new().write(true).create_new(true).open(&output).map_err(io_error)?;
                    file.write_all(&plain[offset..offset + length]).map_err(io_error)?;
                    file.sync_all().map_err(io_error)?;
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
    use std::fs;

    #[test]
    fn directory_round_trip_preserves_nested_and_empty_directories() {
        let source_parent = tempfile::tempdir().unwrap();
        let source = source_parent.path().join("source");
        fs::create_dir(&source).unwrap();
        fs::create_dir_all(source.join("nested/deeper")).unwrap();
        fs::create_dir(source.join("empty")).unwrap();
        fs::write(source.join("hello.txt"), b"hello NOCTYRA").unwrap();
        fs::write(source.join("nested/deeper/data.bin"), [0, 1, 2, 255]).unwrap();

        let archive = seal_directory(b"directory passphrase", &source).unwrap();

        let output_parent = tempfile::tempdir().unwrap();
        let output = output_parent.path().join("restored");
        extract_directory(b"directory passphrase", &archive, &output).unwrap();

        assert_eq!(fs::read(output.join("hello.txt")).unwrap(), b"hello NOCTYRA");
        assert_eq!(fs::read(output.join("nested/deeper/data.bin")).unwrap(), [0, 1, 2, 255]);
        assert!(output.join("empty").is_dir());
    }

    #[test]
    fn wrong_password_does_not_create_destination() {
        let source_parent = tempfile::tempdir().unwrap();
        let source = source_parent.path().join("source");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("file"), b"secret").unwrap();
        let archive = seal_directory(b"correct", &source).unwrap();

        let output_parent = tempfile::tempdir().unwrap();
        let output = output_parent.path().join("restored");
        assert!(matches!(
            extract_directory(b"wrong", &archive, &output),
            Err(ContainerError::Crypto(_))
        ));
        assert!(!output.exists());
    }

    #[test]
    fn refuses_existing_destination() {
        let source_parent = tempfile::tempdir().unwrap();
        let source = source_parent.path().join("source");
        fs::create_dir(&source).unwrap();
        let archive = seal_directory(b"password", &source).unwrap();

        let output_parent = tempfile::tempdir().unwrap();
        let output = output_parent.path().join("already-here");
        fs::create_dir(&output).unwrap();
        assert!(matches!(
            extract_directory(b"password", &archive, &output),
            Err(ContainerError::DestinationExists)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn refuses_symbolic_links() {
        use std::os::unix::fs::symlink;
        let source_parent = tempfile::tempdir().unwrap();
        let source = source_parent.path().join("source");
        fs::create_dir(&source).unwrap();
        fs::write(source_parent.path().join("outside"), b"outside").unwrap();
        symlink(source_parent.path().join("outside"), source.join("link")).unwrap();
        assert!(matches!(
            seal_directory(b"password", &source),
            Err(ContainerError::InvalidTree)
        ));
    }
}
