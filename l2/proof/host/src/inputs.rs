//! Bounded regular-file reads; keep one checked handle and reject file changes.

use crate::HostResult;
use sha2::{Digest, Sha256};
use std::{
    fs::{File, Metadata, OpenOptions},
    io::Read,
    path::{Path, PathBuf},
};

pub const MAX_INPUT_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_PROGRAM_BYTES: usize = 32 * 1024 * 1024;

pub struct CheckedFile {
    pub file: File,
    pub length: u64,
    original: Metadata,
    path: PathBuf,
}

impl CheckedFile {
    pub fn open(path: &Path) -> HostResult<Self> {
        let entry = std::fs::symlink_metadata(path)
            .map_err(|_| "Cannot inspect the input artifact entry.")?;
        check_regular(&entry)?;
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::OpenOptionsExt;
            // Linux O_NOFOLLOW rejects a substituted final symlink atomically.
            options.custom_flags(0x0002_0000);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            options.custom_flags(0x0020_0000); // FILE_FLAG_OPEN_REPARSE_POINT
        }
        let file = options
            .open(path)
            .map_err(|_| "Cannot open the bounded regular input artifact.")?;
        let original = file
            .metadata()
            .map_err(|_| "Cannot inspect the opened input artifact.")?;
        check_regular(&original)?;
        if !same_file(&entry, &original) {
            return Err("Input artifact changed while opening.");
        }
        let checked = Self {
            length: original.len(),
            file,
            original,
            path: path.into(),
        };
        checked.check_unchanged()?;
        Ok(checked)
    }

    pub fn check_unchanged(&self) -> HostResult<()> {
        let current = self
            .file
            .metadata()
            .map_err(|_| "Cannot recheck the opened input artifact.")?;
        let entry = std::fs::symlink_metadata(&self.path)
            .map_err(|_| "Input artifact entry disappeared while reading.")?;
        check_regular(&current)?;
        check_regular(&entry)?;
        if !same_file(&self.original, &current) || !same_file(&self.original, &entry) {
            return Err(
                "Input artifact size, identity or modification time changed while reading.",
            );
        }
        Ok(())
    }
}

fn check_regular(metadata: &Metadata) -> HostResult<()> {
    if !metadata.is_file() || metadata.len() == 0 || metadata.modified().is_err() {
        return Err("Input artifact must be a nonempty regular file without a symlink.");
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x0000_0400 != 0 {
            return Err("Input artifact must not be a Windows reparse point.");
        }
    }
    Ok(())
}

fn same_file(before: &Metadata, after: &Metadata) -> bool {
    if before.len() != after.len() || before.modified().ok() != after.modified().ok() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.dev() != after.dev() || before.ino() != after.ino() {
            return false;
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if before.creation_time() != after.creation_time() {
            return false;
        }
    }
    true
}

pub fn read_bounded(path: &Path, maximum: usize) -> HostResult<Vec<u8>> {
    let mut source = CheckedFile::open(path)?;
    let length = usize::try_from(source.length)
        .map_err(|_| "Input artifact byte length is not representable on this host.")?;
    if maximum == 0 || length > maximum {
        return Err("Input artifact exceeds its bounded read limit.");
    }
    let mut bytes = Vec::with_capacity(length);
    (&mut source.file)
        .take(length as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "Cannot read the bounded input artifact.")?;
    if bytes.len() != length {
        return Err("Input artifact became truncated or changed size while reading.");
    }
    source.check_unchanged()?;
    Ok(bytes)
}

pub fn sha256_bounded(path: &Path, maximum: u64) -> HostResult<[u8; 32]> {
    let mut source = CheckedFile::open(path)?;
    if source.length > maximum {
        return Err("Pinned artifact exceeds its bounded hash limit.");
    }
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut read = 0_u64;
    loop {
        let count = source
            .file
            .read(&mut buffer)
            .map_err(|_| "Cannot hash the pinned artifact.")?;
        if count == 0 {
            break;
        }
        read = read
            .checked_add(count as u64)
            .ok_or("Pinned artifact hash length overflow.")?;
        if read > maximum || read > source.length {
            return Err("Pinned artifact changed beyond its bounded hash limit.");
        }
        digest.update(&buffer[..count]);
    }
    if read != source.length {
        return Err("Pinned artifact became truncated while hashing.");
    }
    source.check_unchanged()?;
    Ok(digest.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::{CheckedFile, read_bounded};
    use std::{fs, time::SystemTime};

    #[test]
    fn checked_input_rejects_bounds_changes_and_symlinks() {
        let nonce = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory =
            std::env::temp_dir().join(format!("l2-input-check-{}-{nonce}", std::process::id()));
        fs::create_dir(&directory).unwrap();
        let path = directory.join("input.bin");
        fs::write(&path, b"fixed bytes").unwrap();
        assert_eq!(read_bounded(&path, 11).unwrap(), b"fixed bytes");
        assert!(read_bounded(&path, 10).is_err());
        let source = CheckedFile::open(&path).unwrap();
        fs::write(&path, b"changed length").unwrap();
        assert!(source.check_unchanged().is_err());
        drop(source);
        #[cfg(unix)]
        {
            let link = directory.join("link.bin");
            std::os::unix::fs::symlink(&path, &link).unwrap();
            assert!(CheckedFile::open(&link).is_err());
            fs::remove_file(link).unwrap();
        }
        fs::remove_file(path).unwrap();
        fs::remove_dir(directory).unwrap();
    }
}
