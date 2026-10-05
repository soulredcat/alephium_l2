use super::FileEntry;
use crate::storage::path;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, Metadata, OpenOptions},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
};

pub(super) const MAX_FILES: usize = 16_384;
pub(super) const MAX_BYTES: u64 = 64 * 1024 * 1024 * 1024;
const MAX_DIRECTORIES: usize = 16_384;

pub(super) fn owned_directory(input: &Path) -> Result<PathBuf, String> {
    normalized_canonical(path::existing_owned(input)?)
}

pub(super) fn existing_directory(input: &Path) -> Result<PathBuf, String> {
    let absolute = path::checked_absolute(input)?;
    directory(&fs::symlink_metadata(&absolute).map_err(io_error)?)?;
    normalized_canonical(fs::canonicalize(absolute).map_err(io_error)?)
}

/// Existing parents are required. Outputs are never merged with existing data.
pub(super) fn fresh_directory(input: &Path, excluded: &Path) -> Result<PathBuf, String> {
    let absolute = path::checked_absolute(input)?;
    let parent = existing_directory(absolute.parent().ok_or("Missing output parent")?)?;
    let target = parent.join(
        absolute
            .file_name()
            .ok_or("Missing output directory name")?,
    );
    let excluded = existing_directory(excluded)?;
    disjoint(&target, &excluded)?;
    match fs::symlink_metadata(&target) {
        Ok(_) => return Err("Backup/replay output already exists; overwrite is forbidden".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(io_error(error)),
    }
    fs::create_dir(&target).map_err(io_error)?;
    existing_directory(&target)
}

fn disjoint(left: &Path, right: &Path) -> Result<(), String> {
    let components = |path: &Path| -> Vec<String> {
        path.components()
            .map(|part| {
                let name = part.as_os_str().to_string_lossy().into_owned();
                if cfg!(windows) {
                    name.to_lowercase()
                } else {
                    name
                }
            })
            .collect()
    };
    let left = components(left);
    let right = components(right);
    if left.starts_with(&right) || right.starts_with(&left) {
        Err("Backup/replay output must be outside and must not contain its source".into())
    } else {
        Ok(())
    }
}

fn normalized_canonical(input: PathBuf) -> Result<PathBuf, String> {
    #[cfg(windows)]
    {
        // canonicalize adds a verbatim prefix; our public path guard admits only local drives.
        let value = input.to_str().ok_or("Non-UTF-8 operator path")?;
        Ok(PathBuf::from(value.strip_prefix(r"\\?\").unwrap_or(value)))
    }
    #[cfg(not(windows))]
    {
        Ok(input)
    }
}

pub(super) fn lock_database(root: &Path) -> Result<File, String> {
    let target = root.join("lock");
    let metadata = fs::symlink_metadata(&target).map_err(io_error)?;
    regular(&metadata)?;
    if metadata.len() != 0 {
        return Err("Development database lock must already exist and be empty".into());
    }
    // Pinned Fjall 3.1.12 uses this same exclusive standard-library lock.
    // Opening the existing coordination file does not write source bytes.
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(target)
        .map_err(io_error)?;
    if file.metadata().map_err(io_error)?.len() != 0 {
        return Err("Development database lock changed during inspection".into());
    }
    file.try_lock().map_err(|error| match error {
        std::fs::TryLockError::WouldBlock => {
            "Development database lock is held; stop its owned node before backup".into()
        }
        std::fs::TryLockError::Error(error) => io_error(error),
    })?;
    Ok(file)
}

pub(super) fn safe_relative(value: &str) -> Result<PathBuf, String> {
    if value.is_empty()
        || value.len() > 1_024
        || value.contains(['\\', ':'])
        || value.chars().any(char::is_control)
    {
        return Err("Invalid backup relative file path".into());
    }
    let parts: Vec<_> = value.split('/').collect();
    if parts.len() > 64 {
        return Err("Backup path nesting limit exceeded".into());
    }
    for part in &parts {
        let stem = part
            .split('.')
            .next()
            .unwrap_or_default()
            .to_ascii_uppercase();
        if part.is_empty()
            || *part == "."
            || *part == ".."
            || part.ends_with(['.', ' '])
            || matches!(
                stem.as_str(),
                "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
            )
            || ["COM", "LPT"].iter().any(|prefix| {
                stem.strip_prefix(prefix)
                    .is_some_and(|n| n.len() == 1 && matches!(n.as_bytes()[0], b'1'..=b'9'))
            })
        {
            return Err("Ambiguous backup relative file path".into());
        }
    }
    let path = PathBuf::from(value);
    if path
        .components()
        .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err("Backup file path must be strictly relative".into());
    }
    Ok(path)
}

fn walk(root: &Path) -> Result<(Vec<PathBuf>, Vec<PathBuf>), String> {
    let mut pending = vec![PathBuf::new()];
    let mut directories = Vec::new();
    let mut files = Vec::new();
    while let Some(relative) = pending.pop() {
        let current = root.join(&relative);
        path::checked_absolute(&current)?;
        directory(&fs::symlink_metadata(&current).map_err(io_error)?)?;
        directories.push(relative.clone());
        if directories.len() + pending.len() > MAX_DIRECTORIES {
            return Err("Backup directory count limit exceeded".into());
        }
        for item in fs::read_dir(current).map_err(io_error)? {
            let item = item.map_err(io_error)?;
            let relative = relative.join(item.file_name());
            let name = relative
                .to_str()
                .ok_or("Non-UTF-8 backup file path")?
                .replace('\\', "/");
            safe_relative(&name)?;
            let metadata = fs::symlink_metadata(item.path()).map_err(io_error)?;
            if metadata.is_dir() {
                directory(&metadata)?;
                if directories.len() + pending.len() >= MAX_DIRECTORIES {
                    return Err("Backup directory count limit exceeded".into());
                }
                pending.push(relative);
            } else {
                regular(&metadata)?;
                files.push(relative);
                if files.len() > MAX_FILES {
                    return Err("Backup file count limit exceeded".into());
                }
            }
        }
    }
    files.sort();
    directories.sort();
    Ok((directories, files))
}

pub(super) fn inventory(root: &Path) -> Result<Vec<FileEntry>, String> {
    let (_, paths) = walk(root)?;
    let mut total = 0u64;
    let mut entries = paths
        .into_iter()
        .map(|relative| {
            let entry = hash_file(&root.join(&relative), &relative)?;
            total = total
                .checked_add(entry.length)
                .ok_or("Backup size overflow")?;
            if total > MAX_BYTES {
                return Err("Backup byte limit exceeded".into());
            }
            Ok(entry)
        })
        .collect::<Result<Vec<_>, String>>()?;
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(entries)
}

fn hash_file(path: &Path, relative: &Path) -> Result<FileEntry, String> {
    let metadata = fs::symlink_metadata(path).map_err(io_error)?;
    regular(&metadata)?;
    if relative == Path::new("lock") && metadata.len() == 0 {
        // An exclusive Windows coordination lock forbids reading its byte range.
        return Ok(FileEntry {
            path: "lock".into(),
            length: 0,
            sha256: hex::encode(Sha256::digest([])),
        });
    }
    let mut file = File::open(path).map_err(io_error)?;
    let length = file.metadata().map_err(io_error)?.len();
    if length > MAX_BYTES {
        return Err("Backup file byte limit exceeded".into());
    }
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 65_536];
    let mut read = 0u64;
    loop {
        let count = file.read(&mut buffer).map_err(io_error)?;
        if count == 0 {
            break;
        }
        read += count as u64;
        if read > length {
            return Err("Backup file changed during hashing".into());
        }
        hash.update(&buffer[..count]);
    }
    if read != length {
        return Err("Backup file changed during hashing".into());
    }
    Ok(FileEntry {
        path: relative
            .to_str()
            .ok_or("Non-UTF-8 backup file path")?
            .replace('\\', "/"),
        length,
        sha256: hex::encode(hash.finalize()),
    })
}

pub(super) fn copy_tree(source: &Path, destination: &Path) -> Result<(), String> {
    let (directories, paths) = walk(source)?;
    let mut total = 0u64;
    for relative in directories
        .into_iter()
        .filter(|path| !path.as_os_str().is_empty())
    {
        fs::create_dir(destination.join(relative)).map_err(io_error)?;
    }
    for relative in paths {
        let source_file = source.join(&relative);
        let metadata = fs::symlink_metadata(&source_file).map_err(io_error)?;
        regular(&metadata)?;
        total = total
            .checked_add(metadata.len())
            .ok_or("Backup size overflow")?;
        if total > MAX_BYTES {
            return Err("Backup byte limit exceeded".into());
        }
        let mut target = File::create_new(destination.join(&relative)).map_err(io_error)?;
        if relative != Path::new("lock") {
            let file = File::open(source_file).map_err(io_error)?;
            let copied =
                std::io::copy(&mut file.take(metadata.len() + 1), &mut target).map_err(io_error)?;
            if copied != metadata.len() {
                return Err("Source file changed during copy".into());
            }
        } else if metadata.len() != 0 {
            return Err("Source coordination lock is not empty".into());
        }
        target.flush().map_err(io_error)?;
        target.sync_all().map_err(io_error)?;
    }
    synchronize(destination)
}

pub(super) fn synchronize(root: &Path) -> Result<(), String> {
    let (directories, files) = walk(root)?;
    for relative in files {
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(root.join(relative))
            .map_err(io_error)?
            .sync_all()
            .map_err(io_error)?;
    }
    for relative in directories.into_iter().rev() {
        sync_directory(&root.join(relative))?;
    }
    Ok(())
}

pub(super) fn sync_directory(path: &Path) -> Result<(), String> {
    #[cfg(not(windows))]
    File::open(path)
        .map_err(io_error)?
        .sync_all()
        .map_err(io_error)?;
    #[cfg(windows)]
    let _ = path; // Same unresolved directory-persistence limit as pinned Fjall.
    Ok(())
}

pub(super) fn regular(metadata: &Metadata) -> Result<(), String> {
    if redirected(metadata) || !metadata.is_file() {
        Err("Backup contains a redirected or nonregular file".into())
    } else {
        Ok(())
    }
}

fn directory(metadata: &Metadata) -> Result<(), String> {
    if redirected(metadata) || !metadata.is_dir() {
        Err("Backup contains a redirected or nondirectory path".into())
    } else {
        Ok(())
    }
}

fn redirected(metadata: &Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        metadata.file_type().is_symlink() || metadata.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    {
        metadata.file_type().is_symlink()
    }
}

pub(super) fn io_error(error: std::io::Error) -> String {
    format!("Development backup filesystem error: {error}")
}
