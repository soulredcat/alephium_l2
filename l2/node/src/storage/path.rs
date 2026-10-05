use std::{
    fs::{self, Metadata, OpenOptions},
    io::Write,
    path::{Component, Path, PathBuf},
};

const MARKER: &str = ".alephium-l2-development";
const IDENTITY: &[u8] = b"alephium-l2-development-schema-1\n";
const FORBIDDEN_MARKERS: [&str; 4] = [
    "L2_DEVELOPMENT_IDENTITY",
    "L2_PRODUCTION_IDENTITY",
    ".alephium-l2-production",
    "ALEPHIUM_L2_PRODUCTION",
];

/// Inspect an already owned source without creating directories or markers.
pub(crate) fn existing_owned(path: &Path) -> Result<PathBuf, String> {
    let absolute = checked_absolute(path)?;
    check_directory(&fs::symlink_metadata(&absolute).map_err(error_text)?)?;
    let marker = absolute.join(MARKER);
    check_marker(&marker, &fs::symlink_metadata(&marker).map_err(error_text)?)?;
    fs::canonicalize(absolute).map_err(error_text)
}

/// Validate path syntax and all existing ancestors without filesystem writes.
pub(crate) fn checked_absolute(path: &Path) -> Result<PathBuf, String> {
    let absolute = absolute_path(path)?;
    check_ancestors(&absolute)?;
    Ok(absolute)
}

/// Check an isolated development path before the storage engine writes files.
/// The directory must be empty or carry this runtime's exact ownership marker.
pub(super) fn guard(path: &Path) -> Result<PathBuf, String> {
    let absolute = absolute_path(path)?;
    check_ancestors(&absolute)?;

    match fs::symlink_metadata(&absolute) {
        Ok(metadata) => {
            check_directory(&metadata)?;
            let marker = absolute.join(MARKER);
            match fs::symlink_metadata(&marker) {
                Ok(metadata) => check_marker(&marker, &metadata)?,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    let mut entries = fs::read_dir(&absolute).map_err(error_text)?;
                    if let Some(entry) = entries.next() {
                        entry.map_err(error_text)?;
                        return Err("Refusing an unrelated nonempty data directory".into());
                    }
                }
                Err(error) => return Err(error_text(error)),
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            create_checked_directories(&absolute)?;
        }
        Err(error) => return Err(error_text(error)),
    }
    Ok(absolute)
}

/// Create the ownership marker once; never replace existing identity material.
pub(super) fn mark(path: &Path) -> Result<(), String> {
    let absolute = absolute_path(path)?;
    check_ancestors(&absolute)?;
    let metadata = fs::symlink_metadata(&absolute).map_err(error_text)?;
    check_directory(&metadata)?;
    let marker = absolute.join(MARKER);
    match fs::symlink_metadata(&marker) {
        Ok(metadata) => check_marker(&marker, &metadata),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&marker)
                .map_err(error_text)?;
            file.write_all(IDENTITY).map_err(error_text)?;
            file.sync_all().map_err(error_text)
        }
        Err(error) => Err(error_text(error)),
    }
}

fn absolute_path(path: &Path) -> Result<PathBuf, String> {
    if path.as_os_str().is_empty() {
        return Err("A dedicated development data directory is required".into());
    }
    if path
        .components()
        .any(|part| matches!(part, Component::ParentDir))
    {
        return Err("Data directory traversal is not allowed".into());
    }
    #[cfg(windows)]
    {
        use std::path::Prefix;
        match path.components().next() {
            Some(Component::Prefix(prefix)) => {
                if !matches!(prefix.kind(), Prefix::Disk(_)) || !path.is_absolute() {
                    return Err("Use a local absolute drive path or a relative data path".into());
                }
            }
            _ if path.has_root() => {
                return Err("Drive-relative rooted data paths are not allowed".into());
            }
            _ => {}
        }
        for part in path.components() {
            if let Component::Normal(name) = part {
                let name = name.to_string_lossy();
                if name.ends_with(['.', ' ']) || name.contains(':') {
                    return Err("Ambiguous Windows data path components are not allowed".into());
                }
            }
        }
    }
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().map_err(error_text)?.join(path)
    };
    let normalized: PathBuf = path.components().collect();
    if normalized.parent().is_none() {
        return Err("A filesystem root cannot be used as a data directory".into());
    }
    let mut previous = None;
    for part in normalized.components() {
        if let Component::Normal(name) = part {
            if previous.as_deref() == Some(".local")
                && name
                    .to_string_lossy()
                    .eq_ignore_ascii_case("l2-development")
            {
                return Err("The legacy development directory belongs to another runtime".into());
            }
            previous = Some(name.to_string_lossy().to_ascii_lowercase());
        }
    }
    Ok(normalized)
}

fn check_ancestors(path: &Path) -> Result<(), String> {
    let mut current = PathBuf::new();
    for part in path.components() {
        current.push(part.as_os_str());
        if !current.is_absolute() {
            continue;
        }
        match fs::symlink_metadata(&current) {
            Ok(metadata) => {
                check_directory(&metadata)?;
                for name in FORBIDDEN_MARKERS {
                    match fs::symlink_metadata(current.join(name)) {
                        Ok(_) => {
                            return Err("Legacy or production storage paths are forbidden".into());
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                        Err(error) => return Err(error_text(error)),
                    }
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) => return Err(error_text(error)),
        }
    }
    Ok(())
}

fn create_checked_directories(path: &Path) -> Result<(), String> {
    let mut current = PathBuf::new();
    for part in path.components() {
        current.push(part.as_os_str());
        if !current.is_absolute() {
            continue;
        }
        match fs::symlink_metadata(&current) {
            Ok(metadata) => check_directory(&metadata)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(&current).map_err(error_text)?;
                let metadata = fs::symlink_metadata(&current).map_err(error_text)?;
                check_directory(&metadata)?;
            }
            Err(error) => return Err(error_text(error)),
        }
    }
    Ok(())
}

fn check_directory(metadata: &Metadata) -> Result<(), String> {
    if redirected(metadata) {
        return Err("Redirected storage paths (symlink/reparse point) are forbidden".into());
    }
    if !metadata.is_dir() {
        return Err("A storage path component is not a directory".into());
    }
    Ok(())
}

fn check_marker(path: &Path, metadata: &Metadata) -> Result<(), String> {
    if redirected(metadata) || !metadata.is_file() || metadata.len() != IDENTITY.len() as u64 {
        return Err("Invalid development storage ownership marker".into());
    }
    if fs::read(path).map_err(error_text)? != IDENTITY {
        return Err("Incompatible development storage ownership marker".into());
    }
    Ok(())
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

fn error_text(error: std::io::Error) -> String {
    format!("Development storage path error: {error}")
}
