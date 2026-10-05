//! Owned burst storage on the source project's filesystem, never default TEMP.
use std::{
    fs,
    io::ErrorKind,
    path::{Path, PathBuf},
};

pub(super) struct Workspace {
    pub directory: tempfile::TempDir,
    pub data_dir: PathBuf,
    pub root_volume: String,
}

fn reject_redirects(path: &Path) -> Result<(), String> {
    for component in path.ancestors() {
        let metadata = fs::symlink_metadata(component).map_err(|e| e.to_string())?;
        #[cfg(windows)]
        let redirected = {
            use std::os::windows::fs::MetadataExt;
            metadata.file_attributes() & 0x400 != 0
        };
        #[cfg(not(windows))]
        let redirected = metadata.file_type().is_symlink();
        if redirected || metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err("Burst storage ancestry must contain only real directories".into());
        }
    }
    Ok(())
}

fn create_owned_directory(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(_) => (),
        Err(error) if error.kind() == ErrorKind::NotFound => {
            fs::create_dir(path).map_err(|e| e.to_string())?;
        }
        Err(error) => return Err(error.to_string()),
    }
    reject_redirects(path)
}

#[cfg(windows)]
fn volume(path: &Path) -> Result<String, String> {
    use std::path::{Component, Prefix};
    match path.components().next() {
        Some(Component::Prefix(prefix)) => match prefix.kind() {
            Prefix::Disk(letter) | Prefix::VerbatimDisk(letter) => {
                Ok(format!("{}:", (letter as char).to_ascii_uppercase()))
            }
            _ => Err("Burst source project requires a Windows drive-letter path".into()),
        },
        _ => Err("Burst source project must have an absolute Windows path".into()),
    }
}

#[cfg(unix)]
fn volume(path: &Path) -> Result<String, String> {
    use std::os::unix::fs::MetadataExt;
    Ok(format!(
        "device:{}",
        fs::metadata(path).map_err(|e| e.to_string())?.dev()
    ))
}

#[cfg(not(any(windows, unix)))]
fn volume(_path: &Path) -> Result<String, String> {
    Err("Burst storage volume checks are unavailable on this platform".into())
}

#[cfg(windows)]
fn creation_path(canonical: &Path) -> Result<PathBuf, String> {
    use std::path::{Component, Prefix};
    let mut components = canonical.components();
    let letter = match components.next() {
        Some(Component::Prefix(prefix)) => match prefix.kind() {
            Prefix::Disk(letter) | Prefix::VerbatimDisk(letter) => letter,
            _ => return Err("Canonical burst path is not a local drive path".into()),
        },
        _ => return Err("Canonical burst path has no drive".into()),
    };
    // Store creation deliberately accepts ordinary drive paths, while Windows
    // canonicalize returns a verbatim prefix. Preserve all native path names.
    let mut ordinary = PathBuf::from(format!("{}:\\", letter as char));
    for component in components {
        match component {
            Component::RootDir => (),
            Component::Normal(name) => ordinary.push(name),
            _ => return Err("Unexpected canonical burst path component".into()),
        }
    }
    Ok(ordinary)
}

#[cfg(not(windows))]
fn creation_path(canonical: &Path) -> Result<PathBuf, String> {
    Ok(canonical.to_path_buf())
}

pub(super) fn workspace() -> Result<Workspace, String> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let source_project = manifest
        .parent()
        .and_then(Path::parent)
        .ok_or("Cannot derive source project from node crate location")?;
    if !source_project.is_absolute() {
        return Err("Source project location must be absolute".into());
    }
    reject_redirects(source_project)?;
    let source_volume = volume(source_project)?;
    let project = fs::canonicalize(source_project).map_err(|e| e.to_string())?;
    if volume(&project)? != source_volume {
        return Err("Canonical source project changed storage volume".into());
    }
    let local = creation_path(&project)?.join(".local");
    create_owned_directory(&local)?;
    let base = local.join("burst-data");
    create_owned_directory(&base)?;
    let canonical_base = fs::canonicalize(&base).map_err(|e| e.to_string())?;
    if !canonical_base.starts_with(&project) || volume(&canonical_base)? != source_volume {
        return Err("Burst base is outside the source project or its storage volume".into());
    }
    let directory = tempfile::Builder::new()
        .prefix("owned-burst-")
        .tempdir_in(&base)
        .map_err(|e| e.to_string())?;
    reject_redirects(directory.path())?;
    let owned = fs::canonicalize(directory.path()).map_err(|e| e.to_string())?;
    if !owned.starts_with(&canonical_base) || volume(&owned)? != source_volume {
        return Err("Owned burst directory changed project storage volume".into());
    }
    let data_dir = directory.path().join("data");
    create_owned_directory(&data_dir)?;
    let canonical_data = fs::canonicalize(&data_dir).map_err(|e| e.to_string())?;
    if !canonical_data.starts_with(&owned) || volume(&canonical_data)? != source_volume {
        return Err("Burst database changed project storage volume".into());
    }
    Ok(Workspace {
        directory,
        data_dir,
        root_volume: source_volume,
    })
}
