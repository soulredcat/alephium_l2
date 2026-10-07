//! Fresh private fixture output on the verified project drive, never default TEMP.
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

pub(super) fn workspace() -> Result<PathBuf, String> {
    let project = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or("Cannot derive fixture project root")?;
    checked_directory(project)?;
    let root = if let Some(path) = std::env::var_os("L2_P4_DEVELOPMENT_OUTPUT") {
        let root = PathBuf::from(path);
        if !root.is_absolute() {
            return Err("P4 fixture output must be a new absolute local directory".into());
        }
        checked_directory(root.parent().ok_or("Missing output parent")?)?;
        fs::create_dir(&root).map_err(|_| "Cannot create fresh P4 fixture output")?;
        root
    } else {
        let local = project.join(".local");
        if !local.exists() {
            fs::create_dir(&local).map_err(|_| "Cannot create project-local fixture base")?;
        }
        checked_directory(&local)?;
        tempfile::Builder::new()
            .prefix("p4-development-")
            .tempdir_in(&local)
            .map_err(|_| "Cannot create project-local fixture output")?
            .keep()
    };
    checked_directory(&root)?;
    if volume(&root)? != volume(project)? {
        return Err("P4 fixture output changed project storage volume".into());
    }
    fs::create_dir(root.join("data")).map_err(|_| "Cannot create owned fixture data")?;
    checked_directory(&root.join("data"))?;
    Ok(root)
}

fn checked_directory(path: &Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err("Fixture storage must use absolute project-drive paths".into());
    }
    for ancestor in path.ancestors() {
        let metadata = fs::symlink_metadata(ancestor)
            .map_err(|_| "Cannot inspect fixture storage ancestry")?;
        #[cfg(windows)]
        let redirected = {
            use std::os::windows::fs::MetadataExt;
            metadata.file_attributes() & 0x400 != 0
        };
        #[cfg(not(windows))]
        let redirected = metadata.file_type().is_symlink();
        if redirected || metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err("Fixture storage ancestry must contain real directories only".into());
        }
    }
    #[cfg(windows)]
    if volume(path)? != "E:" {
        return Err("P4 development fixtures must stay on the project E: drive".into());
    }
    #[cfg(unix)]
    if !path.starts_with("/mnt/e") {
        return Err("P4 development fixtures require the explicit E: mount".into());
    }
    Ok(())
}

#[cfg(windows)]
fn volume(path: &Path) -> Result<String, String> {
    use std::path::{Component, Prefix};
    match path.components().next() {
        Some(Component::Prefix(prefix)) => match prefix.kind() {
            Prefix::Disk(letter) | Prefix::VerbatimDisk(letter) => {
                Ok(format!("{}:", (letter as char).to_ascii_uppercase()))
            }
            _ => Err("Fixture storage cannot use device or network paths".into()),
        },
        _ => Err("Fixture storage has no local drive".into()),
    }
}

#[cfg(unix)]
fn volume(path: &Path) -> Result<String, String> {
    use std::os::unix::fs::MetadataExt;
    Ok(format!(
        "device:{}",
        fs::metadata(path)
            .map_err(|_| "Cannot verify fixture filesystem")?
            .dev()
    ))
}

#[cfg(not(any(windows, unix)))]
fn volume(_path: &Path) -> Result<String, String> {
    Err("Fixture storage verification is unsupported on this platform".into())
}

/// Unsigned plans, genesis and reports are synchronized before further work.
pub(super) fn write_json(path: &Path, value: &impl serde::Serialize) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| "Cannot create fresh private fixture record")?;
    serde_json::to_writer_pretty(&mut file, value)
        .map_err(|_| "Cannot encode private fixture record")?;
    file.write_all(b"\n")
        .map_err(|_| "Cannot finish fixture record")?;
    file.sync_all()
        .map_err(|_| "Cannot sync fixture record".to_owned())
}
