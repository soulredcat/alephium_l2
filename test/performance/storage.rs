//! Fresh benchmark storage retained on both success and failure; no Drop deletion.
use std::{
    fs,
    path::{Component, Path, PathBuf},
};

pub(super) struct Workspace {
    pub directory: PathBuf,
    pub data_dir: PathBuf,
    pub root_volume: String,
}

pub(super) fn workspace(output: &Path, count: usize) -> Result<Workspace, String> {
    if !matches!(count, 1_000 | 10_000 | 100_000) {
        return Err("Benchmark storage requires one selected transaction count".into());
    }
    let project = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or("Cannot derive the main repository root")?;
    if !project.is_absolute()
        || !output.is_absolute()
        || output
            .components()
            .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
    {
        return Err("Benchmark output requires an absolute canonical directory path".into());
    }
    reject_redirects(project)?;
    let project = canonical(project)?;
    let private = creation_path(&project)?.join("test/private");
    reject_redirects(&private)?;
    reject_redirects(output)?;
    let private = canonical(&private)?;
    let output = canonical(output)?;
    let root_volume = volume(&project)?;
    if !private.starts_with(&project)
        || !output.starts_with(&private)
        || volume(&private)? != root_volume
        || volume(&output)? != root_volume
    {
        return Err(
            "Benchmark output must remain under main/test/private on the project volume".into(),
        );
    }
    let directory = creation_path(&output)?.join(format!("tx-{count}"));
    // create_dir fails when any entry already exists, including a dangling link.
    // Later failures intentionally leave this reservation and all data in place.
    fs::create_dir(&directory).map_err(|_| "Cannot reserve fresh benchmark count directory")?;
    reject_redirects(&directory)?;
    let owned = canonical(&directory)?;
    if canonical(output.as_path())? != output
        || owned.parent() != Some(output.as_path())
        || volume(&owned)? != root_volume
    {
        return Err("Benchmark count directory changed its verified parent or volume".into());
    }
    let data_dir = directory.join("data");
    fs::create_dir(&data_dir).map_err(|_| "Cannot create fresh benchmark data directory")?;
    reject_redirects(&data_dir)?;
    let data = canonical(&data_dir)?;
    if canonical(&directory)? != owned
        || data.parent() != Some(owned.as_path())
        || volume(&data)? != root_volume
    {
        return Err("Benchmark data directory changed its verified parent or volume".into());
    }
    Ok(Workspace {
        directory,
        data_dir,
        root_volume,
    })
}

fn canonical(path: &Path) -> Result<PathBuf, String> {
    fs::canonicalize(path).map_err(|_| "Cannot resolve benchmark directory".to_owned())
}

fn reject_redirects(path: &Path) -> Result<(), String> {
    for ancestor in path.ancestors() {
        let metadata = fs::symlink_metadata(ancestor)
            .map_err(|_| "Cannot inspect benchmark directory ancestry")?;
        #[cfg(windows)]
        let reparse = {
            use std::os::windows::fs::MetadataExt;
            metadata.file_attributes() & 0x400 != 0
        };
        #[cfg(not(windows))]
        let reparse = false;
        if reparse || metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(
                "Benchmark ancestry must contain only real directories without redirection".into(),
            );
        }
    }
    Ok(())
}

#[cfg(windows)]
fn volume(path: &Path) -> Result<String, String> {
    use std::path::Prefix;
    match path.components().next() {
        Some(Component::Prefix(prefix)) => match prefix.kind() {
            Prefix::Disk(letter) | Prefix::VerbatimDisk(letter)
                if letter.eq_ignore_ascii_case(&b'E') =>
            {
                Ok("E:".into())
            }
            _ => Err("Benchmark storage must use the main project drive E:".into()),
        },
        _ => Err("Benchmark directory must have an absolute drive path".into()),
    }
}

#[cfg(unix)]
fn volume(path: &Path) -> Result<String, String> {
    use std::os::unix::fs::MetadataExt;
    Ok(format!(
        "device:{}",
        fs::metadata(path)
            .map_err(|_| "Cannot inspect benchmark storage volume")?
            .dev()
    ))
}

#[cfg(not(any(windows, unix)))]
fn volume(_: &Path) -> Result<String, String> {
    Err("Benchmark storage volume inspection is unsupported".into())
}

#[cfg(windows)]
fn creation_path(path: &Path) -> Result<PathBuf, String> {
    use std::path::Prefix;
    let mut components = path.components();
    let drive = match components.next() {
        Some(Component::Prefix(prefix)) => match prefix.kind() {
            Prefix::Disk(letter) | Prefix::VerbatimDisk(letter) => letter,
            _ => return Err("Benchmark canonical path is not a local drive path".into()),
        },
        _ => return Err("Benchmark canonical path has no drive".into()),
    };
    // Store expects ordinary drive paths; canonicalize produces a verbatim prefix.
    let mut ordinary = PathBuf::from(format!("{}:\\", drive as char));
    for part in components {
        match part {
            Component::RootDir => (),
            Component::Normal(name) => ordinary.push(name),
            _ => return Err("Unexpected canonical benchmark path component".into()),
        }
    }
    Ok(ordinary)
}

#[cfg(not(windows))]
fn creation_path(path: &Path) -> Result<PathBuf, String> {
    Ok(path.to_path_buf())
}
