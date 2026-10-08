//! Fresh project-drive metadata only; no overwrite, cleanup or raw payload log.
use serde_json::Value;
use std::{
    fs,
    io::Write,
    path::{Component, Path, PathBuf},
};

pub(super) fn fresh_output(path: &Path) -> Result<PathBuf, String> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir))
    {
        return Err("Funding output requires an absolute non-traversing project-drive path".into());
    }
    #[cfg(windows)]
    if !matches!(path.components().next(), Some(Component::Prefix(prefix))
        if matches!(prefix.kind(), std::path::Prefix::Disk(letter) if letter.eq_ignore_ascii_case(&b'E')))
    {
        return Err("Funding metadata must stay on the E project drive".into());
    }
    #[cfg(not(windows))]
    if !path.starts_with("/mnt/e") {
        return Err("Funding metadata requires the checked project mount".into());
    }
    let parent = path.parent().ok_or("Funding output parent is missing")?;
    reject_links(parent)?;
    if !parent.is_dir() || path.file_name().is_none() || path.exists() {
        return Err("Funding output must be a new directory beneath an existing parent".into());
    }
    #[cfg(unix)]
    let mut builder = fs::DirBuilder::new();
    #[cfg(not(unix))]
    let builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(path)
        .map_err(|_| "Cannot create fresh owned funding output")?;
    reject_links(path)?;
    path.canonicalize()
        .map_err(|_| "Cannot resolve owned funding output".into())
}

pub(super) fn reject_links(path: &Path) -> Result<(), String> {
    for ancestor in path.ancestors() {
        let metadata =
            fs::symlink_metadata(ancestor).map_err(|_| "Cannot inspect funding path ancestry")?;
        if metadata.file_type().is_symlink() {
            return Err("Funding paths must not traverse symlinks".into());
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if metadata.file_attributes() & 0x400 != 0 {
                return Err("Funding paths must not traverse reparse points".into());
            }
        }
    }
    Ok(())
}

pub(super) fn write_json(directory: &Path, name: &str, value: &Value) -> Result<(), String> {
    reject_links(directory)?;
    if !matches!(name, "intent.json" | "success.json" | "failure.json") {
        return Err("Unknown funding metadata report name".into());
    }
    let bytes =
        serde_json::to_vec_pretty(value).map_err(|_| "Cannot encode private funding metadata")?;
    if bytes.len() > 1_048_576 {
        return Err("Funding metadata exceeds the bounded report size".into());
    }
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(directory.join(name))
        .map_err(|_| "Cannot create new private funding metadata")?;
    file.write_all(&bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| "Cannot flush private funding metadata".into())
}
