//! Bounded create-only files. Partial/uncertain writes are preserved, never replayed.
use super::types::*;
use alloy_primitives::B256;
use serde::de::DeserializeOwned;
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
};

pub(super) struct Directory {
    path: PathBuf,
}

/// The OS mode is evidence, not an assertion that Windows ACLs were inspected.
pub struct AccessReport {
    pub unix_directory_mode: Option<u32>,
    pub windows_acl_inspected: bool,
}

impl Directory {
    /// An operator provisions the dedicated directory and its ACL outside the
    /// publisher. Opening it starts no effect and claims no request durability.
    pub(super) fn open(path: &Path) -> Result<Self, HandoffError> {
        let path = checked_existing(path, true)?;
        Ok(Self { path })
    }
    pub(super) fn access_report(&self) -> Result<AccessReport, HandoffError> {
        #[cfg(unix)]
        let mode = {
            use std::os::unix::fs::PermissionsExt;
            Some(
                fs::metadata(&self.path)
                    .map_err(|_| HandoffError::Io)?
                    .permissions()
                    .mode()
                    & 0o777,
            )
        };
        #[cfg(not(unix))]
        let mode = None;
        Ok(AccessReport {
            unix_directory_mode: mode,
            windows_acl_inspected: false,
        })
    }
    pub(super) fn request_path(&self, id: B256) -> PathBuf {
        self.path.join(format!("request-{}.json", hex::encode(id)))
    }
    pub(super) fn write_request(
        &self,
        id: B256,
        bytes: &[u8],
        stage: &mut ExportStage,
    ) -> Result<(), HandoffError> {
        if bytes.len() > MAX_DOCUMENT_BYTES {
            return Err(HandoffError::Bounds);
        }
        checked_existing(&self.path, true)?;
        let path = self.request_path(id);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            options.custom_flags(0x0020_0000).share_mode(0);
        }
        let mut file = options.open(&path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                HandoffError::AlreadyExists
            } else {
                HandoffError::Io
            }
        })?;
        *stage = ExportStage::FileCreated;
        file.write_all(bytes).map_err(|_| HandoffError::Io)?;
        file.sync_all().map_err(|_| HandoffError::Io)?;
        *stage = ExportStage::FileSynced;
        // Release the Windows deny-share handle before querying the path.
        drop(file);
        // Recheck before the namespace barrier. Failure after creation leaves
        // the exact file for investigation; there is no truncate/delete retry.
        checked_existing(&path, false)?;
        sync_directory(&self.path)?;
        *stage = ExportStage::DirectorySynced;
        Ok(())
    }
    pub(super) fn read_request(&self, id: B256) -> Result<RequestDocument, HandoffError> {
        read_document(&self.request_path(id))
    }
}

pub(super) fn read_document<T: DeserializeOwned>(path: &Path) -> Result<T, HandoffError> {
    let path = checked_existing(path, false)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x0020_0000).share_mode(1);
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(0x0002_0000);
    }
    let file = options.open(&path).map_err(|_| HandoffError::Io)?;
    let before = file.metadata().map_err(|_| HandoffError::Io)?;
    if !before.is_file() || redirected(&before) || before.len() > MAX_DOCUMENT_BYTES as u64 {
        return Err(HandoffError::Bounds);
    }
    let mut bytes = Vec::new();
    (&file)
        .take(MAX_DOCUMENT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| HandoffError::Io)?;
    let after = file.metadata().map_err(|_| HandoffError::Io)?;
    if bytes.len() > MAX_DOCUMENT_BYTES
        || bytes.len() as u64 != before.len()
        || after.len() != before.len()
        || after.modified().ok() != before.modified().ok()
        || checked_existing(&path, false)? != path
    {
        return Err(HandoffError::Io);
    }
    serde_json::from_slice(&bytes).map_err(|_| HandoffError::Format)
}

fn checked_existing(path: &Path, directory: bool) -> Result<PathBuf, HandoffError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir))
    {
        return Err(HandoffError::InvalidPath);
    }
    let mut ancestor = PathBuf::new();
    for part in path.components() {
        ancestor.push(part.as_os_str());
        if matches!(part, Component::Prefix(_)) {
            continue;
        }
        let metadata = fs::symlink_metadata(&ancestor).map_err(|_| HandoffError::InvalidPath)?;
        if redirected(&metadata) {
            return Err(HandoffError::InvalidPath);
        }
    }
    let metadata = fs::metadata(path).map_err(|_| HandoffError::InvalidPath)?;
    if directory && !metadata.is_dir() || !directory && !metadata.is_file() {
        return Err(HandoffError::InvalidPath);
    }
    let path = fs::canonicalize(path).map_err(|_| HandoffError::InvalidPath)?;
    if !project_drive(&path) {
        return Err(HandoffError::InvalidPath);
    }
    Ok(path)
}

fn redirected(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return true;
        }
    }
    metadata.file_type().is_symlink()
}
fn project_drive(path: &Path) -> bool {
    #[cfg(windows)]
    {
        use std::path::Prefix;
        matches!(path.components().next(), Some(Component::Prefix(prefix))
            if matches!(prefix.kind(), Prefix::Disk(letter) | Prefix::VerbatimDisk(letter) if letter.eq_ignore_ascii_case(&b'E')))
    }
    #[cfg(not(windows))]
    {
        path.starts_with("/mnt/e")
    }
}

fn sync_directory(path: &Path) -> Result<(), HandoffError> {
    #[cfg(windows)]
    let directory = {
        use std::os::windows::fs::OpenOptionsExt;
        // BACKUP_SEMANTICS opens the directory itself. File sync is not a
        // substitute: if the OS rejects this flush, report unknown durability.
        OpenOptions::new()
            .read(true)
            .custom_flags(0x0220_0000)
            .open(path)
    };
    #[cfg(not(windows))]
    let directory = fs::File::open(path);
    directory
        .and_then(|directory| directory.sync_all())
        .map_err(|_| HandoffError::DirectoryDurabilityUnconfirmed)
}
