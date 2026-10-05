use super::{BackupManifest, BackupReport, files};
use crate::{
    protocol::{Genesis, MAX_PENDING, validate_chain_id},
    storage::Store,
};
use std::{
    fs::{self, File},
    io::{Read, Write},
    path::Path,
};

const MANIFEST: &str = "manifest.json";
const MANIFEST_LIMIT: u64 = 4 * 1024 * 1024;
const BACKUP_SCHEMA: u32 = 1;

/// Closed development database copy. The source is never opened by Fjall.
/// Owned paths must not be replaced concurrently by another filesystem writer.
pub fn backup(
    source: &Path,
    destination: &Path,
    genesis: &Genesis,
) -> Result<BackupReport, String> {
    genesis.validate()?;
    let source = files::owned_directory(source)?;
    let source_lock = files::lock_database(&source)?;
    let destination = files::fresh_directory(destination, &source)?;
    let data = destination.join("data");
    fs::create_dir(&data).map_err(files::io_error)?;
    files::copy_tree(&source, &data)?;
    drop(source_lock);

    // Recovery may write engine files, so validate only the newly owned copy.
    let (head, state_digest, pending_count) = {
        let store = Store::open_existing(&data, genesis)?;
        let head = store.view()?.head;
        (head, store.state_digest()?, store.pending()?.len())
    };
    files::synchronize(&data)?;
    let manifest = BackupManifest {
        schema: BACKUP_SCHEMA,
        chain_id: genesis.chain_id,
        head: head.clone(),
        state_digest,
        pending_count,
        files: files::inventory(&data)?,
    };
    validate_manifest(&manifest)?;
    let bytes = manifest.files.iter().map(|file| file.length).sum();
    write_manifest(&destination, &manifest)?;
    Ok(BackupReport {
        head,
        state_digest,
        pending_count,
        file_count: manifest.files.len(),
        bytes,
    })
}

/// Verify an immutable backup, then clone it into a fresh engine working path.
/// No database engine is ever opened on the backup artifact itself.
pub(super) fn materialize_backup(
    backup: &Path,
    working_copy: &Path,
) -> Result<BackupManifest, String> {
    let backup = files::existing_directory(backup)?;
    validate_container(&backup)?;
    let manifest = read_manifest(&backup)?;
    validate_manifest(&manifest)?;
    let data = files::owned_directory(&backup.join("data"))?;
    let _lock = files::lock_database(&data)?;
    if files::inventory(&data)? != manifest.files {
        return Err("Backup file list, lengths or checksums do not match its manifest".into());
    }
    let destination = files::fresh_directory(working_copy, &backup)?;
    files::copy_tree(&data, &destination)?;
    if files::inventory(&destination)? != manifest.files {
        return Err("Backup changed while cloning; working copy is incomplete".into());
    }
    // Detect additions/removals or manifest replacement around the clone boundary.
    validate_container(&backup)?;
    let final_manifest = read_manifest(&backup)?;
    if serde_json::to_vec(&final_manifest).map_err(json_error)?
        != serde_json::to_vec(&manifest).map_err(json_error)?
        || files::inventory(&data)? != manifest.files
    {
        return Err("Backup artifact changed during materialization".into());
    }
    Ok(manifest)
}

fn validate_container(root: &Path) -> Result<(), String> {
    let mut names = Vec::new();
    for entry in fs::read_dir(root).map_err(files::io_error)? {
        let entry = entry.map_err(files::io_error)?;
        names.push(
            entry
                .file_name()
                .into_string()
                .map_err(|_| "Non-UTF-8 backup entry")?,
        );
        if names.len() > 2 {
            return Err("Backup container has unexplained entries".into());
        }
    }
    names.sort();
    if names != ["data", MANIFEST] {
        return Err("Backup is incomplete or contains unexplained entries".into());
    }
    files::existing_directory(&root.join("data"))?;
    files::regular(&fs::symlink_metadata(root.join(MANIFEST)).map_err(files::io_error)?)
}

fn read_manifest(root: &Path) -> Result<BackupManifest, String> {
    let path = root.join(MANIFEST);
    let metadata = fs::symlink_metadata(&path).map_err(files::io_error)?;
    files::regular(&metadata)?;
    if metadata.len() == 0 || metadata.len() > MANIFEST_LIMIT {
        return Err("Backup manifest exceeds its bounded size".into());
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)
        .map_err(files::io_error)?
        .take(MANIFEST_LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(files::io_error)?;
    if bytes.len() as u64 != metadata.len() {
        return Err("Backup manifest changed during read".into());
    }
    serde_json::from_slice(&bytes).map_err(json_error)
}

fn validate_manifest(manifest: &BackupManifest) -> Result<(), String> {
    validate_chain_id(manifest.chain_id)?;
    if manifest.schema != BACKUP_SCHEMA
        || manifest.pending_count > MAX_PENDING
        || manifest.files.is_empty()
        || manifest.files.len() > files::MAX_FILES
    {
        return Err("Unsupported or unbounded development backup manifest".into());
    }
    let mut total = 0u64;
    let mut previous: Option<&str> = None;
    for entry in &manifest.files {
        files::safe_relative(&entry.path)?;
        if previous.is_some_and(|path| path >= entry.path.as_str()) {
            return Err("Backup file paths must be unique and sorted".into());
        }
        previous = Some(&entry.path);
        if entry.sha256.len() != 64
            || !entry
                .sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err("Invalid backup file checksum".into());
        }
        total = total
            .checked_add(entry.length)
            .ok_or("Backup size overflow")?;
        if total > files::MAX_BYTES {
            return Err("Backup byte limit exceeded".into());
        }
    }
    for required in [".alephium-l2-development", "version", "lock"] {
        if !manifest.files.iter().any(|entry| entry.path == required) {
            return Err("Backup manifest omits required database identity files".into());
        }
    }
    if manifest
        .files
        .iter()
        .any(|entry| entry.path == "lock" && entry.length != 0)
    {
        return Err("Backup coordination lock must be empty".into());
    }
    Ok(())
}

fn write_manifest(root: &Path, manifest: &BackupManifest) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(manifest).map_err(json_error)?;
    if bytes.len() as u64 > MANIFEST_LIMIT {
        return Err("Backup manifest exceeds its bounded size".into());
    }
    let temporary = root.join("manifest.partial");
    let mut file = File::create_new(&temporary).map_err(files::io_error)?;
    file.write_all(&bytes).map_err(files::io_error)?;
    file.sync_all().map_err(files::io_error)?;
    drop(file);
    files::sync_directory(&root.join("data"))?;
    files::sync_directory(root)?;
    let complete = root.join(MANIFEST);
    match fs::symlink_metadata(&complete) {
        Ok(_) => return Err("Backup manifest already exists; overwrite is forbidden".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(files::io_error(error)),
    }
    fs::rename(temporary, complete).map_err(files::io_error)?;
    files::sync_directory(root).map_err(|error| format!(
        "Backup manifest was published but directory synchronization failed; verify the artifact before use: {error}"
    ))?;
    Ok(())
}

fn json_error(error: serde_json::Error) -> String {
    format!("Invalid development backup manifest: {error}")
}
