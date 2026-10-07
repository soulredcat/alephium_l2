//! Process-local CPU budget and one owned proof job per pinned prover install.

use crate::HostResult;
use std::{
    env,
    ffi::OsStr,
    fs::{File, OpenOptions},
    path::Path,
};

const LOCK_NAME: &str = ".alephium-l2-proof-worker.lock";
pub const DEFAULT_MAX_CYCLES: u64 = 256 * 1024 * 1024;

pub struct ResourcePolicy {
    pub workers: usize,
    pub available_logical_cpus: usize,
    pub worker_ceiling: usize,
    pub max_cycles: u64,
}

impl ResourcePolicy {
    pub fn select(explicit: Option<usize>, max_cycles: u64) -> HostResult<Self> {
        validate_max_cycles(max_cycles)?;
        let inherited = env::var_os("RAYON_NUM_THREADS");
        let hardware = std::thread::available_parallelism()
            .map(|count| count.get())
            .unwrap_or(1);
        Ok(Self {
            workers: select_workers(explicit, inherited.as_deref(), hardware)?,
            available_logical_cpus: hardware,
            worker_ceiling: worker_ceiling(hardware),
            max_cycles,
        })
    }

    /// Initialize the environment inherited by the SDK's lazily spawned r0vm.
    /// This bounds Rayon parallelism, not total CPU use or Docker resources.
    ///
    /// # Safety
    /// Call only from single-threaded CLI startup, before SDK or native code
    /// can create threads or read the process environment concurrently.
    pub unsafe fn apply_at_startup(&self) {
        // SAFETY: the caller establishes the single-threaded startup condition.
        unsafe { env::set_var("RAYON_NUM_THREADS", self.workers.to_string()) };
    }
}

/// The pinned SDK accepts Some(u64) as its finite user-cycle budget. This
/// capability is separate from the coordinator's authorization for a run.
/// Never silently increase it or use None to disable the resource guard.
pub fn parse_max_cycles(value: &OsStr) -> HostResult<u64> {
    let text = value
        .to_str()
        .ok_or("Cycle budget must be a positive decimal integer representable by u64.")?;
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("Cycle budget must be a positive decimal integer representable by u64.");
    }
    let cycles = text
        .parse::<u64>()
        .map_err(|_| "Cycle budget must be a positive decimal integer representable by u64.")?;
    validate_max_cycles(cycles)?;
    Ok(cycles)
}

pub fn validate_max_cycles(cycles: u64) -> HostResult<()> {
    if cycles == 0 {
        return Err("Cycle budget must be positive; an unlimited execution mode is forbidden.");
    }
    Ok(())
}

pub fn parse_workers(value: &OsStr) -> HostResult<usize> {
    let text = value
        .to_str()
        .ok_or("Worker budget must be a positive decimal integer.")?;
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("Worker budget must be a positive decimal integer.");
    }
    let count = text
        .parse::<usize>()
        .map_err(|_| "Worker budget must be a positive decimal integer.")?;
    if count == 0 {
        return Err("Worker budget must be a positive decimal integer.");
    }
    Ok(count)
}

fn select_workers(
    explicit: Option<usize>,
    inherited: Option<&OsStr>,
    hardware: usize,
) -> HostResult<usize> {
    let ceiling = worker_ceiling(hardware);
    let count = match explicit {
        Some(count) => count,
        None => inherited.map_or(Ok(ceiling), parse_workers)?,
    };
    if count == 0 || count > ceiling {
        return Err(
            "Worker budget must fit available logical CPUs minus one, with a minimum of one worker.",
        );
    }
    Ok(count)
}

/// Reserve one available logical CPU when possible. This is a parallelism
/// budget based on the host's OS/cgroup quota, not physical-core affinity.
fn worker_ceiling(available: usize) -> usize {
    available.saturating_sub(1).max(1)
}

/// Holding this open handle owns the OS lock until the job returns or exits.
/// The empty shared file remains in place; removing it would split ownership
/// between different inodes and permit overlapping workers.
pub struct WorkerGuard {
    _file: File,
    pub access_policy: String,
}

impl WorkerGuard {
    pub fn acquire(server_path: &Path) -> HostResult<Self> {
        let parent = server_path
            .parent()
            .ok_or("Pinned prover executable has no worker-lock directory.")?;
        let path = parent.join(LOCK_NAME);
        let mut options = OpenOptions::new();
        options.read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::OpenOptionsExt;
            // Linux O_NOFOLLOW: reject symlinks atomically during open.
            options.custom_flags(0x0002_0000);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            // Open the reparse point itself, then reject it below.
            options.custom_flags(0x0020_0000);
        }
        let file = match options.create_new(true).open(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let entry = std::fs::symlink_metadata(&path)
                    .map_err(|_| "Cannot inspect the existing proof-worker lock entry.")?;
                if !entry.is_file() || entry.len() != 0 {
                    return Err(
                        "Proof-worker lock must be an empty regular file without a symlink.",
                    );
                }
                options.create_new(false);
                options.open(&path).map_err(
                    |_| "Cannot open the shared proof-worker lock beside the pinned executable.",
                )?
            }
            Err(_) => {
                return Err(
                    "Cannot create the shared proof-worker lock; prover directory must be writable.",
                );
            }
        };
        let metadata = file
            .metadata()
            .map_err(|_| "Cannot inspect the shared proof-worker lock.")?;
        let entry = std::fs::symlink_metadata(&path)
            .map_err(|_| "Cannot inspect the shared proof-worker lock entry.")?;
        if !metadata.is_file() || !entry.is_file() || metadata.len() != 0 || entry.len() != 0 {
            return Err("Proof-worker lock must be an empty regular file without a symlink.");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.dev() != entry.dev() || metadata.ino() != entry.ino() {
                return Err("Proof-worker lock entry changed while opening.");
            }
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if metadata.file_attributes() & 0x0000_0400 != 0
                || entry.file_attributes() & 0x0000_0400 != 0
            {
                return Err("Proof-worker lock must not be a Windows reparse point.");
            }
        }
        file.try_lock().map_err(|error| match error {
            std::fs::TryLockError::WouldBlock => {
                "Another proof job owns this prover install; retry after it exits."
            }
            _ => "Cannot acquire the operating-system proof-worker lock.",
        })?;
        // This empty synchronization file contains no private payload. Request
        // 0600 on creation and record the actual filesystem mode; DrvFS may
        // report wider permissions. Payload-artifact privacy is a separate
        // policy and is never relaxed by this non-sensitive lock allowance.
        #[cfg(unix)]
        let access_policy = {
            use std::os::unix::fs::PermissionsExt;
            format!(
                "empty-worker-lock; requested-create-mode=0600; observed-Unix-mode={:04o}; no-private-payload-written",
                metadata.permissions().mode() & 0o7777,
            )
        };
        #[cfg(not(unix))]
        let access_policy =
            "empty-worker-lock; inherited-parent-ACL-not-inspected; no-private-payload-written"
                .into();
        Ok(Self {
            _file: file,
            access_policy,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_MAX_CYCLES, LOCK_NAME, WorkerGuard, parse_max_cycles, parse_workers, select_workers,
    };
    use std::{ffi::OsStr, fs, time::SystemTime};

    #[test]
    fn explicit_cycle_budget_keeps_default_and_checks_sdk_u64_representation() {
        assert_eq!(DEFAULT_MAX_CYCLES, 268_435_456);
        for (text, expected) in [
            ("1", 1),
            ("268435456", DEFAULT_MAX_CYCLES),
            ("536870912", 536_870_912),
            ("18446744073709551615", u64::MAX),
        ] {
            assert_eq!(parse_max_cycles(OsStr::new(text)), Ok(expected));
        }
        for text in [
            "",
            "0",
            "none",
            "unlimited",
            "-1",
            "+1",
            "1.5",
            " 2",
            "18446744073709551616",
        ] {
            assert!(parse_max_cycles(OsStr::new(text)).is_err());
        }
    }

    #[test]
    fn worker_budget_is_positive_bounded_and_has_explicit_precedence() {
        for value in ["1", "4", "64", "04", "256"] {
            assert!(parse_workers(OsStr::new(value)).is_ok());
        }
        for value in [
            "",
            "0",
            "-1",
            "+2",
            " 2",
            "2 ",
            "1.5",
            "184467440737095516160",
        ] {
            assert!(parse_workers(OsStr::new(value)).is_err());
        }
        assert_eq!(
            select_workers(Some(2), Some(OsStr::new("invalid")), 16),
            Ok(2)
        );
        assert_eq!(select_workers(None, Some(OsStr::new("3")), 16), Ok(3));
        assert!(select_workers(None, Some(OsStr::new("0")), 16).is_err());
        assert!(select_workers(Some(0), None, 16).is_err());
        assert!(select_workers(Some(16), None, 16).is_err());
        assert!(select_workers(None, Some(OsStr::new("16")), 16).is_err());
        assert_eq!(select_workers(Some(15), None, 16), Ok(15));
        assert_eq!(select_workers(None, None, 16), Ok(15));
        assert_eq!(select_workers(None, None, 2), Ok(1));
        assert_eq!(select_workers(None, None, 1), Ok(1));
        assert!(select_workers(Some(2), None, 1).is_err());
        assert!(select_workers(None, Some(OsStr::new("2")), 2).is_err());
        assert_eq!(select_workers(None, None, 0), Ok(1));
        assert_eq!(select_workers(None, None, 256), Ok(255));
    }

    #[test]
    fn worker_lock_excludes_overlap_and_releases_without_removing_file() {
        let nonce = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory =
            std::env::temp_dir().join(format!("l2-proof-lock-{}-{nonce}", std::process::id()));
        fs::create_dir(&directory).unwrap();
        let server = directory.join("r0vm");
        let first = WorkerGuard::acquire(&server).unwrap();
        assert!(WorkerGuard::acquire(&server).is_err());
        drop(first);
        assert!(directory.join(LOCK_NAME).is_file());
        let next = WorkerGuard::acquire(&server).unwrap();
        drop(next);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(directory.join(LOCK_NAME), fs::Permissions::from_mode(0o666))
                .unwrap();
            let wider = WorkerGuard::acquire(&server).unwrap();
            let observed = fs::metadata(directory.join(LOCK_NAME))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777;
            assert!(
                wider
                    .access_policy
                    .contains(&format!("observed-Unix-mode={observed:04o}"))
            );
            assert!(WorkerGuard::acquire(&server).is_err());
            drop(wider);
        }
        fs::write(directory.join(LOCK_NAME), b"not an empty lock").unwrap();
        assert!(WorkerGuard::acquire(&server).is_err());
        fs::remove_file(directory.join(LOCK_NAME)).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let target = directory.join("other-empty-file");
            fs::write(&target, []).unwrap();
            symlink(&target, directory.join(LOCK_NAME)).unwrap();
            assert!(WorkerGuard::acquire(&server).is_err());
            fs::remove_file(directory.join(LOCK_NAME)).unwrap();
            fs::remove_file(target).unwrap();
        }
        fs::remove_dir(directory).unwrap();
    }
}
