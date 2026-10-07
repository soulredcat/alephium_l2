//! Create-only synchronized package files; fetched metadata supplies no authority.
use crate::{HostResult, inputs::CheckedFile};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

pub(crate) struct PackageRepository {
    directory: PathBuf,
}

impl PackageRepository {
    pub fn create(path: &Path) -> HostResult<Self> {
        let mut options = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            options.mode(0o700);
        }
        options
            .create(path)
            .map_err(|_| "DA output must be a fresh directory.")?;
        #[cfg(unix)]
        {
            let parent = path
                .parent()
                .filter(|value| !value.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            File::open(parent)
                .and_then(|file| file.sync_all())
                .map_err(|_| "Cannot synchronize the new DA directory entry.")?;
        }
        Self::open(path)
    }

    pub fn open(path: &Path) -> HostResult<Self> {
        let entry =
            fs::symlink_metadata(path).map_err(|_| "Cannot inspect DA package directory.")?;
        if !entry.is_dir() || entry.file_type().is_symlink() {
            return Err("DA package must be a regular directory, not a symlink.");
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if entry.file_attributes() & 0x400 != 0 {
                return Err("DA package directory must not be a reparse point.");
            }
        }
        let directory = path
            .canonicalize()
            .map_err(|_| "Cannot resolve DA package directory.")?;
        if directory.to_string_lossy().chars().any(char::is_control) {
            return Err("DA package path contains a control character.");
        }
        Ok(Self { directory })
    }

    pub fn create_file(&self, name: &str) -> HostResult<File> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options
            .open(self.directory.join(name))
            .map_err(|_| "DA artifact must be a new file.")
    }

    pub fn write_new(&self, name: &str, bytes: &[u8]) -> HostResult<()> {
        let mut file = self.create_file(name)?;
        file.write_all(bytes)
            .map_err(|_| "Cannot write DA artifact.")?;
        file.sync_all()
            .map_err(|_| "Cannot synchronize DA artifact.")?;
        self.sync_directory()
    }

    pub fn read(&self, name: &str, maximum: usize) -> HostResult<Vec<u8>> {
        crate::inputs::read_bounded(&self.directory.join(name), maximum)
    }

    pub fn checked_data(&self) -> HostResult<CheckedFile> {
        CheckedFile::open(&self.directory.join("data.bin"))
    }

    pub fn sync_directory(&self) -> HostResult<()> {
        #[cfg(unix)]
        File::open(&self.directory)
            .and_then(|file| file.sync_all())
            .map_err(|_| "Cannot synchronize DA package directory.")?;
        // Windows inherits parent ACLs. std does not promise directory fsync
        // or enforce a private DACL; do not claim either here.
        Ok(())
    }
}
