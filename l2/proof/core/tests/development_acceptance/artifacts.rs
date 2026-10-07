//! Private project-drive artifact I/O for the native-only acceptance check.
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use std::{
    fs::{self, Metadata, OpenOptions},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
};

fn redirected(metadata: &Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return true;
        }
    }
    metadata.file_type().is_symlink()
}

fn directory(path: &Path) -> PathBuf {
    assert!(
        path.is_absolute(),
        "explicit absolute project-drive directory required"
    );
    assert!(
        !path
            .components()
            .any(|item| matches!(item, Component::ParentDir))
    );
    #[cfg(windows)]
    {
        use std::path::Prefix;
        assert!(
            matches!(path.components().next(), Some(Component::Prefix(prefix))
            if matches!(prefix.kind(), Prefix::Disk(letter) | Prefix::VerbatimDisk(letter)
                if letter.to_ascii_uppercase() == b'E'))
        );
    }
    #[cfg(unix)]
    assert!(
        path.starts_with("/mnt/e"),
        "explicit project E: mount required"
    );
    for ancestor in path.ancestors() {
        let metadata = fs::symlink_metadata(ancestor).expect("inspect private artifact ancestry");
        assert!(
            metadata.is_dir() && !redirected(&metadata),
            "real local directories required"
        );
    }
    fs::canonicalize(path).expect("canonical private directory")
}

pub(super) fn directories() -> (PathBuf, PathBuf) {
    let input = PathBuf::from(
        std::env::var_os("L2_P4_DEVELOPMENT_ROOT")
            .expect("set L2_P4_DEVELOPMENT_ROOT to the retained node fixture"),
    );
    let output = PathBuf::from(
        std::env::var_os("L2_P4_DEVELOPMENT_CORE_OUTPUT")
            .expect("set L2_P4_DEVELOPMENT_CORE_OUTPUT to a NEW private output directory"),
    );
    let input = directory(&input);
    assert!(
        output.is_absolute(),
        "new output directory must be absolute"
    );
    let parent = directory(output.parent().expect("existing private output parent"));
    assert!(
        output.starts_with(&parent)
            || fs::canonicalize(output.parent().unwrap()).unwrap() == parent
    );
    let mut options = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        options.mode(0o700);
    }
    options
        .create(&output)
        .expect("output directory must be NEW");
    (input, directory(&output))
}

pub(super) fn read(root: &Path, relative: &str, maximum: usize) -> Vec<u8> {
    let path = root.join(relative);
    directory(path.parent().expect("artifact parent"));
    let before = fs::symlink_metadata(&path).expect("private artifact metadata");
    assert!(before.is_file() && !redirected(&before) && before.len() <= maximum as u64);
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x0020_0000);
    }
    let file = options.open(&path).expect("open bounded private artifact");
    let metadata = file.metadata().expect("opened artifact metadata");
    assert!(metadata.is_file() && !redirected(&metadata) && metadata.len() == before.len());
    let mut bytes = Vec::new();
    (&file)
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .expect("bounded private artifact read");
    let after = file.metadata().expect("artifact metadata after read");
    assert!(bytes.len() as u64 == metadata.len() && bytes.len() <= maximum);
    assert!(after.len() == metadata.len() && after.modified().ok() == metadata.modified().ok());
    assert!(
        fs::canonicalize(&path).unwrap() == path,
        "artifact path changed"
    );
    assert!(!redirected(&fs::symlink_metadata(&path).unwrap()));
    bytes
}

pub(super) fn json<T: DeserializeOwned>(root: &Path, relative: &str) -> T {
    serde_json::from_slice(&read(root, relative, 16 * 1024 * 1024))
        .unwrap_or_else(|_| panic!("typed private fixture metadata rejected"))
}

pub(super) fn write(path: &Path, bytes: &[u8]) {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .expect("create new private native artifact");
    file.write_all(bytes)
        .expect("write private native artifact");
    file.sync_all().expect("sync private native artifact");
}

pub(super) fn access(path: &Path) -> Value {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        json!({"requested_directory_mode":"0700","requested_file_mode":"0600",
            "observed_directory_mode":fs::metadata(path).unwrap().permissions().mode() & 0o777,
            "observed_journal_mode":fs::metadata(path.join("journal.bin")).unwrap().permissions().mode() & 0o777,
            "mode_enforcement_not_assumed":true})
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        json!({"inherited_windows_acl_independently_audited":false,"project_drive_required":true})
    }
}
