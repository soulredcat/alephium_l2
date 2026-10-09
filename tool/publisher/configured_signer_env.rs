//! Bounded root-env access; secrets are never formatted or persisted here.
use crate::publisher::configured_signer::ConfiguredSignerError as Error;
use std::{
    collections::BTreeMap,
    fs,
    io::Read,
    path::{Path, PathBuf},
};

const MAX_ENV_BYTES: usize = 32_768;
const NAMES: &[&str] = &[
    "L2_P5_PUBLISHER_PRIVATE_KEY",
    "L2_P5_PUBLISHER_PUBLIC_KEY",
    "L2_P5_PUBLISHER_ADDRESS",
    "L2_P5_L1_NETWORK_ID",
    "L2_P5_L1_GROUP",
    "ALEPHIUM_NETWORK_ID",
    "L2_P5_LIVE_SIGNING_ENABLED",
    "L2_P5_LIVE_SUBMISSION_ENABLED",
];

pub(crate) struct EnvBytes(Vec<u8>);

impl Drop for EnvBytes {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

impl EnvBytes {
    pub(crate) fn text(&self) -> Result<&str, Error> {
        std::str::from_utf8(&self.0).map_err(|_| Error::InvalidConfiguration)
    }
}

/// Resolve only the root of the Node crate's main repository. There is no
/// fallback to an archived checkout, generic wallet file or process environment.
pub(crate) fn read(path: &Path) -> Result<EnvBytes, Error> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or(Error::InvalidEnvironmentPath)?;
    let root_env = root.join(".env");
    regular(&fs::symlink_metadata(&root_env).map_err(|_| Error::EnvironmentUnavailable)?)?;
    let expected = root_env
        .canonicalize()
        .map_err(|_| Error::EnvironmentUnavailable)?;
    let supplied = path
        .canonicalize()
        .map_err(|_| Error::EnvironmentUnavailable)?;
    if supplied != expected {
        return Err(Error::InvalidEnvironmentPath);
    }
    // Inspect the supplied entry too, not only its canonicalized target.
    let initial = fs::symlink_metadata(path).map_err(|_| Error::EnvironmentUnavailable)?;
    regular(&initial)?;
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x0020_0000); // FILE_FLAG_OPEN_REPARSE_POINT
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(0x0002_0000 | 0x0000_0800); // O_NOFOLLOW | O_NONBLOCK
    }
    if !cfg!(any(
        windows,
        all(target_os = "linux", target_arch = "x86_64")
    )) {
        return Err(Error::UnsupportedPlatform);
    }
    let mut file = options
        .open(path)
        .map_err(|_| Error::EnvironmentUnavailable)?;
    let before = file.metadata().map_err(|_| Error::EnvironmentUnavailable)?;
    regular(&before)?;
    let mut bytes = EnvBytes(Vec::new());
    (&mut file)
        .take(MAX_ENV_BYTES as u64 + 1)
        .read_to_end(&mut bytes.0)
        .map_err(|_| Error::EnvironmentUnavailable)?;
    let after = file.metadata().map_err(|_| Error::EnvironmentUnavailable)?;
    regular(&after)?;
    if bytes.0.len() > MAX_ENV_BYTES
        || bytes.0.len() as u64 != before.len()
        || after.len() != before.len()
        || after.modified().ok() != before.modified().ok()
        || PathBuf::from(path)
            .canonicalize()
            .map_err(|_| Error::EnvironmentUnavailable)?
            != supplied
    {
        return Err(Error::EnvironmentChanged);
    }
    Ok(bytes)
}

fn regular(metadata: &fs::Metadata) -> Result<(), Error> {
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > MAX_ENV_BYTES as u64
    {
        return Err(Error::InvalidConfiguration);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err(Error::InvalidConfiguration);
        }
    }
    Ok(())
}

pub(crate) fn parse(text: &str) -> Result<BTreeMap<&'static str, &str>, Error> {
    if text.len() > MAX_ENV_BYTES {
        return Err(Error::InvalidConfiguration);
    }
    let mut values = BTreeMap::new();
    for line in text.strip_prefix('\u{feff}').unwrap_or(text).lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (name, raw) = line.split_once('=').ok_or(Error::InvalidConfiguration)?;
        let Some(&name) = NAMES.iter().find(|&&known| known == name.trim()) else {
            continue;
        };
        if values.contains_key(name) {
            return Err(Error::InvalidConfiguration);
        }
        let raw = raw.trim();
        let value = if let Some(quote) = raw
            .chars()
            .next()
            .filter(|quote| matches!(quote, '\'' | '"'))
        {
            if raw.len() < 2 || !raw.ends_with(quote) {
                return Err(Error::InvalidConfiguration);
            }
            &raw[1..raw.len() - 1]
        } else {
            raw
        };
        if value.is_empty()
            || value.len() > 256
            || value.contains(['\'', '"', '`', '$'])
            || value.chars().any(char::is_control)
        {
            return Err(Error::InvalidConfiguration);
        }
        values.insert(name, value);
    }
    Ok(values)
}
