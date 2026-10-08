//! Bounded literal assignments. No shell expansion, exports or secret output.
use std::{collections::BTreeMap, fs, io::Read, path::Path};

pub(super) const MAX_BYTES: usize = 16_384;
pub(super) const FIELDS: &[(&str, &str)] = &[
    ("L2_P5_ENV_SCHEMA", "schema"),
    ("L2_P5_NODE_URL", "source"),
    ("L2_P5_L1_NETWORK_ID", "source"),
    ("L2_P5_L1_GROUP", "source"),
    ("L2_P5_PUBLISHER_PUBLIC_KEY", "account"),
    ("L2_P5_PUBLISHER_ADDRESS", "account"),
    ("L2_P5_SIGNER_ADAPTER", "handoff"),
    ("L2_P5_OUTBOX_DIRECTORY", "handoff"),
    ("L2_P5_TOTAL_FEE_CAP_ALPH", "budget"),
    ("L2_P5_TOTAL_DEPOSIT_CAP_ALPH", "budget"),
    ("L2_P5_TOTAL_DEBIT_CAP_ALPH", "budget"),
    ("L2_P5_MAX_GAS_PER_TRANSACTION", "budget"),
    ("L2_P5_MAX_GAS_PRICE_ATTO", "budget"),
    ("L2_P5_MIN_CHAIN_CONFIRMATIONS", "policy"),
    ("L2_P5_MIN_FROM_GROUP_CONFIRMATIONS", "policy"),
    ("L2_P5_MIN_TO_GROUP_CONFIRMATIONS", "policy"),
    ("L2_P5_PUBLISHER_CONFIRMATIONS", "policy"),
    ("L2_P5_MAX_FUTURE_SECONDS", "policy"),
    ("L2_P5_OPERATION_PACKAGE_DIRECTORY", "package"),
    ("L2_P5_LIVE_SIGNING_ENABLED", "interlock"),
    ("L2_P5_LIVE_SUBMISSION_ENABLED", "interlock"),
    ("L2_P5_EXECUTION_DATA_DISCLOSURE_ENABLED", "interlock"),
];

pub(super) struct Issue {
    pub field: &'static str,
    pub category: &'static str,
    pub line: Option<usize>,
}

pub(super) struct Parsed {
    pub values: BTreeMap<&'static str, String>,
    pub issues: Vec<Issue>,
}

pub(super) fn read(path: &Path) -> Result<String, String> {
    let metadata = fs::symlink_metadata(path).map_err(|_| "Cannot inspect private env file")?;
    checked_metadata(&metadata)?;
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // FILE_FLAG_OPEN_REPARSE_POINT: inspect the link rather than follow it.
        options.custom_flags(0x0020_0000);
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // Linux x86_64 O_NOFOLLOW | O_NONBLOCK: refuse links and avoid blocking
        // when a nonregular entry replaces the inspected regular file.
        options.custom_flags(0x0002_0000 | 0x0000_0800);
    }
    if !cfg!(any(
        windows,
        all(target_os = "linux", target_arch = "x86_64")
    )) {
        return Err("Safe env-file opening is unsupported on this platform".into());
    }
    let mut file = options
        .open(path)
        .map_err(|_| "Cannot safely open private env file")?;
    let opened = file
        .metadata()
        .map_err(|_| "Cannot inspect opened env file")?;
    checked_metadata(&opened)?;
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "Cannot read private env file")?;
    if bytes.len() > MAX_BYTES {
        return Err("Env input exceeds its byte bound".into());
    }
    let after = file
        .metadata()
        .map_err(|_| "Cannot recheck opened env file")?;
    checked_metadata(&after)?;
    if opened.len() != bytes.len() as u64
        || after.len() != opened.len()
        || after.modified().ok() != opened.modified().ok()
    {
        return Err("Env file changed during the bounded read".into());
    }
    String::from_utf8(bytes).map_err(|_| "Env input must be UTF-8".into())
}

fn checked_metadata(metadata: &fs::Metadata) -> Result<(), String> {
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > MAX_BYTES as u64
    {
        return Err("Env input must be a bounded regular file".into());
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err("Env reparse points are unsupported".into());
        }
    }
    Ok(())
}

pub(super) fn parse(text: &str) -> Result<Parsed, String> {
    if text.len() > MAX_BYTES {
        return Err("Env input exceeds its byte bound".into());
    }
    let mut parsed = Parsed {
        values: BTreeMap::new(),
        issues: Vec::new(),
    };
    for (index, line) in text
        .strip_prefix('\u{feff}')
        .unwrap_or(text)
        .lines()
        .enumerate()
    {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let issue = |field, category| Issue {
            field,
            category,
            line: Some(index + 1),
        };
        let Some((name, raw)) = line.split_once('=') else {
            parsed
                .issues
                .push(issue("unparsed_field", "invalid_assignment"));
            continue;
        };
        let Some(&(name, _)) = FIELDS.iter().find(|(field, _)| *field == name.trim()) else {
            parsed
                .issues
                .push(issue("unrecognized_field", "unknown_name"));
            continue;
        };
        if parsed.values.contains_key(name) {
            parsed.issues.push(issue(name, "duplicate_assignment"));
            continue;
        }
        let raw = raw.trim();
        let value = if let Some(quote) = raw
            .chars()
            .next()
            .filter(|quote| matches!(quote, '\'' | '"'))
        {
            if raw.len() < 2 || !raw.ends_with(quote) {
                parsed.issues.push(issue(name, "invalid_literal_quotes"));
                continue;
            }
            &raw[1..raw.len() - 1]
        } else {
            raw
        };
        // Quotes only delimit literals. Windows backslashes are preserved.
        if value.len() > 2048
            || value.contains(['\'', '"', '`', '$'])
            || value.chars().any(char::is_control)
        {
            parsed.issues.push(issue(name, "unsupported_literal"));
            continue;
        }
        parsed.values.insert(name, value.to_owned());
    }
    Ok(parsed)
}
