//! Bounded private files. Inputs are explicit; outputs are exclusively new.
use crate::testnet_plan::Hash;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Write},
    path::{Component, Path, PathBuf},
};

pub(super) const JSON_LIMIT: usize = 1_048_576;

pub(super) fn sha(bytes: &[u8]) -> Hash {
    Sha256::digest(bytes).into()
}

pub(super) fn object<'a>(
    value: &'a Value,
    keys: &[&str],
) -> Result<&'a Map<String, Value>, String> {
    let object = value.as_object().ok_or("Expected policy JSON object")?;
    if object.len() != keys.len() || keys.iter().any(|key| !object.contains_key(*key)) {
        return Err("Policy JSON contains missing or unknown fields".into());
    }
    Ok(object)
}

pub(super) fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str, String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("Missing text field: {key}"))
}

pub(super) fn number(value: &Value, key: &str) -> Result<u64, String> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("Missing integer field: {key}"))
}

pub(super) fn hex_bytes<const N: usize>(text: &str) -> Result<[u8; N], String> {
    if text.len() != N * 2
        || !text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("Expected exact lowercase hexadecimal bytes".into());
    }
    hex::decode(text)
        .map_err(|_| "Invalid hexadecimal bytes")?
        .try_into()
        .map_err(|_| "Hexadecimal width differs".into())
}

pub(super) fn hash(value: &Value, key: &str) -> Result<Hash, String> {
    hex_bytes(text(value, key)?)
}

fn plain(path: &Path) -> Result<(), String> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir))
    {
        return Err("Inputs require absolute, non-traversing local paths".into());
    }
    #[cfg(windows)]
    if !matches!(path.components().next(), Some(Component::Prefix(prefix))
        if matches!(prefix.kind(), std::path::Prefix::Disk(_) | std::path::Prefix::VerbatimDisk(_)))
    {
        return Err("Only ordinary local drive paths are supported".into());
    }
    Ok(())
}

fn no_links(path: &Path) -> Result<(), String> {
    for ancestor in path.ancestors() {
        let metadata =
            fs::symlink_metadata(ancestor).map_err(|_| "Cannot inspect local path ancestry")?;
        if metadata.file_type().is_symlink() {
            return Err("Symlinked input/output paths are unsupported".into());
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if metadata.file_attributes() & 0x400 != 0 {
                return Err("Reparse-point input/output paths are unsupported".into());
            }
        }
    }
    Ok(())
}

pub(super) fn existing(path: &Path) -> Result<PathBuf, String> {
    plain(path)?;
    no_links(path)?;
    if !fs::metadata(path)
        .map_err(|_| "Local input is unavailable")?
        .is_file()
    {
        return Err("Local input must be a regular file".into());
    }
    path.canonicalize()
        .map_err(|_| "Cannot resolve local input".into())
}

pub(super) fn read(path: &Path, limit: usize) -> Result<Vec<u8>, String> {
    let path = existing(path)?;
    let file = fs::File::open(path).map_err(|_| "Cannot open bounded local input")?;
    if file
        .metadata()
        .map_err(|_| "Cannot inspect local input")?
        .len()
        > limit as u64
    {
        return Err("Local input exceeds its byte bound".into());
    }
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "Cannot read local input")?;
    if bytes.len() > limit {
        return Err("Local input exceeds its byte bound".into());
    }
    Ok(bytes)
}

pub(super) fn json(bytes: &[u8]) -> Result<Value, String> {
    reject_duplicate_keys(bytes)?;
    serde_json::from_slice(bytes).map_err(|_| "Bounded local JSON is invalid".into())
}

// Value deserialization silently replaces duplicate object keys. Check decoded
// keys first; serde_json still owns the complete grammar and depth validation.
fn reject_duplicate_keys(bytes: &[u8]) -> Result<(), String> {
    use std::collections::BTreeSet;
    let mut stack: Vec<Option<(bool, BTreeSet<String>)>> = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'{' => stack.push(Some((true, BTreeSet::new()))),
            b'[' => stack.push(None),
            b'}' | b']' => {
                stack.pop();
            }
            b',' => {
                if let Some(Some((key, _))) = stack.last_mut() {
                    *key = true;
                }
            }
            b'"' => {
                let start = index;
                index += 1;
                let mut escaped = false;
                while index < bytes.len() {
                    let byte = bytes[index];
                    if byte == b'"' && !escaped {
                        break;
                    }
                    escaped = byte == b'\\' && !escaped;
                    index += 1;
                }
                if index == bytes.len() {
                    return Err("Bounded local JSON is invalid".into());
                }
                if let Some(Some((key, keys))) = stack.last_mut()
                    && *key
                {
                    let decoded: String = serde_json::from_slice(&bytes[start..=index])
                        .map_err(|_| "JSON object key is invalid")?;
                    if !keys.insert(decoded) {
                        return Err("JSON contains duplicate object keys".into());
                    }
                    *key = false;
                }
            }
            _ => {}
        }
        if stack.len() > 128 {
            return Err("Local JSON nesting exceeds its bound".into());
        }
        index += 1;
    }
    Ok(())
}

pub(super) fn pinned_json(path: &Path, pin: Hash) -> Result<Value, String> {
    let bytes = read(path, JSON_LIMIT)?;
    if sha(&bytes) != pin {
        return Err("Local JSON differs from independently supplied pin".into());
    }
    json(&bytes)
}

pub(super) fn fresh_output(path: &Path) -> Result<PathBuf, String> {
    plain(path)?;
    let parent = path.parent().ok_or("Missing output parent")?;
    no_links(parent)?;
    if !parent.is_dir() || path.file_name().is_none() || path.exists() {
        return Err("Output requires an existing parent and a fresh directory".into());
    }
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    #[cfg(windows)]
    if path.components().next() != manifest.components().next() {
        return Err("Private output must stay on the project drive".into());
    }
    #[cfg(not(windows))]
    if !path.starts_with("/mnt/e")
        && !path.starts_with(manifest.ancestors().nth(2).ok_or("Invalid project root")?)
    {
        return Err("Private output must stay on project storage".into());
    }
    fs::create_dir(path).map_err(|_| "Cannot create exclusively owned output directory")?;
    path.canonicalize()
        .map_err(|_| "Cannot resolve owned output directory".into())
}

pub(super) fn write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| "Cannot create exclusively owned private output")?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| "Cannot persist private output".into())
}

pub(super) fn write_json(path: &Path, value: &Value) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(value).map_err(|_| "Cannot encode private report")?;
    if bytes.len() > JSON_LIMIT {
        return Err("Private report exceeds its byte bound".into());
    }
    write(path, &bytes)
}

pub(super) fn check_jar(path: &Path) -> Result<PathBuf, String> {
    let path = existing(path)?;
    let mut file = fs::File::open(&path).map_err(|_| "Compiler JAR is unavailable")?;
    let limit = 512_u64 * 1024 * 1024;
    if file
        .metadata()
        .map_err(|_| "Cannot inspect compiler JAR")?
        .len()
        > limit
    {
        return Err("Compiler JAR exceeds its byte bound".into());
    }
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 65536];
    let mut total = 0_u64;
    loop {
        let length = file
            .read(&mut buffer)
            .map_err(|_| "Cannot read compiler JAR")?;
        if length == 0 {
            break;
        }
        total += length as u64;
        if total > limit {
            return Err("Compiler JAR exceeds its byte bound".into());
        }
        digest.update(&buffer[..length]);
    }
    if hex::encode(digest.finalize()) != crate::compiler::JAR_SHA256 {
        return Err("Compiler JAR differs from its fixed official pin".into());
    }
    Ok(path)
}

pub(super) fn jvm_path(path: &Path) -> Result<String, String> {
    let text = path.to_str().ok_or("Compiler paths require UTF-8")?;
    #[cfg(windows)]
    if let Some(drive) = text.strip_prefix(r"\\?\") {
        return Ok(drive.into());
    }
    Ok(text.into())
}
