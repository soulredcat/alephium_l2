//! Store execution and owned-directory helpers for the bounded offline C4 scenario.
use alephium_l2_node::{
    execution,
    protocol::{BLOCK_GAS, BlockCommit, BlockContext, Genesis, Pending, Receipt},
    storage::Store,
};
use alloy_primitives::{B256, keccak256};
use fjall::{Database, KeyspaceCreateOptions, PersistMode};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs, path::Path};

pub(super) fn context(number: u64) -> BlockContext {
    BlockContext {
        number,
        timestamp: 1_800_000_000 + number * 2,
        gas_limit: BLOCK_GAS,
    }
}

pub(super) fn admit(store: &mut Store, raw: &[u8], number: u64) -> Result<B256, String> {
    let info = execution::inspect(raw)?;
    let validated = execution::validate(store.view()?, raw, context(number))?;
    assert_eq!(validated.hash, info.hash);
    assert_eq!(validated.sender, info.sender);
    let status = store.admit(Pending {
        hash: info.hash,
        sender: info.sender,
        raw: raw.to_vec(),
    })?;
    assert_eq!(status.status, "durably_accepted");
    assert_eq!(status.block_height, None);
    Ok(info.hash)
}

pub(super) fn commit(
    store: &mut Store,
    inputs: &[Vec<u8>],
    number: u64,
) -> Result<Vec<Receipt>, String> {
    let view = store.view()?;
    let parent = view.head.clone();
    let result = execution::execute_block(view, inputs, context(number))?;
    assert!(result.rejected.is_empty());
    assert_eq!(result.receipts.len(), inputs.len());
    let view = store.commit(BlockCommit {
        parent,
        context: context(number),
        transactions: result.receipts.iter().map(|receipt| receipt.hash).collect(),
        changes: result.changes,
        receipts: result.receipts,
        rejected: result.rejected,
    })?;
    inputs
        .iter()
        .map(|raw| {
            view.receipt(keccak256(raw))?
                .ok_or_else(|| "missing committed fixture receipt".into())
        })
        .collect()
}

type FileHashes = BTreeMap<String, (u64, B256)>;

pub(super) fn file_hashes(root: &Path) -> Result<FileHashes, String> {
    fn walk(root: &Path, path: &Path, output: &mut FileHashes) -> Result<(), String> {
        for entry in fs::read_dir(path).map_err(io_error)? {
            let entry = entry.map_err(io_error)?;
            let kind = entry.file_type().map_err(io_error)?;
            if kind.is_dir() {
                walk(root, &entry.path(), output)?;
            } else if kind.is_file() {
                let bytes = fs::read(entry.path()).map_err(io_error)?;
                let relative = entry
                    .path()
                    .strip_prefix(root)
                    .map_err(|error| error.to_string())?
                    .to_string_lossy()
                    .into_owned();
                output.insert(
                    relative,
                    (bytes.len() as u64, B256::from_slice(&Sha256::digest(bytes))),
                );
            } else {
                return Err("unexpected non-regular fixture path".into());
            }
        }
        Ok(())
    }
    let mut output = BTreeMap::new();
    walk(root, root, &mut output)?;
    Ok(output)
}

pub(super) fn copy_tree(source: &Path, target: &Path) -> Result<(), String> {
    fs::create_dir(target).map_err(io_error)?;
    for entry in fs::read_dir(source).map_err(io_error)? {
        let entry = entry.map_err(io_error)?;
        let kind = entry.file_type().map_err(io_error)?;
        let destination = target.join(entry.file_name());
        if kind.is_dir() {
            copy_tree(&entry.path(), &destination)?;
        } else if kind.is_file() {
            fs::copy(entry.path(), destination).map_err(io_error)?;
        } else {
            return Err("unexpected non-regular fixture path".into());
        }
    }
    Ok(())
}

/// Damage only a newly owned genesis fixture while retaining its engine identity files.
pub(super) fn empty_existing_fixture(path: &Path, genesis: &Genesis) -> Result<(), String> {
    drop(Store::open(path, genesis)?);
    let database = Database::builder(path)
        .open()
        .map_err(|error| error.to_string())?;
    let items = database
        .keyspace("l2", KeyspaceCreateOptions::default)
        .map_err(|error| error.to_string())?;
    let keys = items
        .iter()
        .map(|entry| entry.into_inner().map(|(key, _)| key))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    assert!(!keys.is_empty());
    let mut batch = database.batch().durability(Some(PersistMode::SyncAll));
    for key in keys {
        batch.remove(&items, key.to_vec());
    }
    batch.commit().map_err(|error| error.to_string())?;
    drop(items);
    drop(database);
    Ok(())
}

pub(super) fn io_error(error: std::io::Error) -> String {
    error.to_string()
}
