//! Bounded offline transition export from an immutable development backup.
use super::{
    BackupManifest, ReplayReport, files,
    transition_types::{TransitionBundle, TransitionReport},
    verify_replay,
};
use crate::{
    execution,
    protocol::{BLOCK_GAS, Genesis},
    storage::{ReadView, Store},
};
use alloy_primitives::B256;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

const SCHEMA: u32 = 1;
const MAX_MANIFEST_BYTES: u64 = 4 * 1024 * 1024;
pub(super) const MAX_BUNDLE_BYTES: usize = 16 * 1024 * 1024;

/// Reexecutes the retained input, including signature/chain checks, before export.
/// The backup is never opened by Fjall; only fresh source/replayed copies are.
pub fn prepare_transition(
    backup: &Path,
    genesis: &Genesis,
    work: &Path,
) -> Result<TransitionReport, String> {
    genesis.validate()?;
    let backup = files::existing_directory(backup)?;
    preflight(&backup, genesis, 1)?;
    let replay = verify_replay(&backup, genesis, work)?;
    if replay.blocks != 1
        || replay.executed_transactions != 1
        || replay.rejected_intents != 0
        || replay.pending_count != 0
    {
        return Err(
            "Transition export requires exactly one executed input and no other intents".into(),
        );
    }
    let work = files::existing_directory(work)?;
    let source = Store::open_existing(&work.join("source"), genesis)?;
    let target = Store::open_existing(&work.join("replayed"), genesis)?;
    if !source.pending()?.is_empty() || !target.pending()?.is_empty() {
        return Err("Transition export cannot include unresolved intents".into());
    }
    let bundle = validated_bundle(&source.view()?, &target.view()?, genesis, &replay)?;
    let mut bytes = JsonBuffer(Vec::new());
    serde_json::to_writer_pretty(&mut bytes, &bundle)
        .map_err(|_| "Cannot encode transition bundle within its bounded size")?;
    let bundle_sha256 = B256::from_slice(&Sha256::digest(&bytes.0));
    let bundle_path = publish_private(&work, &bytes.0)?;
    Ok(TransitionReport {
        schema: SCHEMA,
        chain_id: bundle.chain_id,
        genesis_id: bundle.genesis_id,
        parent: bundle.parent,
        head: bundle.head,
        transaction_hash: bundle.transaction_hash,
        expected_state_digest: bundle.expected_state_digest,
        work_directory: work,
        bundle_path,
        bundle_sha256,
        bundle_bytes: bytes.0.len(),
        blocks: replay.blocks,
        executed_transactions: replay.executed_transactions,
        rejected_intents: replay.rejected_intents,
        pending_count: replay.pending_count,
        semantic_replay_verified: true,
        guest_proof_generated: false,
        settlement_verified: false,
    })
}

/// An untrusted manifest only filters the bounded candidate before reexecution.
/// verify_replay still validates its complete inventory and authoritative data.
pub(super) fn preflight(backup: &Path, genesis: &Genesis, max_blocks: u64) -> Result<(), String> {
    let path = backup.join("manifest.json");
    let metadata = fs::symlink_metadata(&path).map_err(files::io_error)?;
    files::regular(&metadata)?;
    if metadata.len() == 0 || metadata.len() > MAX_MANIFEST_BYTES {
        return Err("Transition backup manifest exceeds its bounded size".into());
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)
        .map_err(files::io_error)?
        .take(MAX_MANIFEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(files::io_error)?;
    if bytes.len() as u64 != metadata.len() {
        return Err("Transition backup manifest changed during read".into());
    }
    let manifest: BackupManifest =
        serde_json::from_slice(&bytes).map_err(|_| "Invalid transition backup manifest")?;
    if manifest.schema != 1
        || manifest.chain_id != genesis.chain_id
        || manifest.head.height == 0
        || manifest.head.height > max_blocks
        || manifest.pending_count != 0
    {
        return Err(
            "Transition export requires a matching bounded nonempty backup without pending intents"
                .into(),
        );
    }
    Ok(())
}

fn validated_bundle(
    source: &ReadView,
    target: &ReadView,
    genesis: &Genesis,
    replay: &ReplayReport,
) -> Result<TransitionBundle, String> {
    if source.chain_id() != genesis.chain_id
        || target.chain_id() != genesis.chain_id
        || source.head != replay.head
        || target.head != replay.head
        || source.head.height != 1
        || source.pending_counter()? != 1
        || target.pending_counter()? != 1
        || source.state_digest()? != replay.state_digest
        || target.state_digest()? != replay.state_digest
    {
        return Err("Transition stores differ from verified replay".into());
    }
    let block = source
        .replay_block(1)?
        .ok_or("Missing retained transition block")?;
    let genesis_head = source
        .block(0)?
        .ok_or("Missing canonical genesis block")?
        .head;
    if block.head != replay.head
        || block.parent != genesis_head
        || target
            .block(0)?
            .ok_or("Missing replayed genesis block")?
            .head
            != genesis_head
        || block.context.number != 1
        || block.context.timestamp != block.head.timestamp
        || block.context.gas_limit != BLOCK_GAS
        || block.transactions.len() != 1
        || block.receipts.len() != 1
        || !block.rejected.is_empty()
    {
        return Err("Transition is not a single retained execution from canonical genesis".into());
    }
    let hash = block.transactions[0];
    let raw = source
        .raw_transaction(hash)?
        .ok_or("Missing actual retained signed input")?;
    let info = execution::inspect_for_chain(&raw, genesis.chain_id)
        .map_err(|_| "Actual retained input fails canonical signature or chain validation")?;
    let receipt = &block.receipts[0];
    let status = source
        .status(hash)?
        .ok_or("Missing actual retained resolution")?;
    let expected_status = if receipt.success {
        "committed"
    } else {
        "reverted"
    };
    if info.hash != hash
        || info.sender != receipt.from
        || receipt.hash != hash
        || receipt.block_hash != block.head.commit_id
        || receipt.block_height != 1
        || receipt.transaction_index != 0
        || receipt.gas_used > info.gas_limit
        || status.hash != hash
        || status.status != expected_status
        || status.block_height != Some(1)
        || status.error.is_some()
        || source.receipt(hash)?.as_ref() != Some(receipt)
        || target.receipt(hash)?.as_ref() != Some(receipt)
        || target.raw_transaction(hash)?.as_deref() != Some(raw.as_slice())
        || target.status(hash)?.as_ref() != Some(&status)
    {
        return Err("Retained transition input, receipt or resolution differs from replay".into());
    }
    let mut genesis = genesis.clone();
    genesis.accounts.sort_by_key(|account| account.address);
    Ok(TransitionBundle {
        schema: SCHEMA,
        rpc_profile: "development/c5-v1".into(),
        execution_engine: replay.execution_engine.clone(),
        chain_id: genesis.chain_id,
        genesis_id: genesis_head.genesis_id,
        genesis,
        parent: block.parent,
        head: block.head,
        context: block.context.into(),
        transaction_hash: hash,
        raw_envelope_hex: format!("0x{}", hex::encode(raw)),
        expected_receipt: receipt.clone(),
        expected_state_digest: replay.state_digest,
        semantic_replay_verified: true,
        guest_proof_generated: false,
        settlement_verified: false,
    })
}

pub(super) fn publish_private(work: &Path, bytes: &[u8]) -> Result<PathBuf, String> {
    let partial = work.join("transition.partial");
    let complete = work.join("transition.json");
    if complete.try_exists().map_err(files::io_error)? {
        return Err("Transition bundle already exists; overwrite is forbidden".into());
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&partial).map_err(files::io_error)?;
    file.write_all(bytes).map_err(files::io_error)?;
    file.sync_all().map_err(files::io_error)?;
    drop(file);
    fs::rename(partial, &complete).map_err(files::io_error)?;
    files::sync_directory(work)?;
    Ok(complete)
}

/// Bounds allocation during serialization, before any private bundle is written.
pub(super) struct JsonBuffer(pub(super) Vec<u8>);

impl Write for JsonBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX_BUNDLE_BYTES.saturating_sub(self.0.len()) {
            return Err(io::Error::other("Transition bundle size limit exceeded"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
