//! Full-history execution witness export; preserves the legacy schema-one path.
use super::{
    ReplayReport, files,
    transition::{JsonBuffer, preflight, publish_private},
    transition_types::{
        BatchTransitionBundle, BatchTransitionReport, MAX_TRANSITION_BLOCKS, SettlementDomain,
        TransitionBlock, TransitionInput,
    },
    verify_replay,
};
use crate::{
    execution,
    protocol::{BLOCK_GAS, Genesis, Head, ReplayBlock},
    storage::{ReadView, Store},
};
use alloy_primitives::B256;
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, path::Path};

const SCHEMA: u32 = 2;

/// Export a bounded genesis prefix with an explicitly selected settlement suffix.
/// The target domain is an input to the proof, not a claim of live deployment.
pub fn prepare_transition_batch(
    backup: &Path,
    genesis: &Genesis,
    work: &Path,
    batch_start: u64,
    domain: SettlementDomain,
) -> Result<BatchTransitionReport, String> {
    genesis.validate()?;
    domain.validate()?;
    if batch_start == 0 || batch_start > MAX_TRANSITION_BLOCKS {
        return Err("Batch start is outside the bounded full-history witness profile".into());
    }
    let backup = files::existing_directory(backup)?;
    preflight(&backup, genesis, MAX_TRANSITION_BLOCKS)?;
    let replay = verify_replay(&backup, genesis, work)?;
    if replay.blocks < batch_start
        || replay.blocks > MAX_TRANSITION_BLOCKS
        || replay.executed_transactions == 0
        || replay.rejected_intents != 0
        || replay.pending_count != 0
    {
        return Err(
            "Batch export requires nonempty executed history without rejected or pending intents"
                .into(),
        );
    }
    let work = files::existing_directory(work)?;
    let source = Store::open_existing(&work.join("source"), genesis)?;
    let target = Store::open_existing(&work.join("replayed"), genesis)?;
    if !source.pending()?.is_empty() || !target.pending()?.is_empty() {
        return Err("Batch export cannot include unresolved intents".into());
    }
    let bundle = validated_bundle(
        &source.view()?,
        &target.view()?,
        genesis,
        &replay,
        batch_start,
        domain,
    )?;
    let mut bytes = JsonBuffer(Vec::new());
    serde_json::to_writer_pretty(&mut bytes, &bundle)
        .map_err(|_| "Cannot encode batch witness within its bounded size")?;
    let bundle_sha256 = B256::from_slice(&Sha256::digest(&bytes.0));
    let bundle_path = publish_private(&work, &bytes.0)?;
    let transaction_hashes = bundle
        .blocks
        .iter()
        .flat_map(|block| {
            block
                .transactions
                .iter()
                .map(|input| input.transaction_hash)
        })
        .collect();
    Ok(BatchTransitionReport {
        schema: SCHEMA,
        chain_id: bundle.chain_id,
        genesis_id: bundle.genesis_id,
        domain: bundle.domain,
        batch_start: bundle.batch_start,
        parent: bundle.parent,
        head: bundle.head,
        transaction_hashes,
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

fn validated_bundle(
    source: &ReadView,
    target: &ReadView,
    genesis: &Genesis,
    replay: &ReplayReport,
    batch_start: u64,
    domain: SettlementDomain,
) -> Result<BatchTransitionBundle, String> {
    for view in [source, target] {
        if view.chain_id() != genesis.chain_id
            || view.head != replay.head
            || view.pending_counter()? != replay.executed_transactions
            || view.state_digest()? != replay.state_digest
        {
            return Err("Batch stores differ from verified replay".into());
        }
    }
    let parent = source
        .block(0)?
        .ok_or("Missing canonical genesis block")?
        .head;
    if target
        .block(0)?
        .ok_or("Missing replayed genesis block")?
        .head
        != parent
    {
        return Err("Batch replay genesis differs".into());
    }
    let mut previous = parent.clone();
    let mut hashes = BTreeSet::new();
    let mut blocks = Vec::new();
    let mut bounded = JsonBuffer(Vec::new());
    for height in 1..=replay.blocks {
        let block = source
            .replay_block(height)?
            .ok_or("Missing retained batch block")?;
        validate_block(&block, &previous, height)?;
        let mut transactions = Vec::with_capacity(block.transactions.len());
        for (index, hash) in block.transactions.iter().enumerate() {
            if !hashes.insert(*hash) {
                return Err("Duplicate transaction in batch history".into());
            }
            transactions.push(validated_input(source, target, &block, index)?);
        }
        previous = block.head.clone();
        let exported = TransitionBlock {
            parent: block.parent,
            head: block.head,
            context: block.context.into(),
            transactions,
        };
        // Bound retained private material while collecting the full history.
        serde_json::to_writer(&mut bounded, &exported)
            .map_err(|_| "Batch history exceeds the bounded witness size")?;
        blocks.push(exported);
    }
    if previous != replay.head || hashes.len() as u64 != replay.executed_transactions {
        return Err("Batch history differs from verified replay totals".into());
    }
    let mut genesis = genesis.clone();
    genesis.accounts.sort_by_key(|account| account.address);
    Ok(BatchTransitionBundle {
        schema: SCHEMA,
        rpc_profile: "development/c5-v1".into(),
        execution_engine: replay.execution_engine.clone(),
        chain_id: genesis.chain_id,
        genesis_id: parent.genesis_id,
        domain,
        batch_start,
        genesis,
        parent,
        head: replay.head.clone(),
        blocks,
        expected_state_digest: replay.state_digest,
        semantic_replay_verified: true,
        guest_proof_generated: false,
        settlement_verified: false,
    })
}

pub(super) fn validate_block(
    block: &ReplayBlock,
    parent: &Head,
    height: u64,
) -> Result<(), String> {
    if block.parent != *parent
        || block.head.height != height
        || block.head.genesis_id != parent.genesis_id
        || block.context.number != height
        || block.context.timestamp != block.head.timestamp
        || block.context.timestamp < parent.timestamp
        || block.context.gas_limit != BLOCK_GAS
        || block.transactions.is_empty()
        || block.transactions.len() != block.receipts.len()
        || !block.rejected.is_empty()
    {
        return Err(
            "Batch history is not consecutive executed blocks from canonical genesis".into(),
        );
    }
    Ok(())
}

pub(super) fn validated_input(
    source: &ReadView,
    target: &ReadView,
    block: &ReplayBlock,
    index: usize,
) -> Result<TransitionInput, String> {
    let hash = block.transactions[index];
    let raw = source
        .raw_transaction(hash)?
        .ok_or("Missing retained signed batch input")?;
    let info = execution::inspect_for_chain(&raw, source.chain_id())
        .map_err(|_| "Retained batch input fails canonical signature or chain validation")?;
    let receipt = &block.receipts[index];
    let status = source
        .status(hash)?
        .ok_or("Missing retained batch resolution")?;
    let expected_status = if receipt.success {
        "committed"
    } else {
        "reverted"
    };
    if info.hash != hash
        || info.sender != receipt.from
        || receipt.hash != hash
        || receipt.block_hash != block.head.commit_id
        || receipt.block_height != block.head.height
        || receipt.transaction_index != index as u64
        || receipt.gas_used > info.gas_limit
        || status.hash != hash
        || status.status != expected_status
        || status.block_height != Some(block.head.height)
        || status.error.is_some()
        || source.receipt(hash)?.as_ref() != Some(receipt)
        || target.receipt(hash)?.as_ref() != Some(receipt)
        || target.raw_transaction(hash)?.as_deref() != Some(raw.as_slice())
        || target.status(hash)?.as_ref() != Some(&status)
    {
        return Err("Retained batch input, receipt or resolution differs from replay".into());
    }
    Ok(TransitionInput {
        transaction_hash: hash,
        raw_envelope_hex: format!("0x{}", hex::encode(raw)),
        expected_receipt: receipt.clone(),
    })
}
