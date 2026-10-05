//! Bootstrap an ongoing proof input from an actual offline replay checkpoint.
use super::{
    files,
    replay::{MAX_REPLAY_BLOCKS, verify_replay_at},
    transition::{preflight, publish_private_binary},
    transition_batch::{validate_block, validated_input},
    transition_types::{
        CheckpointTransitionBundle, CheckpointTransitionReport, MAX_TRANSITION_BLOCKS,
        SettlementDomain, TransitionBlock,
    },
    transition_wire::{
        MAX_CHECKPOINT_WIRE_BYTES, checkpoint_transition_base_bytes,
        checkpoint_transition_block_bytes, encode_checkpoint_transition,
    },
};
use crate::{protocol::Genesis, storage::Store};
use alloy_primitives::B256;
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, path::Path};

/// The immutable backup is copied/reexecuted, never opened for mutation. Capture
/// occurs at `batch_start - 1` on a genuine pinned ReadView, not a relabelled head.
/// This bootstrap retains the existing 10,000-block offline replay limit;
/// checkpoint/proof semantics themselves impose no maximum absolute height.
pub fn prepare_transition_checkpoint(
    backup: &Path,
    genesis: &Genesis,
    work: &Path,
    batch_start: u64,
    domain: SettlementDomain,
) -> Result<CheckpointTransitionReport, String> {
    genesis.validate()?;
    domain.validate()?;
    if batch_start == 0 || batch_start > MAX_REPLAY_BLOCKS {
        return Err("Checkpoint bootstrap boundary exceeds the offline replay profile".into());
    }
    let backup = files::existing_directory(backup)?;
    // Bound the suffix before doing the full offline replay.
    let max_head = batch_start
        .saturating_add(MAX_TRANSITION_BLOCKS - 1)
        .min(MAX_REPLAY_BLOCKS);
    preflight(&backup, genesis, max_head)?;
    let (replay, checkpoint) = verify_replay_at(&backup, genesis, work, batch_start - 1)?;
    if replay.blocks < batch_start || replay.rejected_intents != 0 || replay.pending_count != 0 {
        return Err(
            "Checkpoint export requires a nonempty suffix without rejected or pending intents"
                .into(),
        );
    }
    checkpoint.validate()?;
    let work = files::existing_directory(work)?;
    let source = Store::open_existing(&work.join("source"), genesis)?;
    let target = Store::open_existing(&work.join("replayed"), genesis)?;
    if !source.pending()?.is_empty() || !target.pending()?.is_empty() {
        return Err("Checkpoint export cannot include unresolved intents".into());
    }
    let source = source.view()?;
    let target = target.view()?;
    for view in [&source, &target] {
        if view.chain_id() != genesis.chain_id
            || view.head != replay.head
            || view.pending_counter()? != replay.executed_transactions
            || view.state_digest()? != replay.state_digest
            || view
                .block(checkpoint.head.height)?
                .ok_or("Missing checkpoint boundary block")?
                .head
                != checkpoint.head
        {
            return Err("Checkpoint stores differ from verified replay".into());
        }
    }
    if checkpoint.chain_id != genesis.chain_id
        || checkpoint.genesis_id != replay.head.genesis_id
        || checkpoint.head.height != batch_start - 1
    {
        return Err("Captured checkpoint identity or boundary differs".into());
    }
    let checkpoint_bytes = checkpoint.encode()?;
    let checkpoint_sha256 = B256::from_slice(&Sha256::digest(&checkpoint_bytes));
    let mut encoded_bytes = checkpoint_transition_base_bytes(
        "development/c5-v1",
        &replay.execution_engine,
        checkpoint_bytes.len(),
    )?;
    drop(checkpoint_bytes);
    let mut previous = checkpoint.head.clone();
    let mut hashes = BTreeSet::new();
    let mut blocks = Vec::new();
    for height in batch_start..=replay.blocks {
        let block = source
            .replay_block(height)?
            .ok_or("Missing retained checkpoint suffix block")?;
        validate_block(&block, &previous, height)?;
        let mut transactions = Vec::with_capacity(block.transactions.len());
        for (index, hash) in block.transactions.iter().enumerate() {
            if !hashes.insert(*hash) {
                return Err("Duplicate transaction in checkpoint suffix".into());
            }
            transactions.push(validated_input(&source, &target, &block, index)?);
        }
        previous = block.head.clone();
        let exported = TransitionBlock {
            parent: block.parent,
            head: block.head,
            context: block.context.into(),
            transactions,
        };
        encoded_bytes = encoded_bytes
            .checked_add(checkpoint_transition_block_bytes(&exported)?)
            .ok_or("Checkpoint suffix size overflow")?;
        if encoded_bytes > MAX_CHECKPOINT_WIRE_BYTES {
            return Err("Checkpoint suffix exceeds the bounded binary witness size".into());
        }
        blocks.push(exported);
    }
    if previous != replay.head || blocks.is_empty() || blocks.len() as u64 > MAX_TRANSITION_BLOCKS {
        return Err("Checkpoint suffix differs from verified replay head or bounds".into());
    }
    let bundle = CheckpointTransitionBundle {
        schema: 3,
        rpc_profile: "development/c5-v1".into(),
        execution_engine: replay.execution_engine,
        domain,
        checkpoint,
        blocks,
        head: replay.head,
        expected_state_digest: replay.state_digest,
    };
    let bytes = encode_checkpoint_transition(&bundle)?;
    if bytes.len() != encoded_bytes {
        return Err("Checkpoint binary size differs from collected suffix".into());
    }
    let bundle_sha256 = B256::from_slice(&Sha256::digest(&bytes));
    let bundle_path = publish_private_binary(&work, &bytes)?;
    let transaction_hashes: Vec<_> = bundle
        .blocks
        .iter()
        .flat_map(|block| {
            block
                .transactions
                .iter()
                .map(|input| input.transaction_hash)
        })
        .collect();
    Ok(CheckpointTransitionReport {
        schema: 3,
        chain_id: genesis.chain_id,
        genesis_id: bundle.checkpoint.genesis_id,
        domain: bundle.domain,
        parent: bundle.checkpoint.head,
        head: bundle.head,
        checkpoint_sha256,
        executed_transactions: transaction_hashes.len() as u64,
        transaction_hashes,
        expected_state_digest: bundle.expected_state_digest,
        work_directory: work,
        bundle_path,
        bundle_sha256,
        bundle_bytes: bytes.len(),
        blocks: bundle.blocks.len() as u64,
        replayed_blocks: replay.blocks,
        semantic_replay_verified: true,
        guest_proof_generated: false,
        settlement_verified: false,
    })
}
