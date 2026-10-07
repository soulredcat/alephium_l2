//! Authenticated complete checkpoint plus bounded consecutive EVM suffix.
use crate::{
    BatchTransitionJournal, CheckpointTransitionBundle, EXECUTION_ENGINE, MAX_TRANSITION_BLOCKS,
    RPC_PROFILE, batch_journal as journal,
    batch_replay::{Commitments, execute_retained},
    batch_state::FullState,
    encoding::{Encoder, MAX_RECORD},
    protocol::{Capacity, checkpoint::ExecutionCheckpoint},
};
use alloy_primitives::B256;
use serde::Serialize;

pub const CHECKPOINT_SCOPE: &str = "cancun-authenticated-checkpoint-batch/v3";

/// Only the journal is public output. The canonical next checkpoint is a private
/// reconstruction artifact authenticated by journal.new_state_root.
#[derive(Serialize)]
pub struct CheckpointTransitionOutput {
    #[serde(flatten)]
    pub journal: BatchTransitionJournal,
    #[serde(skip)]
    pub checkpoint: ExecutionCheckpoint,
}

pub fn checkpoint_profile() -> Result<B256, String> {
    checkpoint_profile_with_capacity(Capacity::default())
}

pub fn checkpoint_profile_with_capacity(capacity: Capacity) -> Result<B256, String> {
    capacity.validate()?;
    let mut out = Encoder::default();
    out.bytes(b"alephium-l2/checkpoint-execution-profile/v3")?;
    out.bytes(CHECKPOINT_SCOPE.as_bytes())?;
    out.hash(journal::profile_commitment(capacity)?);
    out.u32(capacity.checkpoint_schema());
    out.u64(MAX_TRANSITION_BLOCKS);
    out.u64(crate::protocol::checkpoint::MAX_CHECKPOINT_BYTES as u64);
    out.u64(crate::MAX_CONTINUATION_CHECKPOINT_BYTES as u64);
    out.u64(crate::MAX_CHECKPOINT_WIRE_BYTES as u64);
    Ok(journal::hash(&out.finish()?))
}

pub fn prove_checkpoint_transition(
    bundle: &CheckpointTransitionBundle,
) -> Result<CheckpointTransitionOutput, String> {
    if bundle.schema == 4 {
        return crate::large_checkpoint::prove_large_checkpoint_transition(bundle);
    }
    bundle.domain.validate()?;
    let checkpoint = &bundle.checkpoint;
    checkpoint.validate()?;
    validate_transport(bundle)?;
    if bundle.schema != 3
        || bundle.rpc_profile != RPC_PROFILE
        || bundle.execution_engine != EXECUTION_ENGINE
        || bundle.blocks.is_empty()
        || bundle.blocks.len() as u64 > MAX_TRANSITION_BLOCKS
        || bundle.head.height
            != checkpoint
                .head
                .height
                .checked_add(bundle.blocks.len() as u64)
                .ok_or("height overflow")?
    {
        return Err("unsupported checkpoint transition profile or suffix bounds".into());
    }
    let profile = checkpoint_profile_with_capacity(checkpoint.capacity)?;
    let root = |checkpoint: &ExecutionCheckpoint| {
        checkpoint.root(
            profile,
            bundle.domain.l1_network,
            bundle.domain.l1_genesis_id,
            bundle.domain.settlement_contract_id,
        )
    };
    let old_state_root = root(checkpoint)?;
    let mut state = FullState::from_checkpoint(checkpoint)?;
    let before_state_digest = state.digest()?;
    let before_account_count = state.account_count();
    let before_total_balance = state.total_balance()?;
    let parent = checkpoint.head.clone();
    let mut head = parent.clone();
    let mut commitments = Commitments::new()?;
    for block in &bundle.blocks {
        let (derived, receipts) = execute_retained(
            &mut state,
            checkpoint.chain_id,
            &head,
            block,
            checkpoint.capacity,
        )?;
        commitments.include(&block.context, &receipts)?;
        head = derived;
    }
    let after_state_digest = state.digest()?;
    if head != bundle.head || after_state_digest != bundle.expected_state_digest {
        return Err("checkpoint suffix differs from retained runtime output".into());
    }
    // This also enforces the resulting checkpoint bound, not only input bounds.
    let next = state.checkpoint(
        checkpoint.chain_id,
        checkpoint.genesis_id,
        &head,
        checkpoint.capacity,
    )?;
    checkpoint_bytes(&next)?;
    let new_state_root = root(&next)?;
    let (transactions_commitment, context_commitment, receipts_commitment, executed_transactions) =
        commitments.finish()?;
    let statement = BatchTransitionJournal {
        schema: 3,
        proof_scope: CHECKPOINT_SCOPE.into(),
        rpc_profile: RPC_PROFILE.into(),
        execution_engine: EXECUTION_ENGINE.into(),
        domain: bundle.domain.clone(),
        chain_id: checkpoint.chain_id,
        genesis_id: checkpoint.genesis_id,
        execution_profile: profile,
        batch_start: parent.height.checked_add(1).ok_or("height overflow")?,
        blocks: bundle.blocks.len() as u64,
        executed_transactions,
        witness_blocks: bundle.blocks.len() as u64,
        parent,
        head,
        old_state_root,
        new_state_root,
        before_state_digest,
        after_state_digest,
        before_account_count,
        after_account_count: state.account_count(),
        before_total_balance,
        after_total_balance: state.total_balance()?,
        transactions_commitment,
        context_commitment,
        receipts_commitment,
        inbox_commitment: journal::empty_messages(&bundle.domain, checkpoint.genesis_id, b"inbox"),
        outbox_commitment: journal::empty_messages(
            &bundle.domain,
            checkpoint.genesis_id,
            b"outbox",
        ),
        inbox_count: 0,
        outbox_count: 0,
        da_commitment: journal::hash(&checkpoint_batch_data(bundle)?),
    };
    Ok(CheckpointTransitionOutput {
        journal: statement,
        checkpoint: next,
    })
}

/// Private canonical DA bytes. The checkpoint root must match a previously
/// accepted parent before these bytes authorize reconstruction or settlement.
pub fn checkpoint_batch_data(bundle: &CheckpointTransitionBundle) -> Result<Vec<u8>, String> {
    if bundle.schema != 3 {
        return Err("schema-four reconstruction uses its bounded streaming commitment".into());
    }
    bundle.domain.validate()?;
    if bundle.blocks.is_empty() || bundle.blocks.len() as u64 > MAX_TRANSITION_BLOCKS {
        return Err("checkpoint data suffix exceeds block bound".into());
    }
    let mut out = Encoder::default();
    out.bytes(b"alephium-l2/reconstruction/checkpoint-suffix/v3")?;
    journal::encode_domain(&mut out, &bundle.domain);
    out.hash(checkpoint_profile_with_capacity(
        bundle.checkpoint.capacity,
    )?);
    out.bytes(&checkpoint_bytes(&bundle.checkpoint)?)?;
    out.u64(bundle.blocks.len() as u64);
    for block in &bundle.blocks {
        crate::transition_wire::checkpoint_transition_block_bytes_with_capacity(
            block,
            bundle.checkpoint.capacity,
        )?;
        out.u64(block.context.number);
        out.u64(block.context.timestamp);
        out.u64(block.context.gas_limit);
        if block.context.gas_limit != bundle.checkpoint.capacity.block_gas
            || block.transactions.is_empty()
            || block.transactions.len() > bundle.checkpoint.capacity.max_pending
        {
            return Err("checkpoint data transaction count exceeds bound".into());
        }
        out.u32(block.transactions.len() as u32);
        for input in &block.transactions {
            out.bytes(input.raw_envelope_hex.as_bytes())?;
            if out.0.len() > MAX_RECORD {
                return Err("checkpoint reconstruction data exceeds byte bound".into());
            }
        }
    }
    out.finish()
}

fn checkpoint_bytes(checkpoint: &ExecutionCheckpoint) -> Result<Vec<u8>, String> {
    let bytes = checkpoint.encode()?;
    if bytes.len() > crate::MAX_CONTINUATION_CHECKPOINT_BYTES {
        return Err("checkpoint leaves insufficient room for binary continuation input".into());
    }
    Ok(bytes)
}

fn validate_transport(bundle: &CheckpointTransitionBundle) -> Result<(), String> {
    let checkpoint = checkpoint_bytes(&bundle.checkpoint)?;
    let mut size = crate::transition_wire::checkpoint_transition_base_bytes(
        &bundle.rpc_profile,
        &bundle.execution_engine,
        checkpoint.len(),
    )?;
    for block in &bundle.blocks {
        size = size
            .checked_add(
                crate::transition_wire::checkpoint_transition_block_bytes_with_capacity(
                    block,
                    bundle.checkpoint.capacity,
                )?,
            )
            .ok_or("checkpoint transition size overflow")?;
        if size > crate::MAX_CHECKPOINT_WIRE_BYTES {
            return Err("checkpoint transition exceeds its complete binary input bound".into());
        }
    }
    Ok(())
}
