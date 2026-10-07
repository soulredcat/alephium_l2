//! Native reconstruction from authenticated DA inputs, without output oracles.
//! Matching a pinned candidate journal grants no proof or settlement authority.
use super::{DaBlock, DecodedCheckpointDa, ExpectedDa};
use crate::{
    BatchTransitionJournal, CheckpointTransitionOutput, EXECUTION_ENGINE, MAX_TRANSITION_BLOCKS,
    RPC_PROFILE, batch_execution, batch_journal,
    batch_state::FullState,
    block,
    commitment_batch::StreamCommitments,
    large_checkpoint::{LARGE_CHECKPOINT_SCOPE, checkpoint_profile_v4_with_capacity},
    protocol::{BlockCommit, BlockContext, Capacity, Head, Receipt, proof_transport::ProofLimits},
};

/// The strict reader is the only public constructor for the owned data object.
/// It already checked the complete canonical bytes against the independent DA
/// pin; private fields cannot be replaced by an external package manifest.
pub fn reconstruct_checkpoint_da(
    data: DecodedCheckpointDa,
    expected: &ExpectedDa<'_>,
) -> Result<CheckpointTransitionOutput, String> {
    let limits = validate_candidate(&data, expected)?;
    let checkpoint = &data.checkpoint;
    let root = |value: &crate::protocol::checkpoint::ExecutionCheckpoint| {
        value.root_for_transport(
            data.profile,
            data.domain.l1_network,
            data.domain.l1_genesis_id,
            data.domain.settlement_contract_id,
            limits,
        )
    };
    let old_state_root = root(checkpoint)?;
    if old_state_root != expected.journal.old_state_root {
        return Err("DA checkpoint does not match the pinned parent root".into());
    }
    let mut state = FullState::from_checkpoint(checkpoint)?;
    let before_state_digest = state.digest()?;
    let before_account_count = state.account_count();
    let before_total_balance = state.total_balance()?;
    if before_state_digest != expected.journal.before_state_digest
        || before_account_count != expected.journal.before_account_count
        || before_total_balance != expected.journal.before_total_balance
    {
        return Err("DA checkpoint accounting differs from the pinned statement".into());
    }
    let parent = checkpoint.head.clone();
    let mut head = parent.clone();
    let mut commitments = StreamCommitments::new(limits)?;
    for input in &data.blocks {
        // Reuse the pinned decoder/REVM once for each envelope. The original
        // block boundary remains the state normalization and commitment boundary.
        let (derived, receipts) = replay_block(
            &mut state,
            checkpoint.chain_id,
            &head,
            input,
            expected.capacity,
        )?;
        state.enforce_checkpoint_capacity(expected.capacity)?;
        commitments.include(&input.context, &receipts)?;
        head = derived;
    }
    let after_state_digest = state.digest()?;
    let next = state.checkpoint(
        checkpoint.chain_id,
        checkpoint.genesis_id,
        &head,
        expected.capacity,
    )?;
    if next.encoded_len()? > limits.checkpoint_bytes {
        return Err("Reconstructed checkpoint exceeds the pinned transport bound".into());
    }
    let new_state_root = root(&next)?;
    let (transactions_commitment, context_commitment, receipts_commitment, executed_transactions) =
        commitments.finish()?;
    let blocks = u64::try_from(data.blocks.len()).map_err(|_| "DA block count exceeds u64")?;
    let journal = BatchTransitionJournal {
        schema: 4,
        proof_scope: LARGE_CHECKPOINT_SCOPE.into(),
        rpc_profile: RPC_PROFILE.into(),
        execution_engine: EXECUTION_ENGINE.into(),
        domain: data.domain.clone(),
        chain_id: checkpoint.chain_id,
        genesis_id: checkpoint.genesis_id,
        execution_profile: data.profile,
        batch_start: parent
            .height
            .checked_add(1)
            .ok_or("DA batch height overflow")?,
        parent,
        head,
        blocks,
        executed_transactions,
        witness_blocks: blocks,
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
        inbox_commitment: batch_journal::empty_messages(
            &data.domain,
            checkpoint.genesis_id,
            b"inbox",
        ),
        outbox_commitment: batch_journal::empty_messages(
            &data.domain,
            checkpoint.genesis_id,
            b"outbox",
        ),
        inbox_count: 0,
        outbox_count: 0,
        da_commitment: data.encoding.commitment,
    };
    // Compare every field through the existing consensus encoding, including
    // message roots/counts, exact totals, ancestry and all execution commitments.
    if journal.encode()? != expected.journal.encode()? {
        return Err("Reconstructed DA journal differs from the pinned statement".into());
    }
    Ok(CheckpointTransitionOutput {
        journal,
        checkpoint: next,
    })
}

fn validate_candidate(
    data: &DecodedCheckpointDa,
    expected: &ExpectedDa<'_>,
) -> Result<ProofLimits, String> {
    expected.capacity.validate()?;
    data.domain.validate()?;
    expected.journal.domain.validate()?;
    data.checkpoint.validate()?;
    let limits = ProofLimits::for_capacity(expected.capacity)?;
    let profile = checkpoint_profile_v4_with_capacity(expected.capacity)?;
    let blocks = u64::try_from(data.blocks.len()).map_err(|_| "DA block count exceeds u64")?;
    let parent = &data.checkpoint.head;
    let journal = expected.journal;
    if journal.schema != 4
        || journal.proof_scope != LARGE_CHECKPOINT_SCOPE
        || journal.rpc_profile != RPC_PROFILE
        || journal.execution_engine != EXECUTION_ENGINE
        || data.domain != journal.domain
        || data.profile != profile
        || journal.execution_profile != profile
        || data.checkpoint.capacity != expected.capacity
        || data.checkpoint.chain_id != journal.chain_id
        || data.checkpoint.genesis_id != journal.genesis_id
        || *parent != journal.parent
        || blocks == 0
        || blocks > MAX_TRANSITION_BLOCKS
        || journal.blocks != blocks
        || journal.witness_blocks != blocks
        || journal.batch_start
            != parent
                .height
                .checked_add(1)
                .ok_or("DA batch height overflow")?
        || journal.head.height
            != parent
                .height
                .checked_add(blocks)
                .ok_or("DA head overflow")?
        || journal.head.genesis_id != journal.genesis_id
        || data.encoding.bytes == 0
        || data.encoding.bytes > limits.input_bytes
        || data.encoding.commitment != journal.da_commitment
        || journal.inbox_count != 0
        || journal.outbox_count != 0
    {
        return Err("DA input does not match the pinned schema-four statement/profile".into());
    }
    if data.checkpoint.encoded_len()? > limits.checkpoint_bytes {
        return Err("DA checkpoint exceeds the pinned transport bound".into());
    }
    Ok(limits)
}

/// Derive the original local commit normalization and receipt identities from
/// raw DA inputs. No supplied head, state delta or expected receipt is consulted.
fn replay_block(
    state: &mut FullState,
    chain_id: u64,
    parent: &Head,
    input: &DaBlock,
    capacity: Capacity,
) -> Result<(Head, Vec<Receipt>), String> {
    let context = BlockContext {
        number: input.context.number,
        timestamp: input.context.timestamp,
        gas_limit: input.context.gas_limit,
    };
    if context.number
        != parent
            .height
            .checked_add(1)
            .ok_or("DA block height overflow")?
        || context.timestamp < parent.timestamp
        || context.gas_limit != capacity.block_gas
        || input.envelopes.is_empty()
        || input.envelopes.len() > capacity.max_pending
    {
        return Err("DA block ancestry, context or transaction count is invalid".into());
    }
    let raws = input
        .envelopes
        .iter()
        .map(Vec::as_slice)
        .collect::<Vec<_>>();
    let output = batch_execution::execute_block(state, &raws, chain_id, context, capacity)?;
    let commit = BlockCommit {
        parent: parent.clone(),
        context,
        transactions: output.receipts.iter().map(|receipt| receipt.hash).collect(),
        changes: output.changes,
        receipts: output.receipts,
        rejected: Vec::new(),
    };
    block::validate_with_capacity(&commit, capacity)?;
    block::logical_bytes_with_capacity(&commit, raws.iter().copied(), capacity)?;
    let stored = state.apply(&commit.changes)?;
    let (head, _) = block::encode_with_capacity(&commit, &stored, capacity)?;
    let mut receipts = commit.receipts;
    for receipt in &mut receipts {
        receipt.block_hash = head.commit_id;
    }
    state.commit_head(&head)?;
    Ok((head, receipts))
}
