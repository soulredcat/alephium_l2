//! Schema-four complete-checkpoint execution with bounded streamed commitments.
//! Native replay is not a guest receipt, settlement or capacity qualification.
use crate::{
    BatchTransitionJournal, CheckpointTransitionBundle, CheckpointTransitionOutput,
    EXECUTION_ENGINE, MAX_TRANSITION_BLOCKS, RPC_PROFILE, batch_journal as journal,
    batch_replay::execute_retained,
    batch_state::FullState,
    commitment_batch::{StreamCommitments, reconstruction_hash},
    encoding::Encoder,
    protocol::{Capacity, checkpoint::ExecutionCheckpoint, proof_transport::ProofLimits},
};
use alloy_primitives::B256;

pub const LARGE_CHECKPOINT_SCOPE: &str = "cancun-authenticated-checkpoint-batch/v4";

pub fn checkpoint_profile_v4_with_capacity(capacity: Capacity) -> Result<B256, String> {
    let limits = ProofLimits::for_capacity(capacity)?;
    let mut out = Encoder::default();
    out.bytes(b"alephium-l2/checkpoint-execution-profile/v4")?;
    out.bytes(LARGE_CHECKPOINT_SCOPE.as_bytes())?;
    out.hash(journal::profile_commitment(capacity)?);
    out.u32(capacity.checkpoint_schema());
    out.u64(MAX_TRANSITION_BLOCKS);
    out.0.extend_from_slice(&limits.binding_bytes()?);
    Ok(journal::hash(&out.finish()?))
}

pub(crate) fn prove_large_checkpoint_transition(
    bundle: &CheckpointTransitionBundle,
) -> Result<CheckpointTransitionOutput, String> {
    bundle.domain.validate()?;
    let checkpoint = &bundle.checkpoint;
    checkpoint.validate()?;
    if bundle.schema != 4
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
        return Err("unsupported schema-four checkpoint profile or suffix bounds".into());
    }
    let limits = ProofLimits::for_capacity(checkpoint.capacity)?;
    let checkpoint_bytes = validate_transport(bundle, limits)?;
    let profile = checkpoint_profile_v4_with_capacity(checkpoint.capacity)?;
    let root = |checkpoint: &ExecutionCheckpoint| {
        checkpoint.root_for_transport(
            profile,
            bundle.domain.l1_network,
            bundle.domain.l1_genesis_id,
            bundle.domain.settlement_contract_id,
            limits,
        )
    };
    let old_state_root = root(checkpoint)?;
    let mut state = FullState::from_checkpoint(checkpoint)?;
    let before_state_digest = state.digest()?;
    let before_account_count = state.account_count();
    let before_total_balance = state.total_balance()?;
    let parent = checkpoint.head.clone();
    let mut head = parent.clone();
    let mut commitments = StreamCommitments::new(limits)?;
    for block in &bundle.blocks {
        // One authoritative REVM overlay and epoch normalization per original
        // retained block. Transport frames are never execution boundaries.
        let (derived, receipts) = execute_retained(
            &mut state,
            checkpoint.chain_id,
            &head,
            block,
            checkpoint.capacity,
        )?;
        state.enforce_checkpoint_capacity(checkpoint.capacity)?;
        commitments.include(&block.context, &receipts)?;
        head = derived;
    }
    let after_state_digest = state.digest()?;
    if head != bundle.head || after_state_digest != bundle.expected_state_digest {
        return Err("checkpoint suffix differs from retained runtime output".into());
    }
    let next = state.checkpoint(
        checkpoint.chain_id,
        checkpoint.genesis_id,
        &head,
        checkpoint.capacity,
    )?;
    if next.encoded_len()? > limits.checkpoint_bytes {
        return Err("resulting checkpoint exceeds the bound proof profile".into());
    }
    let new_state_root = root(&next)?;
    let (transactions_commitment, context_commitment, receipts_commitment, executed_transactions) =
        commitments.finish()?;
    let statement = BatchTransitionJournal {
        schema: 4,
        proof_scope: LARGE_CHECKPOINT_SCOPE.into(),
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
        da_commitment: reconstruction_hash(bundle, profile, limits, checkpoint_bytes)?,
    };
    Ok(CheckpointTransitionOutput {
        journal: statement,
        checkpoint: next,
    })
}

/// Schema-three uses its unchanged canonical bytes; four hashes its complete
/// canonical reconstruction stream without a transcript-sized allocation.
pub fn checkpoint_batch_commitment(bundle: &CheckpointTransitionBundle) -> Result<B256, String> {
    match bundle.schema {
        3 => Ok(journal::hash(&crate::checkpoint_batch_data(bundle)?)),
        4 => {
            bundle.domain.validate()?;
            let limits = ProofLimits::for_capacity(bundle.checkpoint.capacity)?;
            let checkpoint_bytes = validate_transport(bundle, limits)?;
            reconstruction_hash(
                bundle,
                checkpoint_profile_v4_with_capacity(bundle.checkpoint.capacity)?,
                limits,
                checkpoint_bytes,
            )
        }
        _ => Err("unsupported checkpoint reconstruction version".into()),
    }
}

fn validate_transport(
    bundle: &CheckpointTransitionBundle,
    limits: ProofLimits,
) -> Result<usize, String> {
    if bundle.schema != 4
        || bundle.blocks.is_empty()
        || bundle.blocks.len() as u64 > MAX_TRANSITION_BLOCKS
    {
        return Err("unsupported schema-four checkpoint data suffix".into());
    }
    limits.validate_for_capacity(bundle.checkpoint.capacity)?;
    let bytes = bundle.checkpoint.encoded_len()?;
    if bytes == 0 || bytes > limits.checkpoint_bytes {
        return Err("checkpoint exceeds its bound proof profile".into());
    }
    crate::transition_wire_large::large_checkpoint_transition_bytes(bundle)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_profile_is_domain_separated_and_every_capacity_field_is_bound() {
        let capacity = Capacity {
            block_gas: 3_000_000_000,
            block_bytes: 32 * 1024 * 1024,
            max_pending: 100_000,
        };
        let expected = checkpoint_profile_v4_with_capacity(capacity).unwrap();
        assert_ne!(
            expected,
            crate::checkpoint_profile_with_capacity(capacity).unwrap()
        );
        for changed in [
            Capacity {
                block_gas: capacity.block_gas + 1,
                ..capacity
            },
            Capacity {
                block_bytes: capacity.block_bytes + 1,
                ..capacity
            },
            Capacity {
                max_pending: capacity.max_pending + 1,
                ..capacity
            },
        ] {
            assert_ne!(
                checkpoint_profile_v4_with_capacity(changed).unwrap(),
                expected
            );
        }
        assert!(
            checkpoint_profile_v4_with_capacity(Capacity {
                max_pending: 10_000_000,
                ..capacity
            })
            .is_err()
        );
    }
}
