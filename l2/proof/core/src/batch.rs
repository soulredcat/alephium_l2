//! Reexecute complete bounded history and authenticate the selected suffix batch.
use crate::{
    BatchTransitionBundle, BatchTransitionJournal, EXECUTION_ENGINE, MAX_TRANSITION_BLOCKS,
    RPC_PROFILE, batch_journal as journal,
    batch_replay::{Commitments, execute_retained},
    batch_state::FullState,
    records,
};

pub fn prove_batch_transition(
    bundle: &BatchTransitionBundle,
) -> Result<BatchTransitionJournal, String> {
    bundle.domain.validate()?;
    if bundle.schema != 2
        || bundle.rpc_profile != RPC_PROFILE
        || bundle.execution_engine != EXECUTION_ENGINE
        || bundle.chain_id != bundle.genesis.chain_id
        || bundle.blocks.is_empty()
        || bundle.blocks.len() as u64 > MAX_TRANSITION_BLOCKS
        || bundle.head.height != bundle.blocks.len() as u64
        || bundle.batch_start == 0
        || bundle.batch_start > bundle.head.height
    {
        return Err("unsupported batch identity, execution profile or witness bounds".into());
    }
    let genesis = records::genesis_head(&records::genesis_bytes(&bundle.genesis)?);
    if bundle.parent != genesis || bundle.genesis_id != genesis.genesis_id {
        return Err("batch witness must start from complete canonical genesis".into());
    }
    let profile = journal::profile_commitment(bundle.genesis.capacity)?;
    let mut state = FullState::genesis(&bundle.genesis)?;
    state.commit_head(&genesis)?;
    let mut head = genesis;
    let mut boundary = None;
    let mut commitments = Commitments::new()?;
    for input in &bundle.blocks {
        if input.context.number == bundle.batch_start {
            boundary = Some((
                head.clone(),
                state.digest()?,
                state.account_count(),
                state.total_balance()?,
            ));
        }
        let (derived, receipts) = execute_retained(
            &mut state,
            bundle.chain_id,
            &head,
            input,
            bundle.genesis.capacity,
        )?;
        if input.context.number >= bundle.batch_start {
            commitments.include(&input.context, &receipts)?;
        }
        head = derived;
    }
    let after_digest = state.digest()?;
    if head != bundle.head || after_digest != bundle.expected_state_digest {
        return Err("batch final state differs from retained runtime oracle".into());
    }
    let (parent, before_digest, before_count, before_total) =
        boundary.ok_or("missing batch boundary")?;
    let (transactions_commitment, context_commitment, receipts_commitment, executed_transactions) =
        commitments.finish()?;
    Ok(BatchTransitionJournal {
        schema: 2,
        proof_scope: journal::BATCH_SCOPE.into(),
        rpc_profile: RPC_PROFILE.into(),
        execution_engine: EXECUTION_ENGINE.into(),
        domain: bundle.domain.clone(),
        chain_id: bundle.chain_id,
        genesis_id: bundle.genesis_id,
        execution_profile: profile,
        batch_start: bundle.batch_start,
        blocks: head.height - parent.height,
        executed_transactions,
        witness_blocks: bundle.blocks.len() as u64,
        old_state_root: journal::state_root(&parent, before_digest, profile),
        new_state_root: journal::state_root(&head, after_digest, profile),
        parent,
        head,
        before_state_digest: before_digest,
        after_state_digest: after_digest,
        before_account_count: before_count,
        after_account_count: state.account_count(),
        before_total_balance: before_total,
        after_total_balance: state.total_balance()?,
        transactions_commitment,
        context_commitment,
        receipts_commitment,
        inbox_commitment: journal::empty_messages(&bundle.domain, bundle.genesis_id, b"inbox"),
        outbox_commitment: journal::empty_messages(&bundle.domain, bundle.genesis_id, b"outbox"),
        inbox_count: 0,
        outbox_count: 0,
        da_commitment: journal::hash(&journal::batch_data(bundle)?),
    })
}
