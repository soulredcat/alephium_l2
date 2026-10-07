//! Strict native decoding of the existing schema-four public statement.
use crate::{
    BatchTransitionJournal, EXECUTION_ENGINE, LARGE_CHECKPOINT_SCOPE, MAX_TRANSITION_BLOCKS,
    RPC_PROFILE, SettlementDomain, batch_journal,
    encoding::Decoder,
    protocol::{checkpoint::genesis_commit, validate_chain_id},
    records,
};
use alloy_primitives::B256;

const MAX_JOURNAL_BYTES: usize = 4096;
const NAMESPACE: &[u8] = b"alephium-l2-transition-proof/journal/v4";

/// Parse the exact thirty-field v4 statement without changing its guest format.
/// Successful parsing authenticates neither a proof nor settlement authority.
pub fn decode_journal_v4(bytes: &[u8]) -> Result<BatchTransitionJournal, String> {
    let mut input = Decoder::new_with_limit(bytes, MAX_JOURNAL_BYTES)?;
    fixed_field(&mut input, NAMESPACE)?;
    let schema = input.u32()?;
    if schema != 4 {
        return Err("Unsupported settlement journal schema".into());
    }
    fixed_field(&mut input, LARGE_CHECKPOINT_SCOPE.as_bytes())?;
    fixed_field(&mut input, RPC_PROFILE.as_bytes())?;
    fixed_field(&mut input, EXECUTION_ENGINE.as_bytes())?;
    let journal = BatchTransitionJournal {
        schema,
        proof_scope: LARGE_CHECKPOINT_SCOPE.into(),
        rpc_profile: RPC_PROFILE.into(),
        execution_engine: EXECUTION_ENGINE.into(),
        domain: SettlementDomain {
            l1_network: input.byte()?,
            l1_genesis_id: input.hash()?,
            settlement_contract_id: input.hash()?,
        },
        chain_id: input.u64()?,
        genesis_id: input.hash()?,
        execution_profile: input.hash()?,
        batch_start: input.u64()?,
        parent: records::read_head(&mut input)?,
        head: records::read_head(&mut input)?,
        blocks: input.u64()?,
        executed_transactions: input.u64()?,
        witness_blocks: input.u64()?,
        old_state_root: input.hash()?,
        new_state_root: input.hash()?,
        before_state_digest: input.hash()?,
        after_state_digest: input.hash()?,
        before_account_count: input.u32()?,
        after_account_count: input.u32()?,
        before_total_balance: input.amount()?,
        after_total_balance: input.amount()?,
        transactions_commitment: input.hash()?,
        context_commitment: input.hash()?,
        receipts_commitment: input.hash()?,
        // The existing wire interleaves each message commitment with its count.
        inbox_commitment: input.hash()?,
        inbox_count: input.u64()?,
        outbox_commitment: input.hash()?,
        outbox_count: input.u64()?,
        da_commitment: input.hash()?,
    };
    input.finish()?;
    validate_journal_v4(&journal)?;
    if journal.encode()?.as_slice() != bytes {
        return Err("Settlement journal is not its exact canonical encoding".into());
    }
    Ok(journal)
}

fn fixed_field(input: &mut Decoder<'_>, expected: &[u8]) -> Result<(), String> {
    if input.u32()? as usize != expected.len() || input.take(expected.len())? != expected {
        return Err("Settlement journal has an unsupported domain or fixed profile field".into());
    }
    Ok(())
}

pub(super) fn validate_journal_v4(journal: &BatchTransitionJournal) -> Result<(), String> {
    journal.domain.validate()?;
    validate_chain_id(journal.chain_id)?;
    if journal.schema != 4
        || journal.proof_scope != LARGE_CHECKPOINT_SCOPE
        || journal.rpc_profile != RPC_PROFILE
        || journal.execution_engine != EXECUTION_ENGINE
    {
        return Err("Settlement requires the exact current schema-four execution profile".into());
    }
    if [
        journal.genesis_id,
        journal.execution_profile,
        journal.parent.commit_id,
        journal.head.commit_id,
        journal.old_state_root,
        journal.new_state_root,
        journal.before_state_digest,
        journal.after_state_digest,
        journal.transactions_commitment,
        journal.context_commitment,
        journal.receipts_commitment,
        journal.da_commitment,
    ]
    .contains(&B256::ZERO)
        || journal.parent.genesis_id != journal.genesis_id
        || journal.head.genesis_id != journal.genesis_id
    {
        return Err("Settlement journal has a missing identity or mismatched head genesis".into());
    }
    if !(1..=MAX_TRANSITION_BLOCKS).contains(&journal.blocks)
        || journal.witness_blocks != journal.blocks
        || journal.executed_transactions < journal.blocks
        || journal.executed_transactions > journal.blocks * u64::from(u32::MAX)
    {
        // Each canonical v4 block contains a nonempty u32 transaction count.
        // Its tighter capacity is bound by execution_profile and proof/DA checks.
        return Err("Settlement journal block or execution counters are inconsistent".into());
    }
    if journal.batch_start
        != journal
            .parent
            .height
            .checked_add(1)
            .ok_or("Settlement next height overflow")?
        || journal.head.height
            != journal
                .parent
                .height
                .checked_add(journal.blocks)
                .ok_or("Settlement end height overflow")?
        || journal.head.timestamp < journal.parent.timestamp
        || journal.parent.height == 0
            && (journal.parent.timestamp != 0
                || journal.parent.commit_id != genesis_commit(journal.genesis_id))
    {
        return Err("Settlement journal has invalid height, time or genesis ancestry".into());
    }
    if journal.inbox_count != 0
        || journal.outbox_count != 0
        || journal.inbox_commitment
            != batch_journal::empty_messages(&journal.domain, journal.genesis_id, b"inbox")
        || journal.outbox_commitment
            != batch_journal::empty_messages(&journal.domain, journal.genesis_id, b"outbox")
    {
        return Err(
            "Current settlement profile requires exact empty authenticated message queues".into(),
        );
    }
    Ok(())
}
