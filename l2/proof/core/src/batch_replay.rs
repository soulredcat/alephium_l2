//! Shared retained-block verification for full-history and checkpoint witnesses.
use crate::{
    TransitionBlock, TransitionContext, batch_execution, batch_journal,
    batch_state::FullState,
    block,
    encoding::{Encoder, MAX_RECORD},
    execution::private_envelope,
    protocol::*,
    records,
};
use alloy_primitives::B256;
use std::collections::BTreeSet;

pub(crate) fn execute_retained(
    state: &mut FullState,
    chain_id: u64,
    parent: &Head,
    input: &TransitionBlock,
    capacity: Capacity,
) -> Result<(Head, Vec<Receipt>), String> {
    capacity.validate()?;
    let context = BlockContext {
        number: input.context.number,
        timestamp: input.context.timestamp,
        gas_limit: input.context.gas_limit,
    };
    if input.parent != *parent
        || context.number != parent.height.checked_add(1).ok_or("height overflow")?
        || context.timestamp < parent.timestamp
        || context.gas_limit != capacity.block_gas
        || input.transactions.is_empty()
        || input.transactions.len() > capacity.max_pending
    {
        return Err("batch ancestry, context or transaction count is invalid".into());
    }
    let raws = input
        .transactions
        .iter()
        .map(|tx| private_envelope(&tx.raw_envelope_hex))
        .collect::<Result<Vec<_>, _>>()?;
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
    block::logical_bytes_with_capacity(&commit, raws.iter().map(Vec::as_slice), capacity)?;
    let stored = state.apply(&commit.changes)?;
    let (head, _) = block::encode_with_capacity(&commit, &stored, capacity)?;
    if head != input.head {
        return Err("executed batch head differs from retained runtime head".into());
    }
    let mut receipts = commit.receipts;
    for (expected, receipt) in input.transactions.iter().zip(&mut receipts) {
        receipt.block_hash = head.commit_id;
        if receipt.hash != expected.transaction_hash || *receipt != expected.expected_receipt {
            return Err("executed receipt differs from retained runtime receipt".into());
        }
    }
    state.commit_head(&head)?;
    Ok((head, receipts))
}

pub(crate) struct Commitments {
    transactions: Encoder,
    contexts: Encoder,
    receipts: Encoder,
    seen: BTreeSet<B256>,
}

impl Commitments {
    pub(crate) fn new() -> Result<Self, String> {
        let mut transactions = Encoder::default();
        transactions.bytes(b"alephium-l2/batch-transactions/v2")?;
        let mut contexts = Encoder::default();
        contexts.bytes(b"alephium-l2/batch-contexts/v2")?;
        let mut receipts = Encoder::default();
        receipts.bytes(b"alephium-l2/batch-receipts/v2")?;
        Ok(Self {
            transactions,
            contexts,
            receipts,
            seen: BTreeSet::new(),
        })
    }

    pub(crate) fn include(
        &mut self,
        context: &TransitionContext,
        receipts: &[Receipt],
    ) -> Result<(), String> {
        self.contexts.u64(context.number);
        self.contexts.u64(context.timestamp);
        self.contexts.u64(context.gas_limit);
        self.transactions.u64(context.number);
        self.transactions.u32(receipts.len() as u32);
        self.receipts.u64(context.number);
        self.receipts.u32(receipts.len() as u32);
        for receipt in receipts {
            if !self.seen.insert(receipt.hash) {
                return Err("duplicate transaction in selected batch".into());
            }
            self.transactions.hash(receipt.hash);
            self.receipts
                .bytes(&records::encode_receipt(receipt, true)?)?;
            if self.receipts.0.len() > MAX_RECORD || self.transactions.0.len() > MAX_RECORD {
                return Err("batch result commitment exceeds byte bound".into());
            }
        }
        Ok(())
    }

    pub(crate) fn finish(self) -> Result<(B256, B256, B256, u64), String> {
        Ok((
            batch_journal::hash(&self.transactions.finish()?),
            batch_journal::hash(&self.contexts.finish()?),
            batch_journal::hash(&self.receipts.finish()?),
            self.seen.len() as u64,
        ))
    }
}
