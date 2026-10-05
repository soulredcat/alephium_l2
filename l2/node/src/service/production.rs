//! Block production. Every committed block must stay provable: it carries
//! executed transactions only, and its resulting execution checkpoint must
//! fit the continuation bound that a proven batch starting there needs.
use super::Core;
use crate::{
    execution,
    protocol::*,
    storage::{CapacityExceeded, ReadView},
};

const CAPACITY_REASON: &str =
    "state capacity exhausted: the resulting execution checkpoint would exceed its bound";

impl Core {
    pub(super) fn produce(&mut self) -> Result<(), String> {
        if self.pending.is_empty() {
            return Ok(());
        }
        let view = self.handle.view()?;
        let selected = self.select(&view)?;
        let context = self.context()?;
        if self.build(&view, &selected, context)?.is_err() {
            // Near the bound, retry the oldest intent alone. One that cannot
            // fit even alone is resolved outside the chain, so later intents
            // that shrink or keep the state still progress.
            let alone = &selected[..1];
            if selected.len() == 1 || self.build(&view, alone, context)?.is_err() {
                self.store.discard(selected[0].hash, CAPACITY_REASON)?;
            }
        }
        // Store order is admission order; resolved intents have left it.
        self.pending = self.store.pending()?;
        let new_view = self.store.view()?;
        self.publish(new_view)
    }

    /// The admission-ordered prefix that fits the block gas and byte budgets.
    fn select(&self, view: &ReadView) -> Result<Vec<Pending>, String> {
        let mut selected = Vec::new();
        let mut reserved_gas = 0u64;
        let mut bytes = 4096usize;
        for pending in &self.pending {
            let info = execution::inspect_for_chain(&pending.raw, view.chain_id())?;
            if reserved_gas.saturating_add(info.gas_limit) > BLOCK_GAS
                || bytes.saturating_add(pending.raw.len() + 40) > BLOCK_BYTES
            {
                break;
            }
            reserved_gas += info.gas_limit;
            bytes += pending.raw.len() + 40;
            selected.push(pending.clone());
        }
        if selected.is_empty() {
            return Err("Persisted pending transaction cannot fit block".into());
        }
        Ok(selected)
    }

    /// Execute `selected` and commit its executed transactions as one block.
    /// Over the checkpoint bound nothing is written and no intent is resolved.
    fn build(
        &mut self,
        view: &ReadView,
        selected: &[Pending],
        context: BlockContext,
    ) -> Result<Result<(), CapacityExceeded>, String> {
        let raws: Vec<_> = selected.iter().map(|pending| pending.raw.clone()).collect();
        let result = execution::execute_block(view.clone(), &raws, context)?;
        // A rejected intent changes no state and no receipt, but the transition
        // witness cannot represent one, so a block containing it could never be
        // proven. Commit only executed transactions and resolve rejections
        // outside the chain.
        if !result.receipts.is_empty() {
            let commit = BlockCommit {
                parent: self.head.clone(),
                context,
                transactions: result.receipts.iter().map(|r| r.hash).collect(),
                changes: result.changes,
                receipts: result.receipts,
                rejected: Vec::new(),
            };
            if let Err(exceeded) = self.store.commit_bounded(commit)? {
                return Ok(Err(exceeded));
            }
        }
        for (hash, reason) in &result.rejected {
            self.store.discard(*hash, reason)?;
        }
        Ok(Ok(()))
    }
}
