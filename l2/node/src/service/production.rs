//! Block production persists executed transactions within canonical record and
//! checkpoint byte bounds, reserving the remaining historical hash window.
//! Finite guest execution/proving resources require separate qualification;
//! passing these storage bounds alone does not establish proofability.
use super::Core;
use crate::{
    execution,
    protocol::*,
    storage::{CapacityExceeded, ReadView},
};
use std::time::Instant;

const CAPACITY_REASON: &str =
    "state capacity exhausted: the resulting execution checkpoint would exceed its bound";

/// The same conservative reservation applies to admission and block selection.
#[derive(Clone, Copy)]
pub(super) struct BlockBudget {
    gas: u64,
    bytes: usize,
    capacity: Capacity,
    overflowed: bool,
}

impl BlockBudget {
    pub(super) fn new(capacity: Capacity) -> Self {
        Self {
            gas: 0,
            bytes: 4096,
            capacity,
            overflowed: false,
        }
    }

    pub(super) fn record(&mut self, gas: u64, raw_bytes: usize) {
        match self.gas.checked_add(gas) {
            Some(next) => self.gas = next,
            None => self.overflowed = true,
        }
        match self
            .bytes
            .checked_add(raw_bytes)
            .and_then(|next| next.checked_add(40))
        {
            Some(next) => self.bytes = next,
            None => self.overflowed = true,
        }
    }

    pub(super) fn can_reserve(self, gas: u64, raw_bytes: usize) -> bool {
        if self.overflowed {
            return false;
        }
        let Some(gas) = self.gas.checked_add(gas) else {
            return false;
        };
        let Some(bytes) = self
            .bytes
            .checked_add(raw_bytes)
            .and_then(|next| next.checked_add(40))
        else {
            return false;
        };
        gas <= self.capacity.block_gas && bytes <= self.capacity.block_bytes
    }

    fn reserve(&mut self, gas: u64, raw_bytes: usize) -> bool {
        if !self.can_reserve(gas, raw_bytes) {
            return false;
        }
        self.record(gas, raw_bytes);
        true
    }
}

impl Core {
    pub(super) fn produce(&mut self) -> Result<(), String> {
        if self.pending.is_empty() {
            return Ok(());
        }
        let view = self.handle.view()?;
        let selection_started = Instant::now();
        let selection = self.select(&view);
        self.handle
            .metrics
            .selection
            .record(selection_started.elapsed());
        let selected = selection?;
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
        self.retain_pending_preparations()?;
        let new_view = self.store.view()?;
        self.publish(new_view)
    }

    /// The admission-ordered prefix that fits the block gas and byte budgets.
    fn select(&self, view: &ReadView) -> Result<Vec<Pending>, String> {
        let mut selected = Vec::new();
        let mut budget = BlockBudget::new(view.capacity());
        for pending in &self.pending {
            let info = self.prepared_pending(pending, view.chain_id())?.info();
            if !budget.reserve(info.gas_limit, pending.raw.len()) {
                break;
            }
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
        let prepared: Vec<_> = selected
            .iter()
            .map(|pending| self.prepared_pending(pending, view.chain_id()).cloned())
            .collect::<Result<_, _>>()?;
        let execution_started = Instant::now();
        let executed = execution::execute_prepared_block(view.clone(), &prepared, context);
        self.handle
            .metrics
            .execution
            .record(execution_started.elapsed());
        let result = executed?;
        self.handle.metrics.executed(result.receipts.len());
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
            let commit_started = Instant::now();
            let committed = self.store.commit_bounded(commit);
            self.handle
                .metrics
                .durable_block_commit
                .record(commit_started.elapsed());
            if let Err(exceeded) = committed? {
                return Ok(Err(exceeded));
            }
            if let Some(phases) = self.store.last_commit_phases() {
                self.handle.metrics.committed(phases);
            }
        }
        for (hash, reason) in &result.rejected {
            self.store.discard(*hash, reason)?;
        }
        Ok(Ok(()))
    }
}
