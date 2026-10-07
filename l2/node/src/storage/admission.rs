//! Atomic admission for requests already available to the sole core owner.
//! Grouping changes the number of durable barriers, never their strength.
use super::super::{
    Store,
    encoding::{Encoder, key},
    records,
};
use crate::protocol::{MAX_TRANSACTION_BYTES, Pending, TransactionStatus};
use alloy_primitives::{B256, keccak256};
use std::collections::{BTreeMap, BTreeSet};

struct NewIntent<'a> {
    pending: &'a Pending,
    ordinal: u64,
    status: Vec<u8>,
    record: Vec<u8>,
}

impl Store {
    pub fn admit(&mut self, pending: Pending) -> Result<TransactionStatus, String> {
        self.admit_batch(std::slice::from_ref(&pending))?
            .into_iter()
            .next()
            .ok_or_else(|| "admission batch returned no status".into())
    }

    /// Admit an already validated group with one atomic SyncAll commit. Do not
    /// wait for a group to fill: callers supply only requests already queued.
    /// Every result is aligned with its input, including canonical duplicates.
    /// Validation errors write nothing; commit errors make the store terminal.
    pub fn admit_batch(&mut self, pending: &[Pending]) -> Result<Vec<TransactionStatus>, String> {
        self.check()?;
        if pending.is_empty() {
            return Ok(Vec::new());
        }
        let view = self.view()?;
        let queue = self.pending_records()?;
        let mut reservations: BTreeSet<_> = queue.iter().map(|(_, item)| item.sender).collect();
        let mut ordinal = view.pending_counter()?;
        let mut canonical = BTreeMap::<B256, (&Pending, usize)>::new();
        let mut statuses: Vec<TransactionStatus> = Vec::new();
        let mut new = Vec::new();
        for item in pending {
            if item.raw.is_empty()
                || item.raw.len() > MAX_TRANSACTION_BYTES
                || keccak256(&item.raw) != item.hash
            {
                return Err("invalid pending transaction identity or size".into());
            }
            if let Some((previous, index)) = canonical.get(&item.hash) {
                if previous.raw != item.raw || previous.sender != item.sender {
                    return Err("conflicting canonical transaction identity".into());
                }
                statuses.push(statuses[*index].clone());
                continue;
            }
            if let Some(existing) = view.status(item.hash)? {
                if view.raw_transaction(item.hash)?.as_deref() != Some(item.raw.as_slice()) {
                    return Err("conflicting canonical transaction identity".into());
                }
                canonical.insert(item.hash, (item, statuses.len()));
                statuses.push(existing);
                continue;
            }
            if view.raw_transaction(item.hash)?.is_some() {
                return Err("transaction envelope exists without canonical status".into());
            }
            if reservations.len() >= self.capacity().max_pending
                || !reservations.insert(item.sender)
            {
                return Err("pending capacity or sender reservation exceeded".into());
            }
            ordinal = ordinal.checked_add(1).ok_or("pending ordinal exhausted")?;
            let mut record = Encoder::default();
            record.hash(item.hash);
            record.address(item.sender);
            let status = TransactionStatus {
                hash: item.hash,
                status: "durably_accepted".into(),
                block_height: None,
                error: None,
            };
            new.push(NewIntent {
                pending: item,
                ordinal,
                status: records::encode_status(&status)?,
                record: record.0,
            });
            canonical.insert(item.hash, (item, statuses.len()));
            statuses.push(status);
        }
        if new.is_empty() {
            return Ok(statuses);
        }
        // No durable or published state has changed during validation above.
        let mut batch = self.batch()?;
        for intent in new {
            batch.insert(
                &self.items,
                key(0x20, intent.pending.hash.as_slice()),
                intent.pending.raw.clone(),
            );
            batch.insert(
                &self.items,
                key(0x21, intent.pending.hash.as_slice()),
                intent.status,
            );
            batch.insert(
                &self.items,
                key(0x23, &intent.ordinal.to_be_bytes()),
                intent.record,
            );
        }
        batch.insert(&self.items, vec![0x03], ordinal.to_be_bytes().to_vec());
        self.finish(batch)?;
        Ok(statuses)
    }
}

#[cfg(test)]
#[path = "admission_tests.rs"]
mod tests;
