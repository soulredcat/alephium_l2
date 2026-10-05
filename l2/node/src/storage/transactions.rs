use super::{
    Store,
    block::{self, StoredChange},
    encoding::{Decoder, key, slot_key},
    records,
};
use crate::protocol::{Account, BlockCommit, Pending, TransactionStatus};
use alloy_primitives::B256;
use fjall::Readable;
use std::collections::{BTreeMap, BTreeSet};

#[path = "admission.rs"]
mod admission;

impl Store {
    pub fn pending(&self) -> Result<Vec<Pending>, String> {
        Ok(self
            .pending_records()?
            .into_iter()
            .map(|(_, pending)| pending)
            .collect())
    }

    pub(super) fn pending_records(&self) -> Result<Vec<(u64, Pending)>, String> {
        let view = self.view()?;
        let mut pending = Vec::new();
        let mut hashes = BTreeSet::new();
        let mut senders = BTreeSet::new();
        for item in view.snapshot.prefix(&view.items, [0x23]) {
            let (key, value) = item.into_inner().map_err(super::engine_error)?;
            if key.len() != 9 || pending.len() >= self.capacity().max_pending {
                return Err("invalid durable pending queue".into());
            }
            let ordinal = u64::from_be_bytes(key[1..].try_into().unwrap());
            let mut input = Decoder::new(&value)?;
            let hash = input.hash()?;
            let sender = input.address()?;
            input.finish()?;
            if ordinal == 0 || !hashes.insert(hash) || !senders.insert(sender) {
                return Err("duplicate durable pending identity".into());
            }
            let raw = view
                .raw_transaction(hash)?
                .ok_or("missing pending envelope")?;
            let status = view.status(hash)?.ok_or("missing pending status")?;
            if status.status != "durably_accepted" {
                return Err("pending status is not accepted".into());
            }
            pending.push((ordinal, Pending { hash, sender, raw }));
        }
        Ok(pending)
    }

    pub fn commit(&mut self, commit: BlockCommit) -> Result<super::ReadView, String> {
        self.commit_checked(commit, false)?
            .map_err(|_| "unenforced checkpoint capacity refused a commit".into())
    }

    /// Track the exact encoded checkpoint size from now on and refuse, in
    /// `commit_bounded`, any block whose checkpoint plus remaining hash-window
    /// growth exceeds `limit`.
    pub fn enable_capacity(&mut self, limit: usize) -> Result<(), String> {
        self.capacity = Some(super::capacity::Capacity::scan(&self.view()?, limit)?);
        Ok(())
    }

    /// Encoded checkpoint size of the committed head and its enforced bound.
    pub fn checkpoint_capacity(&self) -> Option<(usize, usize)> {
        self.capacity
            .as_ref()
            .map(|capacity| (capacity.bytes(), capacity.limit()))
    }

    /// Commit unless the resulting checkpoint, including reserved hash-window
    /// growth, would exceed the enabled bound; otherwise nothing is written.
    pub fn commit_bounded(
        &mut self,
        commit: BlockCommit,
    ) -> Result<Result<super::ReadView, super::CapacityExceeded>, String> {
        if self.capacity.is_none() {
            return Err("checkpoint capacity tracking is not enabled".into());
        }
        self.commit_checked(commit, true)
    }

    fn commit_checked(
        &mut self,
        mut commit: BlockCommit,
        enforce: bool,
    ) -> Result<Result<super::ReadView, super::CapacityExceeded>, String> {
        self.check()?;
        if self.latest_head()? != commit.parent {
            return Err("commit parent is stale".into());
        }
        block::validate_with_capacity(&commit, self.capacity())?;
        let view = self.view()?;
        let pending: BTreeMap<_, _> = self
            .pending_records()?
            .into_iter()
            .map(|(order, pending)| (pending.hash, (order, pending)))
            .collect();
        for hash in commit
            .transactions
            .iter()
            .chain(commit.rejected.iter().map(|(hash, _)| hash))
        {
            if !pending.contains_key(hash) {
                return Err("block resolves an unknown pending intent".into());
            }
        }
        for receipt in &commit.receipts {
            if pending[&receipt.hash].1.sender != receipt.from {
                return Err("receipt sender differs from durable intent".into());
            }
        }
        block::logical_bytes_with_capacity(
            &commit,
            commit
                .transactions
                .iter()
                .map(|hash| pending[hash].1.raw.as_slice()),
            self.capacity(),
        )?;
        commit.changes.sort_by_key(|change| change.address);
        let new_codes: BTreeMap<_, _> = commit
            .changes
            .iter()
            .filter_map(|change| change.code.as_ref().map(|code| (change.code_hash, code)))
            .collect();
        for (hash, code) in &new_codes {
            records::verify_code(*hash, code)?;
        }
        let mut changes = Vec::with_capacity(commit.changes.len());
        for mut change in commit.changes.iter().cloned() {
            change.slots.sort_by_key(|(slot, _)| *slot);
            let mut epoch = view
                .account_record(change.address)?
                .map_or(0, |(account, _)| account.storage_epoch);
            if change.storage_reset || change.deleted {
                epoch = epoch.checked_add(1).ok_or("storage epoch exhausted")?;
            }
            if let Some(code) = &change.code {
                records::verify_code(change.code_hash, code)?;
            } else if !change.deleted && !new_codes.contains_key(&change.code_hash) {
                view.code(change.code_hash)?;
            }
            if change.deleted {
                change.balance = Default::default();
                change.nonce = 0;
                change.code_hash = B256::ZERO;
            }
            changes.push(StoredChange { change, epoch });
        }
        let (head, record) = block::encode_with_capacity(&commit, &changes, self.capacity())?;
        let capacity = match &self.capacity {
            Some(capacity) => {
                let next = capacity.after(&view, &changes, head.height)?;
                if enforce && next.required_bytes() > capacity.limit() {
                    return Ok(Err(super::CapacityExceeded));
                }
                Some(next)
            }
            None => None,
        };
        let mut batch = self.batch()?;
        for stored in &changes {
            let change = &stored.change;
            let account = Account {
                balance: change.balance,
                nonce: change.nonce,
                code_hash: change.code_hash,
                storage_epoch: stored.epoch,
            };
            batch.insert(
                &self.items,
                key(0x10, change.address.as_slice()),
                records::encode_account(&account, change.deleted),
            );
            if let Some(code) = &change.code {
                let code_key = key(0x12, change.code_hash.as_slice());
                if let Some(existing) = view.get(&code_key)? {
                    if existing != *code {
                        return Err("conflicting content-addressed code".into());
                    }
                } else if !code.is_empty() {
                    batch.insert(&self.items, code_key, code.clone());
                }
            }
            for (slot, value) in &change.slots {
                let slot_key = slot_key(change.address, stored.epoch, *slot);
                if value.is_zero() {
                    batch.remove(&self.items, slot_key);
                } else {
                    batch.insert(&self.items, slot_key, value.to_be_bytes::<32>().to_vec());
                }
            }
        }
        for mut receipt in commit.receipts {
            receipt.block_hash = head.commit_id;
            let status = TransactionStatus {
                hash: receipt.hash,
                status: if receipt.success {
                    "committed"
                } else {
                    "reverted"
                }
                .into(),
                block_height: Some(head.height),
                error: None,
            };
            batch.insert(
                &self.items,
                key(0x22, receipt.hash.as_slice()),
                records::encode_receipt(&receipt, true)?,
            );
            batch.insert(
                &self.items,
                key(0x21, receipt.hash.as_slice()),
                records::encode_status(&status)?,
            );
            batch.remove(
                &self.items,
                key(0x23, &pending[&receipt.hash].0.to_be_bytes()),
            );
        }
        for (hash, reason) in commit.rejected {
            let status = TransactionStatus {
                hash,
                status: "rejected".into(),
                block_height: Some(head.height),
                error: Some(reason),
            };
            batch.insert(
                &self.items,
                key(0x21, hash.as_slice()),
                records::encode_status(&status)?,
            );
            batch.remove(&self.items, key(0x23, &pending[&hash].0.to_be_bytes()));
        }
        batch.insert(&self.items, key(0x30, &head.height.to_be_bytes()), record);
        batch.insert(
            &self.items,
            key(0x31, head.commit_id.as_slice()),
            head.height.to_be_bytes().to_vec(),
        );
        batch.insert(&self.items, vec![0x02], records::encode_head(&head));
        self.finish(batch)?;
        if let (Some(capacity), Some(next)) = (self.capacity.as_mut(), capacity) {
            capacity.apply(next);
        }
        Ok(Ok(self.view()?))
    }
}
