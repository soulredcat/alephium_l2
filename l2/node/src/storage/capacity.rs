//! Exact encoded size of the execution checkpoint at the committed head.
//!
//! A batch can only be exported and proven when the checkpoint at its start,
//! and the one its guest derives at its end, fit the continuation transport
//! bound. Every committed head can start a batch, so the producer must refuse
//! a block before committing it if the resulting checkpoint would not fit.
//! The size is tracked incrementally from the block's stored changes and
//! must equal `ReadView::execution_checkpoint()?.encode()?.len()`.
//! Capacity also reserves the remaining growth of the 256-entry hash window,
//! so filling state before height 255 cannot prevent state-preserving blocks.
use super::{ReadView, block::StoredChange, encoding::slot_key};
use alloy_primitives::{Address, B256, keccak256};
use fjall::Readable;
use std::collections::{BTreeMap, btree_map::Entry};

// Encoded checkpoint record sizes (see protocol/checkpoint/codec.rs).
const ACCOUNT_BYTES: usize = 105;
const SLOT_BYTES: usize = 64;
const CODE_HEADER_BYTES: usize = 36;
const BLOCK_HASH_BYTES: usize = 40;
const BLOCK_HASH_WINDOW: u64 = 255;

/// A block refused because its resulting checkpoint would exceed the bound.
/// Nothing was written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapacityExceeded;

pub(super) struct Capacity {
    limit: usize,
    bytes: usize,
    /// Live account references and length of each referenced code.
    codes: BTreeMap<B256, (u64, usize)>,
}

/// The tracked state after one prospective commit.
pub(super) struct Next {
    bytes: usize,
    required_bytes: usize,
    codes: BTreeMap<B256, (u64, usize)>,
}

impl Next {
    pub(super) fn required_bytes(&self) -> usize {
        self.required_bytes
    }
}

fn live_code(hash: B256) -> bool {
    hash != B256::ZERO && hash != keccak256([])
}

impl Capacity {
    pub(super) fn scan(view: &ReadView, limit: usize) -> Result<Self, String> {
        let checkpoint = view.execution_checkpoint()?;
        let bytes = checkpoint.encode()?.len();
        if with_history_reserve(bytes, view.head.height)? > limit {
            return Err(
                "Committed state already exceeds the checkpoint capacity bound including its history reserve"
                    .into(),
            );
        }
        let lengths: BTreeMap<_, _> = checkpoint
            .codes
            .iter()
            .map(|code| (code.hash, code.bytes.len()))
            .collect();
        let mut codes = BTreeMap::new();
        for account in &checkpoint.accounts {
            if !account.deleted && live_code(account.code_hash) {
                let length = *lengths
                    .get(&account.code_hash)
                    .ok_or("checkpoint misses referenced code")?;
                codes.entry(account.code_hash).or_insert((0, length)).0 += 1;
            }
        }
        Ok(Self {
            limit,
            bytes,
            codes,
        })
    }

    pub(super) fn limit(&self) -> usize {
        self.limit
    }

    pub(super) fn bytes(&self) -> usize {
        self.bytes
    }

    pub(super) fn apply(&mut self, next: Next) {
        self.bytes = next.bytes;
        for (hash, entry) in next.codes {
            if entry.0 == 0 {
                self.codes.remove(&hash);
            } else {
                self.codes.insert(hash, entry);
            }
        }
    }

    /// Size after committing `changes` (already normalized by `Store::commit`)
    /// as the block at `height`, read against the committed `view`.
    pub(super) fn after(
        &self,
        view: &ReadView,
        changes: &[StoredChange],
        height: u64,
    ) -> Result<Next, String> {
        let mut added = 0usize;
        let mut removed = 0usize;
        let mut codes = BTreeMap::<B256, (u64, usize)>::new();
        for stored in changes {
            let change = &stored.change;
            let address = change.address;
            let prior = view.account_record(address)?;
            if prior.is_none() {
                added += ACCOUNT_BYTES;
            }
            let written = change.slots.iter().filter(|(_, value)| !value.is_zero());
            match &prior {
                Some((account, false)) if account.storage_epoch == stored.epoch => {
                    for (slot, value) in &change.slots {
                        let present = view.get(slot_key(address, stored.epoch, *slot))?.is_some();
                        match (present, value.is_zero()) {
                            (false, false) => added += SLOT_BYTES,
                            (true, true) => removed += SLOT_BYTES,
                            _ => {}
                        }
                    }
                }
                Some((account, false)) => {
                    // A reset or removal abandons every live slot of the old epoch.
                    removed += SLOT_BYTES * live_slots(view, address, account.storage_epoch)?;
                    added += SLOT_BYTES * written.count();
                }
                // Absent or removed accounts have no live slots before this change.
                _ => added += SLOT_BYTES * written.count(),
            }
            let before = match prior {
                Some((account, false)) if live_code(account.code_hash) => Some(account.code_hash),
                _ => None,
            };
            let after =
                (!change.deleted && live_code(change.code_hash)).then_some(change.code_hash);
            if before != after {
                if let Some(hash) = before {
                    let entry = self.entry(&mut codes, hash, view, None)?;
                    entry.0 = entry.0.checked_sub(1).ok_or("code reference underflow")?;
                    if entry.0 == 0 {
                        removed += CODE_HEADER_BYTES + entry.1;
                    }
                }
                if let Some(hash) = after {
                    let entry = self.entry(&mut codes, hash, view, change.code.as_deref())?;
                    entry.0 += 1;
                    if entry.0 == 1 {
                        added += CODE_HEADER_BYTES + entry.1;
                    }
                }
            }
        }
        if height <= BLOCK_HASH_WINDOW {
            added += BLOCK_HASH_BYTES;
        }
        let bytes = (self.bytes + added)
            .checked_sub(removed)
            .ok_or("checkpoint capacity accounting underflow")?;
        Ok(Next {
            bytes,
            required_bytes: with_history_reserve(bytes, height)?,
            codes,
        })
    }

    /// This block's working entry for `hash`, seeded from the committed counts.
    fn entry<'a>(
        &self,
        codes: &'a mut BTreeMap<B256, (u64, usize)>,
        hash: B256,
        view: &ReadView,
        code: Option<&[u8]>,
    ) -> Result<&'a mut (u64, usize), String> {
        Ok(match codes.entry(hash) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => entry.insert(match self.codes.get(&hash) {
                Some(committed) => *committed,
                None => match code {
                    Some(code) => (0, code.len()),
                    None => (0, view.code(hash)?.len()),
                },
            }),
        })
    }
}

fn with_history_reserve(bytes: usize, height: u64) -> Result<usize, String> {
    let remaining = BLOCK_HASH_WINDOW.saturating_sub(height) as usize;
    bytes
        .checked_add(remaining * BLOCK_HASH_BYTES)
        .ok_or_else(|| "checkpoint history reservation size overflow".into())
}

fn live_slots(view: &ReadView, address: Address, epoch: u64) -> Result<usize, String> {
    let mut prefix = super::encoding::key(0x11, address.as_slice());
    prefix.extend(epoch.to_be_bytes());
    let mut count = 0usize;
    for item in view.snapshot.prefix(&view.items, prefix) {
        item.key().map_err(super::engine_error)?;
        count += 1;
    }
    Ok(count)
}
