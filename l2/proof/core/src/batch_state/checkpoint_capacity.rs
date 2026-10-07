//! Match the producer's canonical upper checkpoint bound at every block.
//! Operator-selected lower storage throttles are not authenticated profile fields.
use super::FullState;
use crate::protocol::Capacity;
use alloy_primitives::{B256, keccak256};
use std::collections::BTreeSet;

// Exact protocol/checkpoint/codec.rs widths, including complete tombstones.
const HEADER_BYTES: usize = b"alephium-l2/execution-checkpoint/v1".len() + 136;
const ACCOUNT_BYTES: usize = 105;
const SLOT_BYTES: usize = 64;
const CODE_HEADER_BYTES: usize = 36;
const BLOCK_HASH_BYTES: usize = 40;
const BLOCK_HASH_WINDOW: u64 = 255;

impl FullState {
    /// Called after each original retained block, before accepting its result.
    /// A later state shrink must not hide an uncommittable intermediate state.
    pub(crate) fn enforce_checkpoint_capacity(&self, capacity: Capacity) -> Result<(), String> {
        let head = self
            .head
            .as_ref()
            .ok_or("checkpoint capacity requires an executed head")?;
        ensure_checkpoint_bytes(
            self.checkpoint_encoded_bytes(capacity)?,
            head.height,
            capacity,
        )
    }

    /// Meter the same records as checkpoint(), without cloning state/code or
    /// rehashing immutable code already checked on import and insertion.
    fn checkpoint_encoded_bytes(&self, capacity: Capacity) -> Result<usize, String> {
        let mut size = HEADER_BYTES + if capacity.is_default() { 0 } else { 24 };
        add_records(&mut size, self.accounts.len(), ACCOUNT_BYTES)?;
        let empty_code = keccak256([]);
        let mut referenced = BTreeSet::new();
        for (address, (account, deleted)) in &self.accounts {
            let slots = self.slots.get(address).map_or(0, |slots| slots.len());
            add_records(&mut size, slots, SLOT_BYTES)?;
            if !deleted && account.code_hash != B256::ZERO && account.code_hash != empty_code {
                referenced.insert(account.code_hash);
            }
        }
        for hash in referenced {
            let code = self
                .codes
                .get(&hash)
                .ok_or("checkpoint misses referenced code")?;
            add_records(&mut size, 1, CODE_HEADER_BYTES)?;
            add_records(&mut size, code.len(), 1)?;
        }
        add_records(&mut size, self.blocks.len(), BLOCK_HASH_BYTES)?;
        Ok(size)
    }
}

pub(super) fn ensure_checkpoint_bytes(
    bytes: usize,
    height: u64,
    capacity: Capacity,
) -> Result<(), String> {
    capacity.validate()?;
    ensure_limit(bytes, height, capacity.producer_checkpoint_bytes()?)
}

fn ensure_limit(bytes: usize, height: u64, limit: usize) -> Result<(), String> {
    let remaining = usize::try_from(BLOCK_HASH_WINDOW.saturating_sub(height))
        .map_err(|_| "checkpoint history reserve conversion overflow")?;
    let mut required = bytes;
    add_records(&mut required, remaining, BLOCK_HASH_BYTES)?;
    if required > limit {
        return Err("checkpoint exceeds the producer bound including its history reserve".into());
    }
    Ok(())
}

fn add_records(size: &mut usize, count: usize, width: usize) -> Result<(), String> {
    *size = size
        .checked_add(
            count
                .checked_mul(width)
                .ok_or("checkpoint capacity size overflow")?,
        )
        .ok_or("checkpoint capacity size overflow")?;
    Ok(())
}

#[cfg(test)]
#[path = "checkpoint_capacity_tests.rs"]
mod tests;
