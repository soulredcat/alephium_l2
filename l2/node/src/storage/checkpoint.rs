//! Capture a complete execution witness from one committed database snapshot.
use super::{ReadView, encoding::key, records};
use crate::protocol::checkpoint::{
    CHECKPOINT_SCHEMA, CheckpointAccount, CheckpointBlockHash, CheckpointCode, CheckpointSlot,
    ExecutionCheckpoint, MAX_CHECKPOINT_ACCOUNTS, MAX_CHECKPOINT_BYTES,
};
use alloy_primitives::{Address, B256, U256, keccak256};
use fjall::Readable;
use std::collections::BTreeSet;

impl ReadView {
    /// Includes live state, tombstone epochs and the next block's historical
    /// hash window. No field is read from a newer snapshot or mutable Store.
    /// Authenticity still requires comparison against an accepted proof root.
    pub fn execution_checkpoint(&self) -> Result<ExecutionCheckpoint, String> {
        let persisted_head =
            records::decode_head(&self.get([0x02])?.ok_or("Missing checkpoint head")?)?;
        let genesis =
            records::genesis_head(&self.get([0x01])?.ok_or("Missing checkpoint genesis")?);
        if persisted_head != self.head || self.head.genesis_id != genesis.genesis_id {
            return Err("Checkpoint view differs from its pinned database head".into());
        }
        let mut accounts = Vec::new();
        let mut referenced = BTreeSet::new();
        let mut bytes = 0usize;
        for item in self.snapshot.prefix(&self.items, [0x10]) {
            let (account_key, record) = item.into_inner().map_err(super::engine_error)?;
            if account_key.len() != 21 || accounts.len() >= MAX_CHECKPOINT_ACCOUNTS {
                return Err("Invalid checkpoint account key or count".into());
            }
            add_bytes(&mut bytes, 105)?;
            let address = Address::from_slice(&account_key[1..]);
            let (account, deleted) = records::decode_account(&record)?;
            let slots = if deleted {
                Vec::new()
            } else {
                self.checkpoint_slots(address, account.storage_epoch, &mut bytes)?
            };
            if !deleted && account.code_hash != B256::ZERO && account.code_hash != keccak256([]) {
                referenced.insert(account.code_hash);
            }
            accounts.push(CheckpointAccount {
                address,
                balance: account.balance,
                nonce: account.nonce,
                code_hash: account.code_hash,
                storage_epoch: account.storage_epoch,
                deleted,
                slots,
            });
        }
        let mut codes = Vec::with_capacity(referenced.len());
        for hash in referenced {
            let code = self.code(hash)?;
            add_bytes(&mut bytes, 36 + code.len())?;
            codes.push(CheckpointCode { hash, bytes: code });
        }
        let mut block_hashes = Vec::new();
        for height in self.head.height.saturating_sub(255)..=self.head.height {
            add_bytes(&mut bytes, 40)?;
            block_hashes.push(CheckpointBlockHash {
                height,
                hash: self.block_hash(height)?,
            });
        }
        let checkpoint = ExecutionCheckpoint {
            schema: CHECKPOINT_SCHEMA,
            chain_id: self.chain_id(),
            genesis_id: genesis.genesis_id,
            head: self.head.clone(),
            accounts,
            codes,
            block_hashes,
        };
        checkpoint.validate()?;
        Ok(checkpoint)
    }

    fn checkpoint_slots(
        &self,
        address: Address,
        epoch: u64,
        bytes: &mut usize,
    ) -> Result<Vec<CheckpointSlot>, String> {
        let mut prefix = key(0x11, address.as_slice());
        prefix.extend(epoch.to_be_bytes());
        let mut slots = Vec::new();
        for item in self.snapshot.prefix(&self.items, prefix) {
            let (slot_key, value) = item.into_inner().map_err(super::engine_error)?;
            if slot_key.len() != 61 || value.len() != 32 || U256::from_be_slice(&value).is_zero() {
                return Err("Invalid active checkpoint storage record".into());
            }
            add_bytes(bytes, 64)?;
            slots.push(CheckpointSlot {
                key: U256::from_be_slice(&slot_key[29..]),
                value: U256::from_be_slice(&value),
            });
        }
        Ok(slots)
    }
}

fn add_bytes(bytes: &mut usize, additional: usize) -> Result<(), String> {
    *bytes = bytes
        .checked_add(additional)
        .ok_or("Checkpoint collection size overflow")?;
    if *bytes > MAX_CHECKPOINT_BYTES {
        return Err("Checkpoint collection exceeds its byte bound".into());
    }
    Ok(())
}
